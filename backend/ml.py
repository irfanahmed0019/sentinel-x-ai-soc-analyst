from typing import Any

import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from config import settings
from eda import numeric_columns


SUPPORTED_CLASSES = ["BENIGN", "DDoS", "PortScan", "Bot", "BruteForce", "WebAttack", "Infiltration"]

LABEL_MAP = {
    "BENIGN": "BENIGN",
    "Normal Traffic": "BENIGN",
    "DoS": "DDoS",
    "DDoS": "DDoS",
    "DoS Hulk": "DDoS",
    "DoS GoldenEye": "DDoS",
    "DoS slowloris": "DDoS",
    "DoS Slowhttptest": "DDoS",
    "PortScan": "PortScan",
    "Port Scanning": "PortScan",
    "Bot": "Bot",
    "Bots": "Bot",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "Brute Force": "BruteForce",
    "Web Attack - Brute Force": "WebAttack",
    "Web Attack - XSS": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
    "Web Attacks": "WebAttack",
    "Infiltration": "Infiltration",
}

CLASS_RISK_WEIGHT = {
    "BENIGN": 0.0,
    "PortScan": 0.55,
    "BruteForce": 0.75,
    "Bot": 0.8,
    "WebAttack": 0.85,
    "DDoS": 0.9,
    "Infiltration": 1.0,
}

MITRE_MAP = {
    "BENIGN": {"id": None, "technique": "Normal Traffic"},
    "PortScan": {"id": "T1046", "technique": "Network Service Discovery"},
    "BruteForce": {"id": "T1110", "technique": "Brute Force"},
    "DDoS": {"id": "T1498", "technique": "Network Denial of Service"},
    "Bot": {"id": "T1071", "technique": "Application Layer Protocol"},
    "WebAttack": {"id": "T1190", "technique": "Exploit Public-Facing Application"},
    "Infiltration": {"id": "T1021", "technique": "Remote Services"},
}

SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]


def _normalize(values: np.ndarray) -> np.ndarray:
    low = float(np.nanmin(values))
    high = float(np.nanmax(values))
    if high - low < 1e-9:
        return np.zeros_like(values, dtype=float)
    return ((values - low) / (high - low)) * 100


def _score_in_chunks(model: IsolationForest, df_features: pl.DataFrame, chunk_size: int = 100_000) -> np.ndarray:
    scores = []
    for start in range(0, len(df_features), chunk_size):
        end = min(start + chunk_size, len(df_features))
        chunk_matrix = df_features[start:end].to_numpy()
        scores.append(model.decision_function(chunk_matrix))
    return np.concatenate(scores)


def _classify_in_chunks(model: RandomForestClassifier, df_features: pl.DataFrame, chunk_size: int = 100_000) -> tuple[np.ndarray, np.ndarray]:
    predictions = []
    confidences = []
    for start in range(0, len(df_features), chunk_size):
        end = min(start + chunk_size, len(df_features))
        chunk_matrix = df_features[start:end].to_numpy()
        probabilities = model.predict_proba(chunk_matrix)
        class_indices = np.argmax(probabilities, axis=1)
        predictions.append(model.classes_[class_indices])
        confidences.append(np.max(probabilities, axis=1))
    return np.concatenate(predictions), np.concatenate(confidences)


def _severity(score: float) -> str:
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def _canonical_label(label: Any) -> str:
    return LABEL_MAP.get(str(label).strip(), "WebAttack" if "Web Attack" in str(label) else "BENIGN")


def _mitre(attack_type: str) -> dict[str, str | None]:
    return MITRE_MAP.get(attack_type, {"id": None, "technique": "Unmapped"})


def run_ml(df: pl.DataFrame, detected_columns: dict[str, str | None], job_dir) -> tuple[pl.DataFrame, dict[str, Any]]:
    label_col = detected_columns.get("label")
    excluded = [
        label_col,
        detected_columns.get("src_ip"),
        detected_columns.get("dst_ip"),
        detected_columns.get("src_port"),
        detected_columns.get("dst_port"),
        detected_columns.get("timestamp"),
    ]
    features = numeric_columns(df, excluded=excluded)
    if not features:
        raise ValueError("No numeric columns found. SENTINEL-X needs numeric network features to score threats.")

    df_features = df.select(features)
    row_count = len(df)
    sample_size = min(settings.subsample_rows, row_count)
    rng = np.random.default_rng(42)
    sample_indices = rng.choice(row_count, size=sample_size, replace=False) if row_count > sample_size else np.arange(row_count)
    
    iso = IsolationForest(
        n_estimators=100,
        contamination=0.02,
        max_samples=0.8,
        random_state=42,
        n_jobs=-1,
    )
    sample_matrix = df_features[sample_indices].to_numpy()
    iso.fit(sample_matrix)
    raw_scores = _score_in_chunks(iso, df_features)
    anomaly_scores = _normalize(-raw_scores)
    anomaly_labels = np.where(anomaly_scores >= 40, "anomaly", "normal")

    supervised_available = False
    classification: dict[str, Any] | None = None
    confusion: dict[str, Any] | None = None
    model_accuracy: float | None = None
    model_precision: float | None = None
    model_recall: float | None = None
    model_f1: float | None = None
    rf_predictions = np.array(["BENIGN"] * row_count, dtype=object)
    rf_confidences = np.zeros(row_count, dtype=float)

    if label_col:
        labels_all = np.array([_canonical_label(value) for value in df.select(label_col).to_series().to_list()], dtype=object)
        sample_labels = labels_all[sample_indices]
        unique_labels, label_counts = np.unique(sample_labels, return_counts=True)
        if len(unique_labels) >= 2:
            supervised_available = True
            stratify = sample_labels if int(label_counts.min()) >= 2 else None
            x_train, x_test, y_train, y_test = train_test_split(
                sample_matrix,
                sample_labels,
                test_size=0.3,
                random_state=42,
                stratify=stratify,
            )
            clf = RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                n_jobs=-1,
                random_state=42,
                class_weight="balanced",
            )
            clf.fit(x_train, y_train)
            y_pred = clf.predict(x_test)
            labels_for_metrics = [label for label in SUPPORTED_CLASSES if label in set(y_test) | set(y_pred)]
            classification = classification_report(
                y_test,
                y_pred,
                labels=labels_for_metrics,
                output_dict=True,
                zero_division=0,
            )
            model_accuracy = float(classification.get("accuracy", 0))
            model_precision = float(classification.get("weighted avg", {}).get("precision", 0))
            model_recall = float(classification.get("weighted avg", {}).get("recall", 0))
            model_f1 = float(classification.get("weighted avg", {}).get("f1-score", 0))
            confusion = {
                "labels": labels_for_metrics,
                "matrix": confusion_matrix(y_test, y_pred, labels=labels_for_metrics).tolist(),
            }
            rf_predictions, rf_confidences = _classify_in_chunks(clf, df_features)

    if supervised_available:
        class_weights = np.array([CLASS_RISK_WEIGHT.get(str(label), 0.5) for label in rf_predictions])
        threat_component = rf_confidences * class_weights * 100
        risk_scores = np.where(
            rf_predictions == "BENIGN",
            anomaly_scores * 0.35,
            (0.35 * anomaly_scores) + (0.65 * threat_component),
        )
    else:
        risk_scores = anomaly_scores
    risk_scores = np.clip(risk_scores, 0, 100)
    severities = [_severity(float(score)) for score in risk_scores]
    mitre_ids = [_mitre(str(label))["id"] for label in rf_predictions]
    mitre_techniques = [_mitre(str(label))["technique"] for label in rf_predictions]

    output = df.with_columns(
        pl.Series("risk_score", risk_scores),
        pl.Series("severity", severities),
        pl.Series("anomaly_score", anomaly_scores),
        pl.Series("anomaly_label", anomaly_labels),
        pl.Series("threat_type", rf_predictions),
        pl.Series("confidence_score", rf_confidences),
        pl.Series("mitre_id", mitre_ids),
        pl.Series("mitre_technique", mitre_techniques),
    )
    output.write_parquet(job_dir / "scored.parquet")
    output.write_csv(job_dir / "scored.csv")

    src_col = detected_columns.get("src_ip")
    if src_col and src_col in output.columns:
        grouped_stats = output.group_by(src_col).agg(
            pl.len().alias("occurrences"),
            pl.col("risk_score").mean().alias("avg_risk_score")
        )
        top_df = output.sort("risk_score", descending=True).unique(subset=[src_col], keep="first")
        top_df = top_df.join(grouped_stats, on=src_col, how="left")
        top_df = top_df.sort("risk_score", descending=True).head(settings.top_threats_count)
    else:
        top_df = output.sort("risk_score", descending=True).head(settings.top_threats_count)
        
    top_threats = [_shape_threat(row, rank, detected_columns) for rank, row in enumerate(top_df.to_dicts(), start=1)]

    severity_counts = {severity: severities.count(severity) for severity in SEVERITY_ORDER}
    attack_counts = {
        str(row["threat_type"]): int(row["len"])
        for row in output.group_by("threat_type").len().sort("len", descending=True).to_dicts()
    }
    most_common_attack = next((label for label, _ in attack_counts.items() if label != "BENIGN"), None)

    ml_output = {
        "supervised_available": supervised_available,
        "features_used": features,
        "model_accuracy": model_accuracy,
        "model_precision": model_precision,
        "model_recall": model_recall,
        "model_f1": model_f1,
        "classification_report": classification,
        "confusion_matrix": confusion,
        "validation_warning": _validation_warning(row_count, sample_size, model_accuracy),
        "top_threats": top_threats,
        "severity_counts": severity_counts,
        "attack_counts": attack_counts,
        "most_common_attack": most_common_attack,
    }
    return output, ml_output


def _validation_warning(row_count: int, sample_size: int, accuracy: float | None) -> str | None:
    if accuracy is None:
        return "Supervised validation unavailable because labels were missing or single-class."
    if row_count < 100:
        return "Validation sample is tiny; accuracy can be misleading on toy CSVs."
    if accuracy >= 0.999:
        return "Very high accuracy may be genuine on CICIDS2017, but review feature leakage and class balance."
    return None


def _shape_threat(row: dict[str, Any], rank: int, detected_columns: dict[str, str | None]) -> dict[str, Any]:
    def value(key: str, fallback: Any = None) -> Any:
        column = detected_columns.get(key)
        return row.get(column, fallback) if column else fallback

    threat_type = str(row.get("threat_type", "BENIGN"))
    mitre = _mitre(threat_type)
    severity = str(row.get("severity", "Low"))
    threat_category = {
        "Critical": "critical",
        "High": "likely_threat",
        "Medium": "suspicious",
        "Low": "safe",
    }.get(severity, "safe")

    return {
        "rank": rank,
        "src_ip": str(value("src_ip", "unknown")),
        "dst_ip": str(value("dst_ip", "unknown")),
        "dst_port": value("dst_port", "?"),
        "protocol": str(value("protocol", "?")),
        "risk_score": round(float(row.get("risk_score", 0)), 2),
        "danger_score": round(float(row.get("risk_score", 0)), 2),
        "severity": severity,
        "threat_category": threat_category,
        "anomaly_score": round(float(row.get("anomaly_score", 0)), 2),
        "anomaly_label": str(row.get("anomaly_label", "normal")),
        "threat_type": threat_type,
        "rf_label": threat_type,
        "confidence_score": round(float(row.get("confidence_score", 0)), 3),
        "rf_confidence": round(float(row.get("confidence_score", 0)), 3),
        "mitre_id": mitre["id"],
        "mitre_technique": mitre["technique"],
        "original_label": str(value("label", "unknown")),
        "occurrences": int(row.get("occurrences", 1)),
        "avg_risk_score": round(float(row.get("avg_risk_score", row.get("risk_score", 0))), 2),
    }
