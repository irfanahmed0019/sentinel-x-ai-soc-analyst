import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

import polars as pl

from ai_analyst import analyze_threats
from config import settings
from eda import compute_eda
from ml import run_ml
from explainability import ensemble_threat_score, get_feature_importance
from threat_intel import enrich_threat_row

ProgressCallback = Callable[[str, int, str], None]


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _summary(total: int, ml_output: dict[str, Any]) -> dict[str, Any]:
    severity_counts = ml_output.get("severity_counts", {})
    attack_counts = ml_output.get("attack_counts", {})
    low = int(severity_counts.get("Low", 0))
    medium = int(severity_counts.get("Medium", 0))
    high = int(severity_counts.get("High", 0))
    critical = int(severity_counts.get("Critical", 0))
    normal = int(attack_counts.get("BENIGN", 0))
    threat_total = max(0, total - normal)
    return {
        "total_records": total,
        "normal_count": normal,
        "safe_count": normal,
        "low_count": low,
        "medium_count": medium,
        "suspicious_count": medium,
        "high_count": high,
        "likely_threat_count": high,
        "critical_count": critical,
        "threat_count": threat_total,
        "threat_percentage": round((threat_total / total) * 100, 2) if total else 0,
        "most_common_attack": ml_output.get("most_common_attack"),
    }


def run_pipeline(
    job_id: str,
    file_path: Path,
    original_name: str,
    ai_provider: str,
    gemini_api_key: str | None,
    ollama_model: str | None,
    ollama_base_url: str,
    progress: ProgressCallback,
) -> dict[str, Any]:
    start = time.perf_counter()
    job_dir = settings.jobs_dir / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    report_path = job_dir / "report.json"

    try:
        progress("eda", 15, "→ Loading CSV with Polars (infer_schema_length=10k)...")
        df = pl.read_csv(file_path, infer_schema_length=10_000, ignore_errors=True)
        
        progress("eda", 25, "→ normalize_columns() | clean_dataframe() | detect_columns()...")
        df, eda_output, detected_columns = compute_eda(df)
        if eda_output["numeric_columns_found"] == 0:
            raise ValueError("CSV has no numeric columns. Upload network logs with measurable traffic fields.")

        progress("ml", 40, "→ IsolationForest(n_estimators=100) | fitting on sample...")
        scored_df, ml_output = run_ml(df, detected_columns, job_dir)

        progress("ml", 60, "→ RandomForestClassifier | classification_report() | confusion_matrix()...")
        total = int(eda_output["total_records"])
        # Re-compute traffic_over_time using ML-labeled threats
        timestamp_col = detected_columns.get("timestamp")
        if timestamp_col:
            parsed = scored_df.with_columns(
                pl.col(timestamp_col)
                .str.to_datetime(strict=False)
                .dt.truncate("1h")
                .alias("__bucket")
            )
            valid = parsed.filter(pl.col("__bucket").is_not_null())
            if len(valid):
                traffic_over_time = [
                    {
                        "bucket": str(row["__bucket"]),
                        "count": int(row["count"]),
                        "flagged_count": int(row["flagged_count"]),
                    }
                    for row in valid.group_by("__bucket")
                    .agg([
                        pl.len().alias("count"),
                        pl.col("risk_score").filter(pl.col("risk_score") >= 40).len().alias("flagged_count")
                    ])
                    .sort("__bucket")
                    .to_dicts()
                ]
                eda_output["traffic_over_time"] = traffic_over_time

        report = {
            "job_id": job_id,
            "status": "processing",
            "file_name": original_name,
            "processed_at": datetime.now(UTC).isoformat(),
            "pipeline_duration_seconds": None,
            "ai_provider_used": ai_provider,
            "ollama_model_used": ollama_model if ai_provider == "ollama" else None,
            "summary": _summary(total, ml_output),
            "eda": eda_output,
            "ml": ml_output,
            "ai_analysis": None,
        }
        _write_json(report_path, report)

        progress("ai", 80, "→ enrich_threats() | IP intelligence | SHAP explanations...")
        # Enrich threats with IP intelligence
        top_threats = ml_output.get("top_threats", [])
        enriched_threats = []
        for threat in top_threats[:20]:  # Enrich top 20 threats
            enriched = enrich_threat_row(threat)
            enriched_threats.append(enriched)
        ml_output["top_threats"] = enriched_threats
        
        # Add SHAP feature importance to top threats (sample for performance)
        try:
            feature_importance = get_feature_importance(scored_df, ml_output)
            for i, threat in enumerate(enriched_threats[:5]):  # SHAP for top 5 only
                if feature_importance:
                    threat["shap_features"] = feature_importance.get("top_features", [])
                    threat["threat_factors"] = feature_importance.get("summary", "")
        except Exception as e:
            print(f"SHAP explainability warning: {e}")
        
        progress("ai", 85, "→ analyze_threats() | format_for_ai() | LLM.generate_response()...")
        ai_analysis = analyze_threats(
            ai_provider,
            ml_output["top_threats"],
            total,
            gemini_api_key=gemini_api_key,
            ollama_model=ollama_model,
            ollama_base_url=ollama_base_url,
        )
        if not ai_analysis or ai_analysis.get("provider") == "none":
            report["ai_provider_used"] = "none"
            report["ollama_model_used"] = None
            report["ai_analysis"] = None
        else:
            report["ai_analysis"] = ai_analysis
            # If AI returned an overall severity, reflect it in the summary so dashboard shows AI findings
            ai_sev = ai_analysis.get("severity")
            if ai_sev in ("Critical", "High", "Medium", "Low"):
                report["summary"]["ai_overall_severity"] = ai_sev
                # Ensure numeric keys exist
                report["summary"].setdefault("critical_count", 0)
                report["summary"].setdefault("high_count", report["summary"].get("high_count", 0))
                report["summary"].setdefault("medium_count", report["summary"].get("medium_count", 0))
                ai_records = int(ai_analysis.get("records_analyzed", 1))
                if ai_sev == "Critical":
                    report["summary"]["critical_count"] = max(report["summary"].get("critical_count", 0), ai_records)
                elif ai_sev == "High":
                    report["summary"]["high_count"] = max(report["summary"].get("high_count", 0), ai_records)
                elif ai_sev == "Medium":
                    report["summary"]["medium_count"] = max(report["summary"].get("medium_count", 0), ai_records)
                # update display aliases used by frontend
                report["summary"]["likely_threat_count"] = report["summary"].get("high_count", 0)
                report["summary"]["suspicious_count"] = report["summary"].get("medium_count", 0)

        progress("done", 95, "→ report.json | scoring.csv | scored.parquet | COMPLETE")
        report["status"] = "complete"
        report["pipeline_duration_seconds"] = round(time.perf_counter() - start, 2)
        _write_json(report_path, report)
        progress("done", 100, "✨ SENTINEL-X pipeline complete")
        return report
    except Exception as exc:
        error_report = {
            "job_id": job_id,
            "status": "error",
            "file_name": original_name,
            "processed_at": datetime.now(UTC).isoformat(),
            "pipeline_duration_seconds": round(time.perf_counter() - start, 2),
            "ai_provider_used": "none",
            "ollama_model_used": None,
            "summary": None,
            "eda": None,
            "ml": None,
            "ai_analysis": None,
            "error": str(exc),
        }
        _write_json(report_path, error_report)
        progress("error", -1, str(exc))
        return error_report
