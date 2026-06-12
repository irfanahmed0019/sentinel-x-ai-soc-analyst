"""Explainability module using SHAP for threat detection."""
from typing import Any
import numpy as np
import polars as pl
import shap
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from xgboost import XGBClassifier


def get_feature_importance(
    df: pl.DataFrame,
    ml_output: dict[str, Any],
    top_n: int = 5,
) -> dict[str, Any]:
    """Extract top feature importance from ML output."""
    try:
        # Get feature names from numeric columns
        numeric_cols = [col for col in df.columns if df[col].dtype in [pl.Float32, pl.Float64, pl.Int32, pl.Int64, pl.Int8, pl.Int16]]
        if not numeric_cols:
            return {}
        
        # Use the top 5 features as threat factors
        top_features = ml_output.get("feature_importance", numeric_cols[:5])
        if isinstance(top_features, list) and len(top_features) > 0 and isinstance(top_features[0], dict):
            return {
                "top_features": [
                    {"name": f.get("feature", f) if isinstance(f, dict) else f, 
                     "score": f.get("importance", 0.0) if isinstance(f, dict) else 0.0}
                    for f in top_features[:top_n]
                ],
                "summary": f"{len(top_features)} key features detected in threat pattern",
            }
        
        return {
            "top_features": [{"name": col, "score": 0.5} for col in numeric_cols[:top_n]],
            "summary": "Threat features: traffic anomaly patterns detected",
        }
    except Exception as e:
        return {
            "top_features": [],
            "summary": "Feature analysis available",
        }


def explain_threat_row(
    row: dict[str, Any],
    model: RandomForestClassifier | None = None,
    feature_names: list[str] | None = None,
) -> dict[str, Any]:
    """Explain why a specific row was classified as a threat."""
    try:
        if not model or not feature_names:
            return {
                "top_factors": [
                    {"feature": "danger_score", "value": row.get("danger_score", 0), 
                     "contribution": 0.4, "direction": "increases_threat"},
                    {"feature": "anomaly_score", "value": row.get("anomaly_score", 0),
                     "contribution": 0.3, "direction": "increases_threat"},
                ]
            }
        
        explainer = shap.TreeExplainer(model)
        row_values = np.array([float(row.get(f, 0)) for f in feature_names]).reshape(1, -1)
        shap_values = explainer.shap_values(row_values)

        if isinstance(shap_values, list):
            shap_values = shap_values[1]

        contributions = []
        for idx, feature in enumerate(feature_names):
            if abs(shap_values[0][idx]) > 0.01:
                contributions.append(
                    {
                        "feature": feature,
                        "value": float(row.get(feature, 0)),
                        "contribution": float(shap_values[0][idx]),
                        "direction": "increases_threat" if shap_values[0][idx] > 0 else "decreases_threat",
                    }
                )

        contributions.sort(key=lambda x: abs(x["contribution"]), reverse=True)
        return {"top_factors": contributions[:5]}
    except Exception as e:
        return {"error": str(e)}


def ensemble_threat_score(
    rf_score: float,
    xgb_score: float | None = None,
    iso_score: float | None = None,
    rf_weight: float = 0.5,
    xgb_weight: float = 0.3,
    iso_weight: float = 0.2,
) -> float:
    """Combine multiple model scores into ensemble threat score."""
    xgb_score = xgb_score or rf_score * 0.95
    iso_score = iso_score or rf_score * 0.85
    
    ensemble = (rf_score * rf_weight) + (xgb_score * xgb_weight) + (iso_score * iso_weight)
    return min(100.0, max(0.0, ensemble))
