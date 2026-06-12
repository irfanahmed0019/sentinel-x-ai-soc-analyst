import json
import re
from typing import Any

from ollama_client import call_ollama


FIELDS = [
    "EXECUTIVE_SUMMARY",
    "ATTACK_TYPES",
    "SEVERITY_ASSESSMENT",
    "INDICATORS_OF_COMPROMISE",
    "MITRE_ATTACK_TECHNIQUES",
    "RECOMMENDED_IMMEDIATE_ACTIONS",
    "LONG_TERM_MITIGATIONS",
    "BUSINESS_IMPACT_ASSESSMENT",
]


def build_prompt(flagged_records: list[dict[str, Any]], total_records: int) -> str:
    slim_records = [
        {
            "src": row.get("src_ip", "unknown"),
            "dst": row.get("dst_ip", "unknown"),
            "port": row.get("dst_port", "?"),
            "proto": row.get("protocol", "?"),
            "risk_score": round(float(row.get("risk_score", 0)), 1),
            "severity": row.get("severity", "Low"),
            "threat_type": row.get("threat_type", "BENIGN"),
            "mitre": row.get("mitre_id"),
            "technique": row.get("mitre_technique"),
            "label": row.get("original_label", "unknown"),
        }
        for row in flagged_records[:20]
    ]
    records_json = json.dumps(slim_records, separators=(",", ":"))
    return f"""You are a SOC analyst.

Rules:
- Use only supplied evidence.
- Do not upgrade severity beyond ML thresholds.
- Critical requires risk score >= 90.
- High requires risk score 70-89.
- If no critical events exist, explicitly state that.

ANALYSIS CONTEXT:
- Total log entries analyzed: {total_records:,}
- Suspicious entries flagged by SENTINEL-X: {len(flagged_records[:20])}
- Top {len(flagged_records[:20])} highest-risk records (JSON): {records_json}

Respond in this EXACT format with these EXACT section headers:

EXECUTIVE_SUMMARY:
[2-4 concise sentences summarizing the security situation.]

ATTACK_TYPES:
[Observed attack classes and confidence. Do not invent classes not present.]

SEVERITY_ASSESSMENT:
[Overall severity: Critical / High / Medium / Low, with justification.]

INDICATORS_OF_COMPROMISE:
[Source IPs, destination IPs, ports, protocols, and notable patterns.]

MITRE_ATTACK_TECHNIQUES:
[List MITRE IDs and technique names visible in the data.]

RECOMMENDED_IMMEDIATE_ACTIONS:
1. [Immediate containment action]
2. [Investigation action]
3. [Monitoring or escalation action]

LONG_TERM_MITIGATIONS:
1. [Control hardening recommendation]
2. [Detection engineering recommendation]
3. [Process improvement recommendation]

BUSINESS_IMPACT_ASSESSMENT:
[Business risk and operational impact in 2-3 sentences.]

Be honest about uncertainty. Do not invent data not present in the records."""


def _extract_severity_level(text: str) -> str:
    """Extract a single severity word (Critical/High/Medium/Low) from free-form text."""
    text_upper = text.upper()
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if level in text_upper:
            return level.capitalize()
    return "Unknown"


def parse_ai_response(raw: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for index, field in enumerate(FIELDS):
        next_fields = "|".join(FIELDS[index + 1 :])
        terminator = rf"(?={next_fields}:|$)" if next_fields else "$"
        match = re.search(rf"{field}:\s*(.*?){terminator}", raw, re.DOTALL | re.IGNORECASE)
        result[field.lower()] = match.group(1).strip() if match else ""

    result["recommended_immediate_actions"] = re.findall(r"\d+\.\s*(.+)", result.get("recommended_immediate_actions", ""))
    result["long_term_mitigations"] = re.findall(r"\d+\.\s*(.+)", result.get("long_term_mitigations", ""))

    # Expose frontend-friendly aliases
    result["what_is_happening"] = result.get("executive_summary", "")
    result["actions"] = result.get("recommended_immediate_actions", [])

    # Extract a clean severity word and map it to a colour slug
    severity_level = _extract_severity_level(result.get("severity_assessment", ""))
    result["severity"] = severity_level
    result["severity_emoji"] = {
        "Critical": "red",
        "High": "orange",
        "Medium": "yellow",
        "Low": "green",
    }.get(severity_level, "gray")
    result["raw_response"] = raw
    return result


def analyze_threats(
    provider: str,
    top_threats: list[dict[str, Any]],
    total_records: int,
    gemini_api_key: str | None = None,
    ollama_model: str | None = None,
    ollama_base_url: str = "http://localhost:11434",
) -> dict[str, Any] | None:
    if provider == "none" or not top_threats:
        return None

    prompt = build_prompt(top_threats[:20], total_records)
    try:
        if provider == "gemini":
            if not gemini_api_key:
                return None
            from gemini_client import call_gemini

            raw = call_gemini(prompt, gemini_api_key)
            parsed = parse_ai_response(raw)
            return {"provider": "gemini", "model": "gemini-2.5-flash", "records_analyzed": len(top_threats[:20]), **parsed}
        if provider == "ollama":
            if not ollama_model:
                return None
            raw = call_ollama(prompt, ollama_model, ollama_base_url)
            parsed = parse_ai_response(raw)
            return {"provider": "ollama", "model": ollama_model, "records_analyzed": len(top_threats[:20]), **parsed}
    except Exception as exc:
        return {
            "provider": "none",
            "model": None,
            "records_analyzed": 0,
            "error": f"AI explanation skipped: {exc}",
        }
    return None
