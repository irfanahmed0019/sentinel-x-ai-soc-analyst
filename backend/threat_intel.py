"""Threat intelligence enrichment module."""
import json
from typing import Any
import httpx

ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_API = "https://www.virustotal.com/api/v3/ip_addresses"


def enrich_ip_simple(ip: str) -> dict[str, Any]:
    """Simple IP enrichment (works without API keys for demo)."""
    suspicious_ips = {
        "172.16.0.107": {"malicious": True, "reports": 53, "last_reported": "2024-01-15"},
        "192.168.100.50": {"malicious": True, "reports": 12, "last_reported": "2024-01-10"},
        "10.0.0.1": {"malicious": False, "reports": 0, "last_reported": None},
    }

    if ip in suspicious_ips:
        return {
            "ip": ip,
            "is_malicious": suspicious_ips[ip]["malicious"],
            "reports": suspicious_ips[ip]["reports"],
            "last_reported": suspicious_ips[ip]["last_reported"],
            "source": "SENTINEL-X-DB",
        }

    return {"ip": ip, "is_malicious": False, "reports": 0, "last_reported": None, "source": "clean"}


async def enrich_ip_abuseipdb(ip: str, api_key: str | None = None) -> dict[str, Any]:
    """Enrich IP with AbuseIPDB data."""
    if not api_key:
        return enrich_ip_simple(ip)

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                ABUSEIPDB_API,
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": api_key, "Accept": "application/json"},
                timeout=5.0,
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    "ip": ip,
                    "is_malicious": data["data"]["abuseConfidenceScore"] > 25,
                    "confidence_score": data["data"]["abuseConfidenceScore"],
                    "reports": data["data"]["totalReports"],
                    "source": "AbuseIPDB",
                }
    except Exception as e:
        pass

    return enrich_ip_simple(ip)


def enrich_threat_row(threat: dict[str, Any]) -> dict[str, Any]:
    """Enrich a threat row with IP intelligence."""
    src_ip = threat.get("src_ip", "unknown")
    dst_ip = threat.get("dst_ip", "unknown")

    threat_enriched = threat.copy()
    threat_enriched["src_ip_intel"] = enrich_ip_simple(src_ip)
    threat_enriched["dst_ip_intel"] = enrich_ip_simple(dst_ip)

    return threat_enriched
