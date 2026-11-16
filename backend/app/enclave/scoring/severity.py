"""Severity from calibrated confidence (and impact hints for DDoS)."""
from __future__ import annotations


def severity_for(threat_class: str, confidence: float, features: dict, cfg: dict) -> str:
    s = cfg["detection"]["severity"]
    if threat_class == "ddos" and confidence >= s["high"] and features.get("pkts_per_s", 0) > 2000:
        return "critical"
    if confidence >= s["high"]:
        return "high"
    if confidence >= s["medium"]:
        return "medium"
    return "low"
