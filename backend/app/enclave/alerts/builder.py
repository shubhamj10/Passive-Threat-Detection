"""Build standard alerts (with decision trace) from passed candidates."""
from __future__ import annotations

from datetime import datetime, timezone

from ..detectors.base import Candidate, Detector
from ..scoring.severity import severity_for


def iso(ts: float, ms: bool = True) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z" if ms \
        else dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class IdGen:
    def __init__(self, prefix: str, start_seq: int = 0):
        self.prefix, self.seq = prefix, start_seq

    def next(self, ts: float) -> str:
        self.seq += 1
        day = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y%m%d")
        return f"{self.prefix}-{day}-{self.seq:06d}"


def flow_id_for(c: Candidate) -> str:
    ctx = c.context
    if c.detector == "ddos_scorer":
        return f"*->{ctx['dst_ip']}:{ctx['dst_port']}/{ctx['proto']}"
    if c.detector == "beacon_scorer":
        return f"{ctx['src_ip']}:{ctx['last_src_port']}->{ctx['dst_ip']}:{ctx['dst_port']}/{ctx['proto']}"
    return f"{ctx['src_ip']}:*->{ctx.get('resolver') or '?'}:53/UDP"


def build_alert(c: Candidate, det: Detector, ids: IdGen, cfg_hash: str, trust: int | None, cfg: dict) -> dict:
    row = c.row
    subtype = c.context.get("attack_subtype")
    return {
        "alert_id": ids.next(row.window_end),
        "timestamp": iso(row.window_end),
        "flow_id": flow_id_for(c),
        "threat_class": c.threat_class,
        "attack_subtype": subtype,
        "severity": severity_for(c.threat_class, c.confidence, row.features, cfg),
        "confidence": c.confidence,
        "entity": c.entity,
        "model": {"name": det.name, "version": det.version},
        "evidence": {
            "features": {k: float(v) for k, v in row.features.items()},
            "thresholds": dict(c.thresholds),
            "gates_passed": list(c.gates_passed),
            "top_shap_features": det.top_features(row.features),
            "evidence_method": det.explainer.method,
            "context": c.context,
        },
        "trace": {
            "config_hash": cfg_hash,
            "data_window": {"start": iso(row.window_start, ms=False), "end": iso(row.window_end, ms=False)},
            "detector_trust_score": trust,
            "raw_score": c.raw_prob,
        },
        "mitre_attack": det.mitre(c.threat_class, subtype),
        "recommended_action": det.action(c.threat_class, subtype),
        "ai_explanation": None,
    }
