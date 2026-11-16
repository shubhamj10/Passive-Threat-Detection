"""Decision trace replay: re-run a stored alert with the same data, model and settings."""
from __future__ import annotations

from pathlib import Path

from ...config import config_hash
from ..detectors.base import detector_class, load_bundle


def replay_alert(alert: dict, cfg: dict, models_dir: Path | None = None) -> dict:
    name, version = alert["model"]["name"], alert["model"]["version"]
    try:
        bundle = load_bundle(name, version, models_dir)
    except FileNotFoundError as e:
        return {"alert_id": alert["alert_id"], "reproduced": False, "error": str(e)}
    cls = detector_class(name)
    det = cls(bundle, cfg)
    ev = alert["evidence"]
    feats, ctx, th = ev["features"], ev["context"], ev["thresholds"]
    raw, conf = det.score_features(feats)
    tclass, sub = cls.classify(feats, th)
    passed, failed = cls.gates(tclass, feats, ctx, th)
    top = det.top_features(feats)
    checks = {
        "model_version": f"{name} {version}",
        "config_hash_match": config_hash(cfg) == alert["trace"]["config_hash"],
        "threat_class_match": tclass == alert["threat_class"],
        "confidence_match": conf == alert["confidence"],
        "raw_score_match": abs(raw - alert["trace"]["raw_score"]) < 1e-12,
        "gates_match": sorted(passed) == sorted(ev["gates_passed"]) and not failed,
        "top_features_match": top == ev["top_shap_features"],
        "evidence_method": det.explainer.method,
    }
    core = ("threat_class_match", "confidence_match", "gates_match", "raw_score_match")
    if ev.get("evidence_method") == det.explainer.method:
        core += ("top_features_match",)
    return {
        "alert_id": alert["alert_id"],
        "reproduced": all(checks[k] for k in core),
        "checks": checks,
        "replayed": {"threat_class": tclass, "attack_subtype": sub, "confidence": conf, "raw_score": raw,
                     "gates_passed": passed, "gates_failed": failed, "top_shap_features": top},
        "original": {"threat_class": alert["threat_class"], "confidence": alert["confidence"],
                     "raw_score": alert["trace"]["raw_score"], "gates_passed": ev["gates_passed"],
                     "top_shap_features": ev["top_shap_features"]},
    }
