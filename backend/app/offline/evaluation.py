"""Alert-level evaluation of the full pipeline against injected ground truth."""
from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from ..enclave.assurance.monitor import AssuranceMonitor
from ..enclave.detectors.base import make_detectors
from ..enclave.pipeline.engine import Engine, load_bigram
from ..generator.scenario import THREAT_OF, read_jsonl, read_labels
from .featurize import to_flow
from .labels import EpisodeIndex

CLASSES = ["ddos", "botnet_c2_beaconing", "dga_domain", "dns_tunnelling"]


def run_file(path: Path, cfg: dict, models_dir: Path | None = None, with_monitor: bool = False):
    dets = make_detectors(cfg, models_dir)
    mon = AssuranceMonitor(cfg, dets) if with_monitor else None
    eng = Engine(cfg, dets, load_bigram(models_dir), monitor=mon)
    for obj in read_jsonl(path):
        r = to_flow(obj)
        if r is not None:
            eng.process(r)
    eng.flush()
    return eng, mon


def _ts(iso_s: str) -> float:
    return datetime.fromisoformat(iso_s.replace("Z", "+00:00")).timestamp()


def score_alerts(alerts: list[dict], episodes: list[dict], duration_h: float) -> dict:
    idx = EpisodeIndex(episodes)
    attack_eps = [e for e in episodes if e["class"] in THREAT_OF]
    first_hit: dict[str, float] = {}
    tp = Counter(); fp = Counter()
    confusion: dict[str, Counter] = defaultdict(Counter)
    for a in alerts:
        e = idx.match_alert(a)
        tc = a["threat_class"]
        if e:
            tp[tc] += 1
            confusion[THREAT_OF[e["class"]]][tc] += 1
            t = _ts(a["trace"]["data_window"]["end"])
            first_hit[e["id"]] = min(first_hit.get(e["id"], t), t)
        else:
            fp[tc] += 1
            confusion["benign"][tc] += 1
    per_class = {}
    for c in CLASSES:
        eps = [e for e in attack_eps if THREAT_OF[e["class"]] == c]
        det = [e for e in eps if e["id"] in first_hit]
        n_alerts = tp[c] + fp[c]
        prec = tp[c] / n_alerts if n_alerts else None
        rec = len(det) / len(eps) if eps else None
        f1 = (2 * prec * rec / (prec + rec)) if prec and rec else (0.0 if eps else None)
        lat = [first_hit[e["id"]] - e["start"] for e in det]
        for e in eps:
            if e["id"] not in first_hit:
                confusion[c]["missed"] += 1
        per_class[c] = {
            "episodes": len(eps), "detected": len(det), "recall": rec, "alerts": n_alerts,
            "true_alerts": tp[c], "false_alerts": fp[c], "precision": prec, "f1": f1,
            "false_alerts_per_hour": round(fp[c] / duration_h, 3) if duration_h else None,
            "detection_latency_s": {"median": statistics.median(lat), "max": max(lat)} if lat else None,
        }
    return {"per_class": per_class,
            "confusion_matrix": {k: dict(v) for k, v in confusion.items()},
            "confusion_matrix_note": "rows = ground truth (benign = no matching episode), columns = alerted class"}


def evaluate_file(path: Path, cfg: dict, models_dir: Path | None = None) -> dict:
    labels = read_labels(path)
    eng, mon = run_file(path, cfg, models_dir, with_monitor=True)
    dur_h = max((eng.max_ts - eng.first_ts) / 3600.0, 1e-9) if eng.first_ts else 0
    res = score_alerts(eng.alerts, labels["episodes"], dur_h)
    res["file"] = path.name
    res["records"] = eng.records
    res["duration_h"] = round(dur_h, 3)
    res["high_severity_false_alerts"] = sum(
        1 for a in eng.alerts if a["severity"] in ("high", "critical")
        and EpisodeIndex(labels["episodes"]).match_alert(a) is None)
    res["final_trust_scores"] = {n: s["trust_score"] for n, s in mon.status.items()}
    res["assurance_alerts"] = sum(1 for k, _ in eng.assurance_events if k == "assurance_alert")
    return res
