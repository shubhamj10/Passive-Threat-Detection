"""Train, calibrate and save the three detectors with a TIME-BASED split."""
from __future__ import annotations

import json
import platform
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

from ..enclave.assurance.drift import make_baseline
from ..enclave.detectors.base import bundle_path, load_registry, registry_path
from ..enclave.features.beacon import BEACON_FEATURES
from ..enclave.features.common import split_domain
from ..enclave.features.ddos import DDOS_FEATURES
from ..enclave.features.dns import DNS_FEATURES, BigramModel
from ..enclave.scoring.calibration import PlattCalibrator
from ..generator.scenario import read_jsonl, read_labels
from .featurize import featurize
from .labels import EpisodeIndex

FEATURES = {"ddos_scorer": DDOS_FEATURES, "beacon_scorer": BEACON_FEATURES, "dns_scorer": DNS_FEATURES}


def _allowlisted(name: str, row, cfg: dict) -> bool:
    allow = cfg["detection"].get("allowlist", {}) or {}
    dsts, doms = set(allow.get("destinations") or []), set(allow.get("domains") or [])
    if name in ("ddos_scorer", "beacon_scorer"):
        return row.context["dst_ip"] in dsts
    return row.context["base_domain"] in doms


def _first_ts(path: Path) -> float:
    for obj in read_jsonl(path):
        return float(obj["ts"])
    return 0.0


def build_bigram(benign_domains: list[str]) -> BigramModel:
    return BigramModel.fit([split_domain(d)[1] for d in benign_domains])


def _metrics(y, p, thr) -> dict:
    yhat = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, yhat, labels=[0, 1]).ravel()
    out = {"n": int(len(y)), "positives": int(y.sum()), "precision": float(precision_score(y, yhat, zero_division=0)),
           "recall": float(recall_score(y, yhat, zero_division=0)), "f1": float(f1_score(y, yhat, zero_division=0)),
           "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
           "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}}
    if len(set(y.tolist())) == 2:
        out["roc_auc"] = float(roc_auc_score(y, p))
    return out


def train_all(train_file: Path, cfg: dict, models_dir: Path, benign_domains: list[str],
              version: str = "1.0.0", seed: int = 42, log=print) -> dict:
    models_dir.mkdir(parents=True, exist_ok=True)
    t_start = time.time()
    bigram = build_bigram(benign_domains)
    bigram.save(models_dir / "dns_bigrams.json")
    labels = read_labels(train_file)
    idx = EpisodeIndex(labels["episodes"])
    log(f"featurising {train_file.name} ...")
    rows = featurize(read_jsonl(train_file), cfg, bigram)
    data_start = _first_ts(train_file)
    summary = {}
    cutoffs = {}
    for name, feats in FEATURES.items():
        rs = [r for r in rows[name] if not _allowlisted(name, r, cfg)]
        X = np.array([[r.features[f] for f in feats] for r in rs], dtype=float)
        y = np.array([1 if idx.match_row(name, r) else 0 for r in rs], dtype=int)
        t = np.array([r.window_end for r in rs])
        t0, t1 = t.min(), t.max()
        c1, c2 = t0 + 0.6 * (t1 - t0), t0 + 0.8 * (t1 - t0)
        cutoffs[name] = float(c1)
        tr, va, te = t < c1, (t >= c1) & (t < c2), t >= c2
        full = np.array([r.window_start >= data_start for r in rs])  # drift baseline: complete, benign windows only
        log(f"{name}: rows={len(rs)} pos={int(y.sum())} train/val/test={tr.sum()}/{va.sum()}/{te.sum()}")
        model = RandomForestClassifier(n_estimators=120, max_depth=10, min_samples_leaf=3,
                                       class_weight="balanced_subsample", random_state=seed, n_jobs=1)
        model.fit(X[tr], y[tr])
        cal = PlattCalibrator.fit(model.predict_proba(X[va])[:, 1], y[va])
        thr = float(cfg["detection"][name.split("_")[0]]["alert_threshold"])
        p_test = np.array([cal(p) for p in model.predict_proba(X[te])[:, 1]])
        metrics = {"test": _metrics(y[te], p_test, thr), "threshold": thr,
                   "split": {"train_end": float(c1), "val_end": float(c2), "method": "time_based_60_20_20"}}
        bundle = {
            "name": name, "version": version, "feature_names": feats, "model": model,
            "calibrator": cal.to_dict(), "means": X[tr].mean(axis=0).tolist(),
            "stds": X[tr].std(axis=0).tolist(), "baseline": make_baseline(X[tr & full & (y == 0)], feats),
            "baseline_alert_rate_per_min": 0.0, "metrics": metrics,
            "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "training_data": {"file": train_file.name, "rows": int(len(rs)), "positives": int(y.sum()),
                              "meta": labels.get("meta", {})},
            "algorithm": "RandomForestClassifier + Platt calibration",
        }
        joblib.dump(bundle, bundle_path(name, version, models_dir))
        summary[name] = metrics
    reg = load_registry(models_dir)
    reg.update({n: version for n in FEATURES})
    registry_path(models_dir).write_text(json.dumps(reg, indent=2), encoding="utf-8")

    # alert-volume baseline: run the full pipeline over the later (out-of-sample) part
    log("computing alert-volume baseline ...")
    rates = baseline_alert_rates(train_file, cfg, models_dir, min(cutoffs.values()))
    for name in FEATURES:
        p = bundle_path(name, version, models_dir)
        b = joblib.load(p)
        b["baseline_alert_rate_per_min"] = rates[name]
        joblib.dump(b, p)
        meta = {k: v for k, v in b.items() if k not in ("model", "baseline")}
        meta["feature_importances"] = dict(zip(b["feature_names"], map(float, b["model"].feature_importances_)))
        (models_dir / f"{name}-{version}.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        summary[name]["baseline_alert_rate_per_min"] = rates[name]
    summary["_run"] = {"seconds": round(time.time() - t_start, 1), "python": platform.python_version(),
                       "machine": platform.machine(), "platform": platform.platform()}
    return summary


def baseline_alert_rates(train_file: Path, cfg: dict, models_dir: Path, from_ts: float) -> dict:
    from ..enclave.detectors.base import make_detectors
    from ..enclave.pipeline.engine import Engine, load_bigram
    from .featurize import to_flow
    dets = make_detectors(cfg, models_dir)
    eng = Engine(cfg, dets, load_bigram(models_dir))
    first = None
    for obj in read_jsonl(train_file):
        if obj["ts"] < from_ts:
            continue
        r = to_flow(obj)
        if r is None:
            continue
        first = first if first is not None else r.ts
        eng.process(r)
    eng.flush()
    minutes = max((eng.max_ts - first) / 60.0, 1.0) if first is not None else 1.0
    out = {n: 0.0 for n in dets}
    for a in eng.alerts:
        out[a["model"]["name"]] += 1
    return {n: round(c / minutes, 5) for n, c in out.items()}
