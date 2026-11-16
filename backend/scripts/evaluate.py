"""Time-based, alert-level evaluation. Writes reports/metrics.json.

Row-level test metrics come from the time-based split done in train.py
(last 20% of the training timeline). Alert-level metrics run the FULL
pipeline (windows, gates, dedup) over held-out scenario files that were
generated with different seeds.
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib

import _path  # noqa: F401
from app.config import DATA_DIR, MODELS_DIR, REPORTS_DIR, load_config
from app.enclave.detectors.base import bundle_path, load_registry
from app.offline.evaluation import evaluate_file


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scenario", default=str(DATA_DIR / "synthetic" / "scenario_01.jsonl"))
    ap.add_argument("--evasion", default=str(DATA_DIR / "synthetic" / "evasion.jsonl"))
    ap.add_argument("--benign", default=str(DATA_DIR / "synthetic" / "benign_scenario.jsonl"))
    args = ap.parse_args(argv)
    cfg = load_config()
    reg = load_registry()
    if not reg:
        print("no models: run scripts/train.py first", file=sys.stderr)
        return 1
    report = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "machine": {"platform": platform.platform(), "python": platform.python_version()},
              "models": reg, "row_level_test": {}, "alert_level": {}}
    for name, ver in reg.items():
        b = joblib.load(bundle_path(name, ver))
        report["row_level_test"][name] = b["metrics"]
    for key, p in (("scenario", args.scenario), ("evasion", args.evasion), ("benign", args.benign)):
        path = Path(p)
        if not path.exists():
            print(f"skip {key}: {path} not found")
            continue
        print(f"evaluating {path.name} ...")
        report["alert_level"][key] = evaluate_file(path, cfg)
    REPORTS_DIR.mkdir(exist_ok=True)
    out = REPORTS_DIR / "metrics.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    for key, res in report["alert_level"].items():
        print(f"\n[{key}] {res['file']}  high-severity false alerts: {res['high_severity_false_alerts']}")
        for c, m in res["per_class"].items():
            if m["episodes"] or m["alerts"]:
                lat = m["detection_latency_s"]["median"] if m["detection_latency_s"] else None
                print(f"  {c:20s} detected {m['detected']}/{m['episodes']}  alerts {m['alerts']} "
                      f"(false {m['false_alerts']})  median latency {lat if lat is None else round(lat)} s")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
