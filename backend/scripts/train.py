"""Build features, train, calibrate and save models (+ drift baselines) to models/."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import _path  # noqa: F401
from app.config import DATA_DIR, MODELS_DIR, REPORTS_DIR, load_config
from app.generator.names import load_benign_domains
from app.offline.training import train_all


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", default=str(DATA_DIR / "synthetic" / "train.jsonl"))
    ap.add_argument("--version", default="1.0.0")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--models", default=str(MODELS_DIR))
    args = ap.parse_args(argv)
    data = Path(args.data)
    if not data.exists():
        print(f"{data} not found. Run: python scripts/make_dataset.py", file=sys.stderr)
        return 1
    cfg = load_config()
    domains, _ = load_benign_domains(DATA_DIR / "benign_domains.txt")
    summary = train_all(data, cfg, Path(args.models), domains, args.version, args.seed)
    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR / "training.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    for name, m in summary.items():
        if name.startswith("_"):
            continue
        t = m["test"]
        print(f"{name:14s} test P={t['precision']:.3f} R={t['recall']:.3f} F1={t['f1']:.3f} "
              f"FPR={t['false_positive_rate']:.4f}  baseline alerts/min={m['baseline_alert_rate_per_min']}")
    print(f"models saved to {args.models}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
