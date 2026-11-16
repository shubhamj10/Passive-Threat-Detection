"""Generate synthetic traffic (seeded) or convert a public dataset.

  python scripts/make_dataset.py --seed 42                     # train + scenario_01 + evasion
  python scripts/make_dataset.py --seed 42 --scenario drift    # drift_scenario.jsonl
  python scripts/make_dataset.py --source public --path data/raw/<dataset_name>
"""
from __future__ import annotations

import argparse
import logging
import random
import sys

import _path  # noqa: F401
from app.config import DATA_DIR
from app.generator.names import load_benign_domains
from app.generator.scenario import (TRAIN_RATES, demo_schedule, evasion_schedule, generate, random_schedule,
                                    write_jsonl)

log = logging.getLogger("make_dataset")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--scenario", choices=["default", "drift", "benign"], default="default")
    ap.add_argument("--train-hours", type=float, default=2.0)
    ap.add_argument("--minutes", type=float, default=30.0, help="length of scenario files")
    ap.add_argument("--source", choices=["synthetic", "public"], default="synthetic")
    ap.add_argument("--path", help="folder of a downloaded public dataset (with --source public)")
    ap.add_argument("--out", default=str(DATA_DIR / "synthetic"))
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if args.source == "public":
        from app.offline.public import convert_public
        if not args.path:
            ap.error("--path is required with --source public")
        out = convert_public(args.path, DATA_DIR / "processed")
        log.info("converted public dataset -> %s", out)
        return 0

    from pathlib import Path
    out = Path(args.out)
    domains, from_file = load_benign_domains(DATA_DIR / "benign_domains.txt")
    if not from_file:
        log.warning("data/benign_domains.txt not found: using the built-in pseudo-benign name generator")
    meta = {"seed": args.seed, "benign_domains_from_file": from_file}
    dur = args.minutes * 60

    if args.scenario == "drift":
        recs, eps = generate(dur, args.seed + 3, domains, demo_schedule, drift_after_s=300)
        write_jsonl(recs, eps, out / "drift_scenario.jsonl", dict(meta, scenario="drift", drift_after_s=300))
        log.info("drift_scenario.jsonl: %d records, %d episodes", len(recs), len(eps))
        return 0
    if args.scenario == "benign":
        recs, eps = generate(dur, args.seed + 4, domains, None)
        write_jsonl(recs, eps, out / "benign_scenario.jsonl", dict(meta, scenario="benign"))
        log.info("benign_scenario.jsonl: %d records", len(recs))
        return 0

    train_dur = args.train_hours * 3600
    recs, eps = generate(train_dur, args.seed, domains,
                         lambda t0, rng: random_schedule(t0, train_dur, rng, TRAIN_RATES))
    write_jsonl(recs, eps, out / "train.jsonl", dict(meta, scenario="train", hours=args.train_hours))
    log.info("train.jsonl: %d records, %d episodes", len(recs), len(eps))
    recs, eps = generate(dur, args.seed + 1, domains, demo_schedule)
    write_jsonl(recs, eps, out / "scenario_01.jsonl", dict(meta, scenario="demo"))
    log.info("scenario_01.jsonl: %d records, %d episodes", len(recs), len(eps))
    recs, eps = generate(dur, args.seed + 2, domains, evasion_schedule)
    write_jsonl(recs, eps, out / "evasion.jsonl", dict(meta, scenario="evasion"))
    log.info("evasion.jsonl: %d records, %d episodes", len(recs), len(eps))
    return 0


if __name__ == "__main__":
    sys.exit(main())
