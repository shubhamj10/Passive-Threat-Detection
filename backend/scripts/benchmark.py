"""Measure throughput and latency on THIS machine. Writes reports/benchmark.json.

1. engine:  records/s through the detection engine (in-process, no network)
2. diode:   records/s end-to-end over the one-way UDP link (sender -> receive-only
            socket -> parser -> queue -> engine), with drops and p95 latencies
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import threading
import time
from datetime import datetime, timezone

import _path  # noqa: F401
from app.config import DATA_DIR, REPORTS_DIR, load_config
from app.enclave.detectors.base import make_detectors
from app.enclave.ingest.parser import STRIPPED_FIELDS, normalise
from app.enclave.pipeline.engine import Engine, load_bigram
from app.enclave.pipeline.stream import StreamPipeline
from app.generator.scenario import read_jsonl
from app.generator.sender import TrafficSender


def p95(xs):
    xs = sorted(xs)
    return round(xs[int(0.95 * (len(xs) - 1))], 2) if xs else None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--file", default=str(DATA_DIR / "synthetic" / "scenario_01.jsonl"))
    ap.add_argument("--speed", type=float, default=200.0, help="time_scale for the diode run")
    ap.add_argument("--port", type=int, default=0, help="UDP port (default: config port + 1)")
    args = ap.parse_args(argv)
    cfg = load_config()
    objs = list(read_jsonl(args.file))
    print(f"loaded {len(objs)} records from {args.file}")

    # 1. engine only (records pre-parsed so we time detection, not JSON)
    recs = [normalise({k: v for k, v in o.items() if k not in STRIPPED_FIELDS}, 0.0) for o in objs]
    eng = Engine(cfg, make_detectors(cfg), load_bigram())
    t = time.perf_counter()
    for r in recs:
        eng.process(r)
    eng.flush()
    eng_s = time.perf_counter() - t
    engine_rate = len(recs) / eng_s
    print(f"engine: {engine_rate:,.0f} records/s ({len(eng.alerts)} alerts)")

    # 2. end-to-end over the software diode
    port = args.port or int(cfg["diode"]["port"]) + 1
    eng2 = Engine(cfg, make_detectors(cfg), load_bigram())
    pipe = StreamPipeline(eng2, "127.0.0.1", port, int(cfg["diode"]["queue_maxsize"]))
    pipe.start()
    sender = TrafficSender("127.0.0.1", port, time_scale=args.speed,
                           per_datagram=int(cfg["generator"]["records_per_datagram"]))
    sender.load(lambda: iter(objs), "benchmark", loop=False)
    t = time.time()
    sender.start()
    while sender.state not in ("finished", "stopped"):
        time.sleep(0.1)
    sent_done = time.time()
    while not pipe.q.empty() and time.time() - sent_done < 60:
        time.sleep(0.05)
    time.sleep(0.5)
    wall = time.time() - t
    received = pipe.parse_stats.ok
    sender.stop(); pipe.stop()
    diode = {
        "speed_time_scale": args.speed, "sent": sender.sent_records, "received": received,
        "processed": eng2.records, "dropped_queue": pipe.dropped,
        "lost_udp": max(0, sender.sent_records - received - pipe.parse_stats.malformed),
        "wall_s": round(wall, 2), "records_per_s": round(eng2.records / wall, 1),
        "p95_processing_latency_ms": p95(list(eng2.proc_latency_ms)),
        "median_processing_latency_ms": round(statistics.median(eng2.proc_latency_ms), 2) if eng2.proc_latency_ms else None,
        "p95_alert_latency_ms": p95(list(eng2.alert_latency_ms)), "alerts": len(eng2.alerts),
    }
    print(f"diode: {diode['records_per_s']:,.0f} records/s, lost {diode['lost_udp']}, "
          f"p95 processing latency {diode['p95_processing_latency_ms']} ms")
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "machine": {"platform": platform.platform(), "processor": platform.processor() or platform.machine(),
                    "cpu_count": os.cpu_count(), "python": platform.python_version()},
        "input": {"file": os.path.basename(args.file), "records": len(objs)},
        "engine_only": {"records_per_s": round(engine_rate, 1), "seconds": round(eng_s, 2), "alerts": len(eng.alerts)},
        "end_to_end_diode": diode,
        "target_flows_per_s": cfg["throughput"]["target_flows_per_s"],
        "note": "Single Python process, one engine thread. Quote these numbers with the machine details above.",
    }
    REPORTS_DIR.mkdir(exist_ok=True)
    out = REPORTS_DIR / "benchmark.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
