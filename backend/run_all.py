"""Start generator (simulated production side) + enclave pipeline + API in one process.

  python run_all.py --mode demo                       # loop a generated 30-minute scenario
  python run_all.py --mode replay --file data/synthetic/scenario_01.jsonl
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

os.environ["PTD_NO_DEFAULT_APP"] = "1"   # we build the app ourselves with the full runtime

import uvicorn

from app.api.main import create_app
from app.api.runtime import Runtime
from app.config import DATA_DIR, get_config, load_env, resolve
from app.enclave.alerts.store import AlertStore
from app.enclave.assurance.monitor import AssuranceMonitor
from app.enclave.detectors.base import make_detectors
from app.enclave.pipeline.engine import Engine, load_bigram
from app.enclave.pipeline.stream import StreamPipeline
from app.generator.names import load_benign_domains
from app.generator.scenario import demo_schedule, generate
from app.generator.sender import TrafficSender

log = logging.getLogger("run_all")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["demo", "replay"], default="demo")
    ap.add_argument("--file", help="JSONL file for --mode replay")
    ap.add_argument("--speed", type=float, help="override generator.time_scale")
    ap.add_argument("--keep-db", action="store_true", help="keep alerts from previous runs")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    load_env()
    cfg = get_config()

    try:
        detectors = make_detectors(cfg)
        bigram = load_bigram()
    except FileNotFoundError as e:
        log.error("%s\nRun first: python scripts/make_dataset.py && python scripts/train.py", e)
        return 1

    store = AlertStore(resolve(cfg["storage"]["sqlite_path"]))
    if not args.keep_db:
        store.clear()
    rt = Runtime(cfg=cfg, store=store, mode=args.mode)
    monitor = AssuranceMonitor(cfg, detectors, feedback_fn=store.feedback_stats,
                               start_seq=store.max_seq("assurance_alerts"))
    engine = Engine(cfg, detectors, bigram, store=store, monitor=monitor,
                    on_event=rt.broadcaster.publish, collect=False)
    d = cfg["diode"]
    pipeline = StreamPipeline(engine, d["host"], int(d["port"]), int(d["queue_maxsize"]),
                              bufsize=int(d["max_datagram_bytes"]) + 1024)
    g = cfg["generator"]
    sender = TrafficSender(d["host"], int(d["port"]), time_scale=args.speed or float(g["time_scale"]),
                           per_datagram=int(g["records_per_datagram"]), max_bytes=int(d["max_datagram_bytes"]))
    if args.mode == "replay":
        if not args.file:
            ap.error("--file is required with --mode replay")
        sender.load_file(resolve(args.file), loop=False)
    else:
        domains, _ = load_benign_domains(DATA_DIR / "benign_domains.txt")
        minutes = float(g["demo_minutes"])
        state = {"loop": 0}

        def demo_source():
            state["loop"] += 1
            recs, _eps = generate(minutes * 60, args.seed + state["loop"], domains, demo_schedule)
            return iter(recs)
        sender.load(demo_source, f"demo ({minutes:.0f} min loop)", loop=True)

    rt.engine, rt.pipeline, rt.sender, rt.monitor = engine, pipeline, sender, monitor
    pipeline.start()
    sender.start()
    host = os.environ.get("API_HOST", "127.0.0.1")
    port = int(os.environ.get("API_PORT", "8000"))
    log.info("enclave listening (receive-only) on udp://%s:%s; API on http://%s:%s", d["host"], d["port"], host, port)
    try:
        uvicorn.run(create_app(rt), host=host, port=port, log_level="warning")
    finally:
        sender.stop()
        pipeline.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
