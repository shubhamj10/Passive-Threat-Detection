"""Shared runtime state for the API: store, engine, pipeline, sender, broadcaster."""
from __future__ import annotations

import queue
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..config import config_hash, get_config, resolve
from ..enclave.alerts.store import AlertStore


class Broadcaster:
    """Thread-safe hand-off from the engine thread to the asyncio WebSocket loop."""

    def __init__(self, maxsize: int = 10000):
        self.q: queue.Queue = queue.Queue(maxsize=maxsize)

    def publish(self, kind: str, body: dict) -> None:
        if kind == "trust_point":
            kind = "assurance_status"
        try:
            self.q.put_nowait({"type": kind, "data": body})
        except queue.Full:
            pass


@dataclass
class Runtime:
    cfg: dict
    store: AlertStore
    broadcaster: Broadcaster = field(default_factory=Broadcaster)
    engine: object = None      # Engine
    pipeline: object = None    # StreamPipeline
    sender: object = None      # TrafficSender (simulated production side)
    monitor: object = None     # AssuranceMonitor
    mode: str = "api-only"
    started_at: float = field(default_factory=time.time)

    @classmethod
    def api_only(cls) -> "Runtime":
        cfg = get_config()
        return cls(cfg=cfg, store=AlertStore(resolve(cfg["storage"]["sqlite_path"])))

    def stats(self) -> dict:
        s = {"mode": self.mode, "uptime_s": round(time.time() - self.started_at, 1),
             "alerts": self.store.counts(), "config_hash": config_hash(self.cfg),
             "target_flows_per_s": self.cfg["throughput"]["target_flows_per_s"]}
        if self.pipeline is not None and self.engine is not None:
            e, p = self.engine, self.pipeline
            lat = sorted(e.proc_latency_ms)
            alat = sorted(e.alert_latency_ms)
            s.update({
                "records_processed": e.records,
                "flows_per_s": round(p.flows_per_s(), 1),
                "queue_depth": p.q.qsize(),
                "queue_dropped": p.dropped,
                "malformed": p.parse_stats.malformed,
                "p95_latency_ms": round(lat[int(0.95 * (len(lat) - 1))], 1) if lat else None,
                "p95_alert_latency_ms": round(alat[int(0.95 * (len(alat) - 1))], 1) if alat else None,
                "rows_scored": dict(e.rows),
                "gate_suppressed": dict(e.gate_suppressed),
                "dedup_suppressed": e.dedup.suppressed,
                "event_time": e.max_ts if e.max_ts > float("-inf") else None,
                "top_talkers": e.top_talkers,
            })
        if self.sender is not None:
            s["replay"] = self.sender.status()
        return s
