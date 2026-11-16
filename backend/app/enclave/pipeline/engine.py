"""Streaming detection engine: event-time windows -> detectors -> gates -> alerts.

Used identically online (fed by the diode receiver) and offline (evaluation,
tests, benchmark). It never sees ground-truth labels: records are FlowRecords.
"""
from __future__ import annotations

import time
from collections import Counter, deque
from pathlib import Path
from typing import Callable

from ...config import MODELS_DIR, config_hash
from ..alerts.builder import IdGen, build_alert
from ..alerts.dedup import Deduper
from ..alerts.schema import Alert, AssuranceAlert
from ..alerts.store import AlertStore
from ..assurance.monitor import AssuranceMonitor
from ..detectors.base import Detector
from ..features.beacon import BeaconExtractor
from ..features.common import FeatureRow, SubnetMatcher
from ..features.ddos import DdosExtractor
from ..features.dns import BigramModel, DnsExtractor
from ..ingest.record import FlowRecord

EventFn = Callable[[str, dict], None]


def load_bigram(models_dir: Path | None = None) -> BigramModel:
    p = (models_dir or MODELS_DIR) / "dns_bigrams.json"
    if not p.exists():
        raise FileNotFoundError(f"{p} missing: run scripts/train.py")
    return BigramModel.load(p)


def make_extractors(cfg: dict, bigram: BigramModel) -> dict:
    subnets = SubnetMatcher(cfg["network"]["internal_subnets"])
    return {"ddos_scorer": DdosExtractor(cfg, subnets),
            "beacon_scorer": BeaconExtractor(cfg, subnets),
            "dns_scorer": DnsExtractor(cfg, subnets, bigram)}


class Engine:
    def __init__(self, cfg: dict, detectors: dict[str, Detector], bigram: BigramModel, *,
                 store: AlertStore | None = None, monitor: AssuranceMonitor | None = None,
                 on_event: EventFn | None = None, collect: bool = True):
        self.cfg = cfg
        self.detectors = detectors
        self.extractors = make_extractors(cfg, bigram)
        self.lateness = float(cfg["detection"]["watermark_lateness_s"])
        self.store, self.monitor, self.on_event, self.collect = store, monitor, on_event, collect
        self.ids = IdGen("a", store.max_seq() if store else 0)
        self.dedup = Deduper(cfg)
        self.cfg_hash = config_hash(cfg)
        self.max_ts = float("-inf")
        self.first_ts: float | None = None
        self._next_adv = float("-inf")
        self.alerts: list[dict] = []
        self.assurance_events: list[tuple[str, dict]] = []
        # stats
        self.records = 0
        self.rows = Counter()
        self.gate_suppressed = Counter()
        self.proc_latency_ms: deque = deque(maxlen=5000)
        self.alert_latency_ms: deque = deque(maxlen=1000)
        self._talk_minute: float | None = None
        self._talk_src: Counter = Counter()
        self._talk_dst: Counter = Counter()
        self.top_talkers: dict = {"sources": [], "destinations": []}

    # ---- main entry ------------------------------------------------------
    def process(self, r: FlowRecord) -> None:
        self.records += 1
        if self.first_ts is None:
            self.first_ts = r.ts
        if r.ts > self.max_ts:
            self.max_ts = r.ts
        for ex in self.extractors.values():
            ex.add(r)
        self._talkers(r)
        wm = self.max_ts - self.lateness
        if wm >= self._next_adv:
            self._next_adv = wm + 1.0
            for name, ex in self.extractors.items():
                rows = ex.advance(wm, r.recv_wall)
                if rows:
                    self._handle(name, rows)
            if self.monitor:
                self._assurance(self.monitor.tick(wm))
        if r.recv_wall and (self.records & 7) == 0:
            self.proc_latency_ms.append((time.time() - r.recv_wall) * 1000.0)

    def flush(self) -> None:
        for name, ex in self.extractors.items():
            rows = ex.flush()
            if rows:
                self._handle(name, rows)
        if self.monitor and self.max_ts > float("-inf"):
            self._assurance(self.monitor.tick(self.max_ts, force=True))

    # ---- internals -------------------------------------------------------
    def _handle(self, name: str, rows: list[FeatureRow]) -> None:
        det = self.detectors[name]
        self.rows[name] += len(rows)
        candidates = det.process(rows)
        if self.monitor:
            # drift is measured on traffic the model judged NORMAL (attacks are not drift);
            # warm-up windows that started before the stream did are skipped (partial data)
            for row, vec in det.last_normal:
                if row.window_start >= self.first_ts:
                    self.monitor.observe_row(name, vec, row.window_end)
        for c in candidates:
            if not c.passed:
                self.gate_suppressed[name] += 1
                continue
            if self.dedup.is_duplicate(c):
                continue
            trust = self.monitor.score(name) if self.monitor else None
            alert = build_alert(c, det, self.ids, self.cfg_hash, trust, self.cfg)
            Alert(**alert)  # schema validation
            if self.store:
                self.store.add_alert(alert)
            if self.monitor:
                self.monitor.observe_alert(name, c.row.window_end)
            if self.collect:
                self.alerts.append(alert)
            if c.row.closed_by_recv_wall:
                self.alert_latency_ms.append((time.time() - c.row.closed_by_recv_wall) * 1000.0)
            if self.on_event:
                self.on_event("threat_alert", alert)

    def _assurance(self, events: list[tuple[str, dict]]) -> None:
        for kind, body in events:
            if kind == "trust_point":
                if self.store:
                    self.store.add_trust_point(self.max_ts, body["detector"], body["trust_score"], body)
            else:
                AssuranceAlert(**body)
                if self.store:
                    self.store.add_assurance_alert(body)
                self.assurance_events.append((kind, body))
            if self.on_event:
                self.on_event(kind, body)

    def _talkers(self, r: FlowRecord) -> None:
        minute = r.ts // 60
        if self._talk_minute is None:
            self._talk_minute = minute
        if minute > self._talk_minute:
            self.top_talkers = {
                "sources": [{"ip": ip, "bytes": b} for ip, b in self._talk_src.most_common(8)],
                "destinations": [{"ip": ip, "bytes": b} for ip, b in self._talk_dst.most_common(8)],
            }
            self._talk_src, self._talk_dst = Counter(), Counter()
            self._talk_minute = minute
        self._talk_src[r.src_ip] += r.bytes
        self._talk_dst[r.dst_ip] += r.bytes
