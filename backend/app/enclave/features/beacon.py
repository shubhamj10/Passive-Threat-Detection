"""Beaconing features: per (internal src, external dst, port) over a sliding window."""
from __future__ import annotations

import math
from collections import deque

from ..ingest.record import FlowRecord
from .common import FeatureRow, SubnetMatcher, cv, mean, median

BEACON_FEATURES = [
    "events", "interval_mean", "interval_cv", "interval_mad_ratio", "periodicity",
    "size_mean", "size_cv", "span_s", "pkts_mean",
]


def beacon_features(times: list[float], sizes: list[int], pkts: list[int]) -> dict:
    t = sorted(times)
    iv = [b - a for a, b in zip(t, t[1:])]
    med = median(iv)
    mad = median([abs(x - med) for x in iv]) if iv else 0.0
    periodic = (sum(1 for x in iv if med > 0 and abs(x - med) <= 0.1 * med) / len(iv)) if iv else 0.0
    return {
        "events": float(len(t)),
        "interval_mean": mean(iv),
        "interval_cv": cv(iv) if iv else 0.0,
        "interval_mad_ratio": mad / med if med > 0 else 1.0,
        "periodicity": periodic,
        "size_mean": mean(sizes),
        "size_cv": cv(sizes),
        "span_s": (t[-1] - t[0]) if t else 0.0,
        "pkts_mean": mean(pkts),
    }


class BeaconExtractor:
    name = "beacon_scorer"

    def __init__(self, cfg: dict, subnets: SubnetMatcher):
        b = cfg["detection"]["beacon"]
        self.window_s = float(b["window_s"])
        self.hop_s = float(b["hop_s"])
        self.min_events = int(b["min_events"])
        self.subnets = subnets
        self.pairs: dict[tuple, deque] = {}
        self.next_hop: float | None = None

    def add(self, r: FlowRecord) -> None:
        if r.is_dns or r.dst_port == 53:
            return
        if not self.subnets.is_internal(r.src_ip) or self.subnets.is_internal(r.dst_ip):
            return
        key = (r.src_ip, r.dst_ip, r.dst_port, r.proto)
        dq = self.pairs.get(key)
        if dq is None:
            dq = self.pairs[key] = deque()
        dq.append((r.ts, r.bytes, r.packets, r.src_port))
        if self.next_hop is None:
            self.next_hop = math.floor(r.ts / self.hop_s) * self.hop_s + self.hop_s

    def advance(self, watermark: float, recv_wall: float = 0.0) -> list[FeatureRow]:
        rows: list[FeatureRow] = []
        while self.next_hop is not None and self.next_hop <= watermark:
            hop_end = self.next_hop
            start = hop_end - self.window_s
            for key in list(self.pairs):
                dq = self.pairs[key]
                while dq and dq[0][0] < start:
                    dq.popleft()
                if not dq:
                    del self.pairs[key]
                    continue
                ev = [e for e in dq if e[0] < hop_end]
                if len(ev) < self.min_events:
                    continue
                times = [e[0] for e in ev]
                rows.append(FeatureRow(
                    detector=self.name, key=key, window_start=start, window_end=hop_end,
                    features=beacon_features(times, [e[1] for e in ev], [e[2] for e in ev]),
                    context={"src_ip": key[0], "dst_ip": key[1], "dst_port": key[2], "proto": key[3],
                             "last_src_port": ev[-1][3], "first_ts": times[0], "last_ts": times[-1]},
                    closed_by_recv_wall=recv_wall))
            self.next_hop = hop_end + self.hop_s
        return rows

    def flush(self) -> list[FeatureRow]:
        """Evaluate the hops that cover the tail of the data (end of a replay)."""
        if self.next_hop is None or not self.pairs:
            return []
        last = max(dq[-1][0] for dq in self.pairs.values() if dq)
        return self.advance(math.floor(last / self.hop_s) * self.hop_s + self.hop_s)
