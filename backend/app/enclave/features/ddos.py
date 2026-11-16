"""DDoS features: per internal destination, per tumbling window."""
from __future__ import annotations

from collections import Counter, defaultdict

from ..ingest.record import FlowRecord
from .common import FeatureRow, SubnetMatcher, entropy_from_counts

DDOS_FEATURES = [
    "flows", "pkts_per_s", "bytes_per_pkt", "unique_src", "src_entropy",
    "syn_only_ratio", "udp_ratio", "reflection_ratio", "unique_dst_ports", "flows_per_src",
]


class _DstAcc:
    __slots__ = ("flows", "packets", "bytes", "srcs", "syn_only", "udp", "refl", "dports", "protos")

    def __init__(self):
        self.flows = self.packets = self.bytes = self.syn_only = self.udp = self.refl = 0
        self.srcs: Counter = Counter()
        self.dports: Counter = Counter()
        self.protos: Counter = Counter()


def ddos_features(acc: _DstAcc, window_s: float) -> dict:
    n_src = len(acc.srcs)
    return {
        "flows": float(acc.flows),
        "pkts_per_s": acc.packets / window_s,
        "bytes_per_pkt": acc.bytes / acc.packets if acc.packets else 0.0,
        "unique_src": float(n_src),
        "src_entropy": entropy_from_counts(acc.srcs.values()),
        "syn_only_ratio": acc.syn_only / acc.flows if acc.flows else 0.0,
        "udp_ratio": acc.udp / acc.flows if acc.flows else 0.0,
        "reflection_ratio": acc.refl / acc.udp if acc.udp else 0.0,
        "unique_dst_ports": float(len(acc.dports)),
        "flows_per_src": acc.flows / n_src if n_src else 0.0,
    }


class DdosExtractor:
    name = "ddos_scorer"

    def __init__(self, cfg: dict, subnets: SubnetMatcher):
        d = cfg["detection"]["ddos"]
        self.window_s = float(d["window_s"])
        self.min_flows = int(d["candidate_min_flows"])
        self.refl_ports = set(d["reflection_ports"])
        self.lateness = float(cfg["detection"]["watermark_lateness_s"])
        self.subnets = subnets
        self.windows: dict[float, dict[str, _DstAcc]] = defaultdict(dict)
        self.late_dropped = 0
        self._closed_upto = float("-inf")

    def add(self, r: FlowRecord) -> None:
        if not self.subnets.is_internal(r.dst_ip):
            return
        ws = (r.ts // self.window_s) * self.window_s
        if ws + self.window_s <= self._closed_upto:
            self.late_dropped += 1
            return
        win = self.windows[ws]
        acc = win.get(r.dst_ip)
        if acc is None:
            acc = win[r.dst_ip] = _DstAcc()
        acc.flows += 1
        acc.packets += r.packets
        acc.bytes += r.bytes
        acc.srcs[r.src_ip] += 1
        acc.dports[r.dst_port] += 1
        acc.protos[r.proto] += 1
        if r.proto == "TCP" and "S" in r.flags and "A" not in r.flags:
            acc.syn_only += 1
        if r.proto == "UDP":
            acc.udp += 1
            if r.src_port in self.refl_ports:
                acc.refl += 1

    def advance(self, watermark: float, recv_wall: float = 0.0) -> list[FeatureRow]:
        rows: list[FeatureRow] = []
        for ws in sorted(w for w in self.windows if w + self.window_s <= watermark):
            for dst, acc in self.windows.pop(ws).items():
                if acc.flows < self.min_flows:
                    continue
                port, _ = acc.dports.most_common(1)[0]
                proto, _ = acc.protos.most_common(1)[0]
                rows.append(FeatureRow(
                    detector=self.name, key=(dst,), window_start=ws, window_end=ws + self.window_s,
                    features=ddos_features(acc, self.window_s),
                    context={"dst_ip": dst, "dst_port": int(port), "proto": proto,
                             "top_sources": [s for s, _ in acc.srcs.most_common(5)]},
                    closed_by_recv_wall=recv_wall))
            self._closed_upto = max(self._closed_upto, ws + self.window_s)
        return rows

    def flush(self) -> list[FeatureRow]:
        return self.advance(float("inf"))
