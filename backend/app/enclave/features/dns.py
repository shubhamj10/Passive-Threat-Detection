"""DNS features: per (internal src, base domain) per tumbling window, from query names only."""
from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from pathlib import Path

from ..ingest.record import FlowRecord
from .common import FeatureRow, SubnetMatcher, char_entropy, mean, split_domain

DNS_FEATURES = [
    "n_queries", "n_unique", "unique_ratio", "mean_qname_len", "max_label_len", "sld_len",
    "sld_entropy", "sub_entropy", "sld_bigram_ll", "digit_ratio", "nx_ratio", "txt_ratio",
]

_ALPH = "abcdefghijklmnopqrstuvwxyz0123456789-"


class BigramModel:
    """Character-bigram log-likelihood of a domain label under benign names.

    Built ONLY from the benign domain list (never from labelled traffic).
    """

    def __init__(self, logp: dict[str, float] | None = None, floor: float = -12.0):
        self.logp = logp or {}
        self.floor = floor

    @classmethod
    def fit(cls, labels: list[str]) -> "BigramModel":
        counts: Counter = Counter()
        firsts: Counter = Counter()
        for lab in labels:
            s = "^" + lab.lower() + "$"
            for a, b in zip(s, s[1:]):
                counts[a + b] += 1
                firsts[a] += 1
        sym = list("^$" + _ALPH)
        V = len(sym)
        logp = {}
        for a in sym:
            tot = firsts.get(a, 0)
            for b in sym:
                logp[a + b] = math.log((counts.get(a + b, 0) + 1) / (tot + V))
        return cls(logp)

    def score(self, label: str) -> float:
        if not label:
            return 0.0
        s = "^" + label.lower() + "$"
        vals = [self.logp.get(a + b, self.floor) for a, b in zip(s, s[1:])]
        return sum(vals) / len(vals)

    def save(self, path: Path) -> None:
        path.write_text(json.dumps({"logp": self.logp, "floor": self.floor}), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "BigramModel":
        d = json.loads(path.read_text(encoding="utf-8"))
        return cls(d["logp"], d.get("floor", -12.0))


def dns_features(qs: list[tuple[str, str, str]], bigram: BigramModel) -> dict:
    """qs: list of (qname, qtype, rcode)."""
    names = [q[0] for q in qs]
    uniq = set(names)
    parts = [split_domain(n) for n in uniq]
    labels = [l for n in uniq for l in n.split(".") if l]
    joined = "".join(n.replace(".", "") for n in names)
    n = len(names)
    return {
        "n_queries": float(n),
        "n_unique": float(len(uniq)),
        "unique_ratio": len(uniq) / n if n else 0.0,
        "mean_qname_len": mean(len(x) for x in names),
        "max_label_len": float(max((len(l) for l in labels), default=0)),
        "sld_len": mean(len(p[1]) for p in parts),
        "sld_entropy": mean(char_entropy(p[1]) for p in parts),
        "sub_entropy": mean(char_entropy(p[2].replace(".", "")) for p in parts),
        "sld_bigram_ll": mean(bigram.score(p[1]) for p in parts),
        "digit_ratio": (sum(c.isdigit() for c in joined) / len(joined)) if joined else 0.0,
        "nx_ratio": sum(1 for q in qs if q[2] == "NXDOMAIN") / n if n else 0.0,
        "txt_ratio": sum(1 for q in qs if q[1] in ("TXT", "NULL")) / n if n else 0.0,
    }


class DnsExtractor:
    name = "dns_scorer"

    def __init__(self, cfg: dict, subnets: SubnetMatcher, bigram: BigramModel):
        d = cfg["detection"]["dns"]
        self.window_s = float(d["window_s"])
        self.subnets = subnets
        self.bigram = bigram
        self.windows: dict[float, dict[tuple, list]] = defaultdict(lambda: defaultdict(list))
        self.resolver: dict[tuple, str] = {}
        self._closed_upto = float("-inf")
        self.late_dropped = 0

    def add(self, r: FlowRecord) -> None:
        if not r.is_dns or not self.subnets.is_internal(r.src_ip):
            return
        ws = (r.ts // self.window_s) * self.window_s
        if ws + self.window_s <= self._closed_upto:
            self.late_dropped += 1
            return
        base, _, _ = split_domain(r.dns_query)
        key = (r.src_ip, base)
        self.windows[ws][key].append((r.dns_query, r.dns_qtype or "A", r.dns_rcode or "NOERROR"))
        self.resolver[key] = r.dst_ip

    def advance(self, watermark: float, recv_wall: float = 0.0) -> list[FeatureRow]:
        rows: list[FeatureRow] = []
        for ws in sorted(w for w in self.windows if w + self.window_s <= watermark):
            for key, qs in self.windows.pop(ws).items():
                uniq = sorted(set(q[0] for q in qs))
                rows.append(FeatureRow(
                    detector=self.name, key=key, window_start=ws, window_end=ws + self.window_s,
                    features=dns_features(qs, self.bigram),
                    context={"src_ip": key[0], "base_domain": key[1],
                             "resolver": self.resolver.get(key, ""), "sample_names": uniq[:3]},
                    closed_by_recv_wall=recv_wall))
            self._closed_upto = max(self._closed_upto, ws + self.window_s)
        return rows

    def flush(self) -> list[FeatureRow]:
        return self.advance(float("inf"))
