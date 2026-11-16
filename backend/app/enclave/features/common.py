"""Shared feature helpers (pure functions, no I/O)."""
from __future__ import annotations

import ipaddress
import math
from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Iterable


@dataclass
class FeatureRow:
    """One candidate produced by a windowed feature extractor."""
    detector: str
    key: tuple
    window_start: float
    window_end: float
    features: dict
    context: dict = field(default_factory=dict)
    closed_by_recv_wall: float = 0.0   # wall time the record that closed the window arrived


def entropy_from_counts(counts: Iterable[int]) -> float:
    counts = [c for c in counts if c > 0]
    total = sum(counts)
    if total <= 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts)


def char_entropy(s: str) -> float:
    if not s:
        return 0.0
    return entropy_from_counts(Counter(s).values())


def mean(xs) -> float:
    xs = list(xs)
    return sum(xs) / len(xs) if xs else 0.0


def std(xs) -> float:
    xs = list(xs)
    if len(xs) < 2:
        return 0.0
    m = mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / len(xs))


def cv(xs) -> float:
    m = mean(xs)
    return std(xs) / m if m > 0 else 0.0


def median(xs) -> float:
    s = sorted(xs)
    n = len(s)
    if n == 0:
        return 0.0
    return s[n // 2] if n % 2 else 0.5 * (s[n // 2 - 1] + s[n // 2])


class SubnetMatcher:
    def __init__(self, cidrs: list[str]):
        self._nets = [ipaddress.ip_network(c, strict=False) for c in cidrs]
        self.is_internal = lru_cache(maxsize=65536)(self._is_internal)

    def _is_internal(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self._nets)


def split_domain(qname: str) -> tuple[str, str, str]:
    """Return (base_domain, sld, subdomain) using the last two labels as the base.

    Simple rule: good enough for the synthetic data. For real traffic use a
    public-suffix list (documented in docs/limitations.md).
    """
    labels = [l for l in qname.split(".") if l]
    if len(labels) == 0:
        return "", "", ""
    if len(labels) == 1:
        return labels[0], labels[0], ""
    base = ".".join(labels[-2:])
    sld = labels[-2]
    sub = ".".join(labels[:-2])
    return base, sld, sub
