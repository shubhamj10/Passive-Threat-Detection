"""Suppress repeat alerts for the same entity within a cooldown (event time)."""
from __future__ import annotations

from ..detectors.base import Candidate


class Deduper:
    def __init__(self, cfg: dict):
        d = cfg["detection"]
        self.cooldown = {"ddos_scorer": d["ddos"]["cooldown_s"], "beacon_scorer": d["beacon"]["cooldown_s"],
                         "dns_scorer": d["dns"]["cooldown_s"]}
        self.last: dict[tuple, float] = {}
        self.suppressed = 0

    def is_duplicate(self, c: Candidate) -> bool:
        key = (c.threat_class, c.entity)
        t = c.row.window_end
        prev = self.last.get(key)
        if prev is not None and t - prev < self.cooldown[c.detector]:
            self.suppressed += 1
            return True
        self.last[key] = t
        return False
