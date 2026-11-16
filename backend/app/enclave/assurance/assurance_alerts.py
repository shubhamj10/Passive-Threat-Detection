"""Assurance alerts: 'one of the AI models may no longer be reliable'.

At most one OPEN assurance alert per detector (hysteresis between the raise and
recover thresholds), so a falling score never produces duplicates.
"""
from __future__ import annotations

import copy

from ..alerts.builder import IdGen, iso


class AssuranceAlertManager:
    def __init__(self, cfg: dict, start_seq: int = 0):
        a = cfg["assurance"]
        self.below = int(a["trust_alert_below"])
        self.recover = int(a.get("trust_recover_above", self.below + 5))
        self.ids = IdGen("aa", start_seq)
        self.open: dict[str, dict] = {}

    def evaluate(self, detector: str, version: str, score: int | None, previous: int | None,
                 signals: dict, event_ts: float) -> list[tuple[str, dict]]:
        events: list[tuple[str, dict]] = []
        if score is None:
            return events
        if detector not in self.open and score < self.below:
            alert = {
                "assurance_alert_id": self.ids.next(event_ts),
                "timestamp": iso(event_ts, ms=False),
                "detector": {"name": detector, "version": version},
                "trust_score": {"previous": previous, "current": score, "threshold": self.below},
                "signals": signals,
                "recommended_action": (f"Review, retune or retrain {detector}. Treat its alerts with extra caution "
                                       f"and use manual review until resolved."),
                "status": "open",
                "resolved_at": None,
            }
            self.open[detector] = alert
            events.append(("assurance_alert", copy.deepcopy(alert)))
        elif detector in self.open:
            alert = self.open[detector]
            if score >= self.recover:
                alert = dict(alert, status="resolved", resolved_at=iso(event_ts, ms=False))
                del self.open[detector]
                events.append(("assurance_resolved", alert))
            elif score < alert["trust_score"]["current"]:
                alert["trust_score"]["current"] = score   # same alert, worse score: update, no duplicate
                alert["signals"] = signals
                events.append(("assurance_update", copy.deepcopy(alert)))
        return events
