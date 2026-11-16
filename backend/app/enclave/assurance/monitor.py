"""Assurance monitor: runs inside the enclave, watches the detectors, never connects out."""
from __future__ import annotations

from collections import deque
from typing import Callable

from ..alerts.builder import iso
from .assurance_alerts import AssuranceAlertManager
from .drift import DriftTracker
from .trust import combine, drift_component, feedback_component, volume_component


class AssuranceMonitor:
    def __init__(self, cfg: dict, detectors: dict, feedback_fn: Callable[[str], tuple[int, int]] | None = None,
                 start_seq: int = 0):
        self.cfg = cfg["assurance"]
        self.detectors = detectors
        self.feedback_fn = feedback_fn
        self.drift = {n: DriftTracker(d.bundle["baseline"], d.feature_names, float(self.cfg["drift_window_s"]),
                                      int(self.cfg["drift_min_samples"])) for n, d in detectors.items()}
        self.alert_times: dict[str, deque] = {n: deque() for n in detectors}
        self.manager = AssuranceAlertManager(cfg, start_seq)
        self.first_ts: float | None = None
        self.last_check: float | None = None
        self.status: dict[str, dict] = {n: self._empty(n) for n in detectors}
        self.history: dict[str, deque] = {n: deque(maxlen=240) for n in detectors}

    def _empty(self, n: str) -> dict:
        return {"detector": n, "version": self.detectors[n].version, "trust_score": None,
                "status": "insufficient_data", "signals": {}, "components": {}, "event_time": None}

    # ---- inputs from the engine -----------------------------------------
    def observe_row(self, detector: str, vec, ts: float) -> None:
        self.drift[detector].add(vec, ts)

    def observe_alert(self, detector: str, event_ts: float) -> None:
        self.alert_times[detector].append(event_ts)

    def score(self, detector: str) -> int | None:
        return self.status[detector]["trust_score"]

    # ---- periodic check ----------------------------------------------------
    def tick(self, event_ts: float, force: bool = False) -> list[tuple[str, dict]]:
        if self.first_ts is None:
            self.first_ts = event_ts
            self.last_check = event_ts
            return []
        if not force and event_ts - self.last_check < float(self.cfg["check_interval_s"]):
            return []
        self.last_check = event_ts
        events = []
        for name in self.detectors:
            events += self._check(name, event_ts)
        return events

    def _check(self, name: str, now: float) -> list[tuple[str, dict]]:
        c = self.cfg
        det = self.detectors[name]
        signals: dict = {}
        comps: dict = {"drift": None, "volume": None, "feedback_fp": None}

        d = self.drift[name].compute(now)
        if d is not None:
            signals["feature_drift_psi"] = round(d["psi"], 3)
            signals["top_drift_features"] = d["top"]
            comps["drift"] = drift_component(d["psi"], float(c["drift_psi_warn"]))
        else:
            signals["feature_drift_psi"] = None

        elapsed = now - self.first_ts
        if elapsed >= float(c["volume_min_elapsed_s"]):
            win = min(float(c["volume_window_s"]), elapsed)
            times = self.alert_times[name]
            while times and times[0] < now - float(c["volume_window_s"]):
                times.popleft()
            observed = sum(1 for t in times if t >= now - win)
            rate = float(det.bundle.get("baseline_alert_rate_per_min", 0.0)) / 60.0
            expected = rate * win
            ratio = observed / max(expected, 1.0)
            signals.update(alert_volume_ratio=round(ratio, 2), observed_alerts=observed,
                           expected_alerts=round(expected, 2))
            comps["volume"] = volume_component(ratio, c["alert_volume_band"], expected)
        else:
            signals["alert_volume_ratio"] = None

        n_fb, n_fp = self.feedback_fn(name) if self.feedback_fn else (0, 0)
        signals["feedback_count"] = n_fb
        if n_fb >= int(c["min_feedback"]):
            rate = n_fp / n_fb
            signals["feedback_fp_rate"] = round(rate, 2)
            comps["feedback_fp"] = feedback_component(rate)
        else:
            signals["feedback_fp_rate"] = None

        score = combine(comps, c["trust_weights"])
        prev = self.status[name]["trust_score"]
        status = "insufficient_data" if score is None else ("warning" if score < int(c["trust_alert_below"]) else "ok")
        self.status[name] = {"detector": name, "version": det.version, "trust_score": score, "status": status,
                             "signals": signals,
                             "components": {k: (None if v is None else round(v, 3)) for k, v in comps.items()},
                             "event_time": iso(now, ms=False)}
        self.history[name].append({"t": iso(now, ms=False), "score": score})
        out_signals = {k: signals.get(k) for k in ("feature_drift_psi", "alert_volume_ratio", "feedback_fp_rate")}
        out_signals["top_drift_features"] = signals.get("top_drift_features")
        return [("trust_point", dict(self.status[name]))] + \
            self.manager.evaluate(name, det.version, score, prev, out_signals, now)

    def snapshot(self) -> dict:
        return {n: dict(s, history=list(self.history[n])) for n, s in self.status.items()}
