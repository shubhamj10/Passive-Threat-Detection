from __future__ import annotations

from ..features.common import FeatureRow
from .base import Candidate, Detector


class DdosDetector(Detector):
    name = "ddos_scorer"
    cfg_key = "ddos"
    MITRE = {"ddos": "T1498", "syn_flood": "T1498.001", "volumetric_flood": "T1498.001",
             "udp_reflection": "T1498.002"}
    ACTIONS = {"ddos": "Notify network operations; consider upstream scrubbing (decided by humans)",
               "udp_reflection": "Notify network operations; check exposure to reflection ports upstream"}

    def __init__(self, bundle, cfg):
        super().__init__(bundle, cfg)
        self._streak: dict[str, tuple[int, float]] = {}

    def thresholds(self) -> dict:
        d = self.dcfg
        return {"alert_threshold": d["alert_threshold"], "min_flows": d["min_flows"],
                "persistence_windows": d["persistence_windows"]}

    @staticmethod
    def classify(features, thresholds):
        if features["syn_only_ratio"] >= 0.5:
            return "ddos", "syn_flood"
        if features["udp_ratio"] >= 0.5 and features["reflection_ratio"] >= 0.5:
            return "ddos", "udp_reflection"
        return "ddos", "volumetric_flood"

    @staticmethod
    def gates(threat_class, features, context, thresholds):
        checks = {
            "min_evidence": features["flows"] >= thresholds["min_flows"],
            "persistence": context.get("consecutive_windows", 0) >= thresholds["persistence_windows"],
            "not_allowlisted": not context.get("allowlisted", False),
        }
        return [k for k, v in checks.items() if v], [k for k, v in checks.items() if not v]

    def process(self, rows: list[FeatureRow]) -> list[Candidate]:
        th = self.thresholds()
        out = []
        for row, raw, conf in self._scored(rows):
            dst = row.context["dst_ip"]
            n, last_end = self._streak.get(dst, (0, None))
            suspicious = conf >= th["alert_threshold"]
            contiguous = last_end is not None and abs(last_end - row.window_start) < 1e-6
            n = (n + 1 if contiguous else 1) if suspicious else 0
            self._streak[dst] = (n, row.window_end)
            if not suspicious:
                continue
            ctx = dict(row.context, consecutive_windows=n, allowlisted=dst in self.allow_dst)
            tclass, sub = self.classify(row.features, th)
            ctx["attack_subtype"] = sub
            ok, bad = self.gates(tclass, row.features, ctx, th)
            out.append(Candidate(self.name, tclass, row, raw, conf, dst, th, ctx, ok, bad))
        return out
