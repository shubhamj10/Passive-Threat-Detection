from __future__ import annotations

from ..features.common import FeatureRow
from .base import Candidate, Detector


class BeaconDetector(Detector):
    name = "beacon_scorer"
    cfg_key = "beacon"
    MITRE = {"botnet_c2_beaconing": "T1071"}
    ACTIONS = {"botnet_c2_beaconing": "Analyst review: investigate source host"}

    def thresholds(self) -> dict:
        d = self.dcfg
        return {"alert_threshold": d["alert_threshold"], "min_events": d["min_events"],
                "min_span_s": d["min_span_s"]}

    @staticmethod
    def classify(features, thresholds):
        return "botnet_c2_beaconing", None

    @staticmethod
    def gates(threat_class, features, context, thresholds):
        checks = {
            "min_evidence": features["events"] >= thresholds["min_events"],
            "persistence": features["span_s"] >= thresholds["min_span_s"],
            "not_allowlisted": not context.get("allowlisted", False),
        }
        return [k for k, v in checks.items() if v], [k for k, v in checks.items() if not v]

    def process(self, rows: list[FeatureRow]) -> list[Candidate]:
        th = self.thresholds()
        out = []
        for row, raw, conf in self._scored(rows):
            if conf < th["alert_threshold"]:
                continue
            c = row.context
            ctx = dict(c, allowlisted=c["dst_ip"] in self.allow_dst)
            tclass, _ = self.classify(row.features, th)
            ok, bad = self.gates(tclass, row.features, ctx, th)
            ent = f"{c['src_ip']}->{c['dst_ip']}:{c['dst_port']}"
            out.append(Candidate(self.name, tclass, row, raw, conf, ent, th, ctx, ok, bad))
        return out
