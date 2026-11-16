from __future__ import annotations

from collections import defaultdict

from ..features.common import FeatureRow
from .base import Candidate, Detector


class DnsDetector(Detector):
    name = "dns_scorer"
    cfg_key = "dns"
    MITRE = {"dga_domain": "T1568.002", "dns_tunnelling": "T1071.004"}
    ACTIONS = {"dga_domain": "Analyst review: likely malware on source host querying generated domains",
               "dns_tunnelling": "Analyst review: possible data exfiltration over DNS from source host"}

    def thresholds(self) -> dict:
        d = self.dcfg
        return {"alert_threshold": d["alert_threshold"], "dga_min_domains": d["dga_min_domains"],
                "tunnel_min_queries": d["tunnel_min_queries"],
                "tunnel_min_label_len": d["tunnel_min_label_len"]}

    @staticmethod
    def classify(features, thresholds):
        if features["max_label_len"] >= thresholds["tunnel_min_label_len"] and features["sub_entropy"] >= 3.0:
            return "dns_tunnelling", None
        return "dga_domain", None

    @staticmethod
    def gates(threat_class, features, context, thresholds):
        if threat_class == "dns_tunnelling":
            checks = {
                "min_evidence": features["n_queries"] >= thresholds["tunnel_min_queries"],
                "persistence": features["n_unique"] >= thresholds["tunnel_min_queries"] / 2,
                "not_allowlisted": not context.get("allowlisted", False),
            }
        else:
            checks = {
                "min_evidence": context.get("flagged_groups", 0) >= thresholds["dga_min_domains"],
                "not_allowlisted": not context.get("allowlisted", False),
            }
        return [k for k, v in checks.items() if v], [k for k, v in checks.items() if not v]

    def process(self, rows: list[FeatureRow]) -> list[Candidate]:
        th = self.thresholds()
        out: list[Candidate] = []
        dga_by_src: dict[str, list] = defaultdict(list)
        for row, raw, conf in self._scored(rows):
            if conf < th["alert_threshold"]:
                continue
            c = row.context
            allow = c["base_domain"] in self.allow_domains
            tclass, _ = self.classify(row.features, th)
            if tclass == "dns_tunnelling":
                ctx = dict(c, allowlisted=allow)
                ok, bad = self.gates(tclass, row.features, ctx, th)
                out.append(Candidate(self.name, tclass, row, raw, conf,
                                     f"{c['src_ip']}->{c['base_domain']}", th, ctx, ok, bad))
            elif not allow:
                dga_by_src[c["src_ip"]].append((row, raw, conf))
        for src, items in dga_by_src.items():
            items.sort(key=lambda t: (-t[2], t[0].context["base_domain"]))
            row, raw, conf = items[0]
            ctx = dict(row.context, flagged_groups=len(items), allowlisted=False,
                       flagged_domains=[i[0].context["base_domain"] for i in items[:5]])
            ok, bad = self.gates("dga_domain", row.features, ctx, th)
            out.append(Candidate(self.name, "dga_domain", row, raw, conf, src, th, ctx, ok, bad))
        return out
