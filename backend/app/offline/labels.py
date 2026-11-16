"""Ground-truth matching: map feature rows / alerts to injected attack episodes."""
from __future__ import annotations

from collections import defaultdict

from ..generator.scenario import THREAT_OF


class EpisodeIndex:
    def __init__(self, episodes: list[dict]):
        self.episodes = episodes
        self.ddos = defaultdict(list)
        self.beacon = defaultdict(list)
        self.dga = defaultdict(list)
        self.tunnel = defaultdict(list)
        for e in episodes:
            ent = e["entity"]
            if e["class"].startswith("ddos"):
                self.ddos[ent["dst_ip"]].append(e)
            elif e["class"] == "beacon":
                self.beacon[(ent["src_ip"], ent["dst_ip"], ent["dst_port"])].append(e)
            elif e["class"] == "dga":
                self.dga[ent["src_ip"]].append(e)
            elif e["class"] == "dns_tunnel":
                self.tunnel[(ent["src_ip"], ent["base_domain"])].append(e)

    @staticmethod
    def _overlap(e, start, end, slack=0.0) -> bool:
        return start < e["end"] + slack and end > e["start"]

    def match_row(self, detector: str, row) -> dict | None:
        c, s, t = row.context, row.window_start, row.window_end
        if detector == "ddos_scorer":
            cands = self.ddos.get(c["dst_ip"], [])
        elif detector == "beacon_scorer":
            cands = self.beacon.get((c["src_ip"], c["dst_ip"], c["dst_port"]), [])
        else:
            cands = [e for e in self.dga.get(c["src_ip"], []) if c["base_domain"] in set(e["entity"]["domains"])]
            cands += self.tunnel.get((c["src_ip"], c["base_domain"]), [])
        for e in cands:
            if self._overlap(e, s, t):
                return e
        return None

    SLACK = {"ddos": 30.0, "botnet_c2_beaconing": 900.0, "dga_domain": 120.0, "dns_tunnelling": 120.0}

    def match_alert(self, alert: dict, slack: float | None = None) -> dict | None:
        """Find the episode an alert belongs to (same threat class + entity + time)."""
        from datetime import datetime
        ctx = alert["evidence"]["context"]
        end = datetime.fromisoformat(alert["trace"]["data_window"]["end"].replace("Z", "+00:00")).timestamp()
        start = datetime.fromisoformat(alert["trace"]["data_window"]["start"].replace("Z", "+00:00")).timestamp()
        tc = alert["threat_class"]
        slack = self.SLACK.get(tc, 60.0) if slack is None else slack
        if tc == "ddos":
            cands = self.ddos.get(ctx["dst_ip"], [])
        elif tc == "botnet_c2_beaconing":
            cands = self.beacon.get((ctx["src_ip"], ctx["dst_ip"], ctx["dst_port"]), [])
        elif tc == "dga_domain":
            cands = self.dga.get(ctx["src_ip"], [])
        else:
            cands = self.tunnel.get((ctx["src_ip"], ctx["base_domain"]), [])
        for e in cands:
            if THREAT_OF.get(e["class"]) == tc and self._overlap(e, start, end, slack):
                return e
        return None
