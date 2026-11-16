"""Synthetic traffic generator (the simulated "production side").

Produces metadata-only flow records with ground-truth labels, plus an episodes
list describing each injected attack. Labels exist ONLY for training and
evaluation; the enclave's parser strips them.

Addresses are reserved ranges: 10.0.0.0/8 (internal), 192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24 (external) and 198.18.0.0/15 (spoofed sources).
"""
from __future__ import annotations

import heapq
import json
import math
import random
from dataclasses import dataclass, field
from pathlib import Path

from .names import dga_domain, tunnel_query

BASE_TS = 1792576800.0   # 2026-10-21T10:00:00Z

CLIENTS = [f"10.1.{a}.{b}" for a in (1, 2, 3) for b in range(10, 30)]
WEB_SERVER, VPN_SERVER, MAIL_SERVER = "10.1.0.10", "10.1.0.20", "10.1.0.25"
RESOLVER, NTP = "192.0.2.53", "192.0.2.123"
EXT_SERVERS = [f"198.51.100.{i}" for i in range(10, 40)] + [f"203.0.113.{i}" for i in range(10, 20)]
APP_SERVERS = [f"198.51.100.{i}" for i in range(50, 55)]
CHAT_SERVER = "198.51.100.60"
EXT_CLIENTS = [f"203.0.113.{i}" for i in range(30, 150)] + [f"198.51.100.{i}" for i in range(100, 150)]
REFLECTORS = [f"198.51.100.{i}" for i in range(150, 250)] + [f"203.0.113.{i}" for i in range(150, 200)]
C2_SERVERS = [f"203.0.113.{i}" for i in range(200, 221)]
TELEMETRY = "203.0.113.240"
TUNNEL_BASES = ["sync-relay.example", "cdn-update.test", "telemetry-cache.example"]


def spoofed_ip(rng: random.Random) -> str:
    return f"198.{rng.randint(18, 19)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


@dataclass
class Episode:
    id: str
    cls: str               # ddos_syn_flood | ddos_udp_reflection | ddos_spoofed_flood | beacon | dga | dns_tunnel | benign_flash_crowd
    start: float
    end: float
    params: dict = field(default_factory=dict)
    evasion: bool = False

    def to_json(self) -> dict:
        return {"id": self.id, "class": self.cls, "start": self.start, "end": self.end,
                "evasion": self.evasion, "entity": self.params.get("entity", {})}


THREAT_OF = {"ddos_syn_flood": "ddos", "ddos_udp_reflection": "ddos", "ddos_spoofed_flood": "ddos",
             "beacon": "botnet_c2_beaconing", "dga": "dga_domain", "dns_tunnel": "dns_tunnelling"}


class TrafficGenerator:
    def __init__(self, seed: int, benign_domains: list[str], drift_at: float | None = None):
        self.rng = random.Random(seed)
        self.domains = benign_domains
        self.popular = benign_domains[: max(50, len(benign_domains) // 5)]
        self.drift_at = drift_at
        self.out: list[dict] = []

    # ---- helpers -------------------------------------------------------
    def _rec(self, ts, src, dst, sport, dport, proto, flags="", packets=1, nbytes=0, label="benign",
             attack_id=None, **dns):
        r = {"ts": round(ts, 6), "src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport,
             "proto": proto, "flags": flags, "packets": int(packets), "bytes": int(nbytes), "label": label}
        if attack_id:
            r["attack_id"] = attack_id
        r.update(dns)
        self.out.append(r)

    def _poisson(self, t0, t1, rate):
        t = t0 + self.rng.expovariate(rate)
        while t < t1:
            yield t
            t += self.rng.expovariate(rate)

    def _eph(self):
        return self.rng.randint(32768, 60999)

    # ---- benign background ---------------------------------------------
    def benign(self, t0: float, t1: float) -> None:
        rng = self.rng
        drifted = lambda t: self.drift_at is not None and t >= self.drift_at
        # outbound web sessions (bursty)
        for t in self._poisson(t0, t1, 6.0):
            c, s = rng.choice(CLIENTS), EXT_SERVERS[min(int(rng.paretovariate(1.2)) - 1, len(EXT_SERVERS) - 1)]
            port = 443 if rng.random() < 0.85 else 80
            for _ in range(min(int(rng.expovariate(1 / 3.0)) + 1, 12)):
                pk = max(3, int(rng.lognormvariate(3.0, 0.9)))
                scale = 5.0 if drifted(t) and rng.random() < 0.4 else 1.0   # drift: new video traffic
                self._rec(t, c, s, self._eph(), port, "TCP", "SAF", pk, pk * rng.randint(400, 1400) * scale)
                t += rng.expovariate(1 / 1.5)
        # inbound web to the internal server
        for t in self._poisson(t0, t1, 4.0):
            pk = rng.randint(8, 60)
            self._rec(t, rng.choice(EXT_CLIENTS), WEB_SERVER, self._eph(), 443, "TCP", "SAF", pk, pk * rng.randint(300, 1200))
        # VPN (UDP) and mail
        workers = EXT_CLIENTS[:20]
        for t in self._poisson(t0, t1, 1.0):
            pk = rng.randint(20, 400)
            self._rec(t, rng.choice(workers), VPN_SERVER, 4500, 4500, "UDP", "", pk, pk * rng.randint(200, 1300))
        for t in self._poisson(t0, t1, 0.3):
            pk = rng.randint(6, 40)
            self._rec(t, rng.choice(EXT_CLIENTS), MAIL_SERVER, self._eph(), 25, "TCP", "SAF", pk, pk * rng.randint(200, 1400))
        # DNS lookups
        for t in self._poisson(t0, t1, 5.0):
            d = rng.choice(self.popular) if rng.random() < 0.7 else rng.choice(self.domains)
            if rng.random() < 0.5:
                d = f"{rng.choice(['www', 'api', 'cdn', 'mail', 'static', 'img', 'login', 'm'])}.{d}"
            qtype = rng.choices(["A", "AAAA", "TXT"], [70, 27, 3])[0]
            rcode = "NXDOMAIN" if rng.random() < 0.03 else "NOERROR"
            self._rec(t, rng.choice(CLIENTS), RESOLVER, self._eph(), 53, "UDP", "", 2, rng.randint(80, 400),
                      dns_query=d, dns_qtype=qtype, dns_rcode=rcode)
        # NTP: exactly periodic but benign (allowlisted)
        for c in CLIENTS[:8]:
            t = t0 + rng.uniform(0, 64)
            while t < t1:
                self._rec(t, c, NTP, 123, 123, "UDP", "", 2, 152)
                t += 64 + rng.uniform(-0.3, 0.3)
        # app pollers: irregular (hard negatives)
        for c in CLIENTS[20:30]:
            srv = APP_SERVERS[CLIENTS.index(c) % len(APP_SERVERS)]
            for t in self._poisson(t0, t1, 1 / 25.0):
                pk = rng.randint(4, 30)
                self._rec(t, c, srv, self._eph(), 443, "TCP", "SAF", pk, int(pk * rng.lognormvariate(6.2, 0.6)))
        # chat heartbeats: periodic-ish with heavy jitter (hard negatives)
        for c in CLIENTS[30:36]:
            t = t0 + rng.uniform(0, 30)
            while t < t1:
                pk = rng.randint(3, 12)
                self._rec(t, c, CHAT_SERVER, self._eph(), 443, "TCP", "SAF", pk, int(pk * rng.lognormvariate(5.8, 0.5)))
                t += 30 * rng.uniform(0.5, 1.5)
        # DRIFT: a new telemetry service polls every 60 s from many hosts
        if self.drift_at is not None and self.drift_at < t1:
            for c in CLIENTS[36:60]:
                t = max(t0, self.drift_at) + rng.uniform(0, 60)
                base = rng.randint(1400, 1700)
                while t < t1:
                    self._rec(t, c, TELEMETRY, self._eph(), 443, "TCP", "SAF", 5, int(base * rng.uniform(0.95, 1.05)))
                    t += 60 * rng.uniform(0.94, 1.06)

    # ---- attacks -------------------------------------------------------
    def inject(self, ep: Episode) -> None:
        rng, aid, lab = self.rng, ep.id, ep.cls
        t0, t1, p = ep.start, ep.end, ep.params
        if ep.cls == "ddos_syn_flood":
            for t in self._poisson(t0, t1, p["rate"]):
                pk = rng.randint(1, 3)
                self._rec(t, spoofed_ip(rng), p["target"], self._eph(), p.get("port", 443), "TCP", "S", pk, pk * rng.randint(40, 60), lab, aid)
        elif ep.cls == "ddos_udp_reflection":
            refl = rng.sample(REFLECTORS, 120)
            for t in self._poisson(t0, t1, p["rate"]):
                pk = rng.randint(2, 30)
                self._rec(t, rng.choice(refl), p["target"], rng.choice([53, 123, 1900, 11211]), rng.randint(1024, 65535),
                          "UDP", "", pk, pk * rng.randint(900, 1400), lab, aid)
        elif ep.cls == "ddos_spoofed_flood":
            for t in self._poisson(t0, t1, p["rate"]):
                self._rec(t, spoofed_ip(rng), p["target"], self._eph(), rng.randint(1, 65535), "UDP", "", 1, rng.randint(60, 120), lab, aid)
        elif ep.cls == "benign_flash_crowd":
            crowd = [f"203.0.113.{i}" for i in range(1, 255)] + [f"198.51.100.{i}" for i in range(1, 255)]
            for t in self._poisson(t0, t1, p["rate"]):
                pk = rng.randint(8, 60)
                self._rec(t, rng.choice(crowd), p["target"], self._eph(), 443, "TCP", "SAF", pk, pk * rng.randint(300, 1200))
        elif ep.cls == "beacon":
            t = t0 + rng.uniform(0, p["interval"])
            while t < t1:
                pk = rng.randint(3, 6)
                self._rec(t, p["src"], p["c2"], self._eph(), p["port"], "TCP", "SAF", pk,
                          int(p["size"] * rng.uniform(0.95, 1.05)), lab, aid)
                t += max(1.0, rng.gauss(p["interval"], p["jitter"] * p["interval"]))
        elif ep.cls == "dga":
            for t in self._poisson(t0, t1, p["rate"]):
                d = dga_domain(rng)
                p.setdefault("domains", []).append(".".join(d.split(".")[-2:]))
                self._rec(t, p["src"], RESOLVER, self._eph(), 53, "UDP", "", 2, rng.randint(80, 160), lab, aid,
                          dns_query=d, dns_qtype="A", dns_rcode="NXDOMAIN" if rng.random() < 0.9 else "NOERROR")
        elif ep.cls == "dns_tunnel":
            for i, t in enumerate(self._poisson(t0, t1, p["rate"])):
                q = tunnel_query(rng, p["base"], i)
                self._rec(t, p["src"], RESOLVER, self._eph(), 53, "UDP", "", 2, rng.randint(200, 600), lab, aid,
                          dns_query=q, dns_qtype=rng.choices(["TXT", "A", "NULL"], [60, 30, 10])[0], dns_rcode="NOERROR")
        # record the entity used for ground-truth matching
        if ep.cls.startswith("ddos") or ep.cls == "benign_flash_crowd":
            p["entity"] = {"dst_ip": p["target"]}
        elif ep.cls == "beacon":
            p["entity"] = {"src_ip": p["src"], "dst_ip": p["c2"], "dst_port": p["port"]}
        elif ep.cls == "dga":
            p["entity"] = {"src_ip": p["src"], "domains": sorted(set(p.get("domains", [])))}
        elif ep.cls == "dns_tunnel":
            p["entity"] = {"src_ip": p["src"], "base_domain": p["base"]}


# ---- episode factories ---------------------------------------------------
def make_episode(cls: str, idx: int, start: float, rng: random.Random, evasion: bool = False,
                 duration: float | None = None) -> Episode:
    ep_id = f"ep{idx:03d}"
    if cls == "ddos_syn_flood":
        p = {"target": WEB_SERVER, "rate": 15.0 if evasion else rng.uniform(60, 150)}
        dur = duration or rng.uniform(120, 240)
    elif cls == "ddos_udp_reflection":
        p = {"target": VPN_SERVER, "rate": rng.uniform(60, 120)}
        dur = duration or rng.uniform(120, 240)
    elif cls == "ddos_spoofed_flood":
        p = {"target": MAIL_SERVER, "rate": rng.uniform(80, 160)}
        dur = duration or rng.uniform(120, 240)
    elif cls == "benign_flash_crowd":
        p = {"target": WEB_SERVER, "rate": rng.uniform(40, 60)}
        dur = duration or rng.uniform(120, 200)
    elif cls == "beacon":
        p = {"src": rng.choice(CLIENTS[36:60]), "c2": rng.choice(C2_SERVERS), "port": rng.choice([443, 8080, 8443]),
             "interval": rng.uniform(20, 75), "jitter": rng.uniform(0.35, 0.6) if evasion else rng.uniform(0.01, 0.08),
             "size": rng.randint(150, 900)}
        dur = duration or rng.uniform(900, 1800)
    elif cls == "dga":
        p = {"src": rng.choice(CLIENTS), "rate": rng.uniform(0.5, 1.5)}
        dur = duration or rng.uniform(300, 600)
    elif cls == "dns_tunnel":
        p = {"src": rng.choice(CLIENTS), "base": rng.choice(TUNNEL_BASES),
             "rate": 1 / 15.0 if evasion else rng.uniform(1.0, 3.0)}
        dur = duration or rng.uniform(300, 600)
    else:
        raise ValueError(cls)
    return Episode(ep_id, cls, start, start + dur, p, evasion)


def random_schedule(t0: float, duration: float, rng: random.Random, per_hour: dict[str, float]) -> list[Episode]:
    eps, idx = [], 0
    hours = duration / 3600.0
    for cls, rate in per_hour.items():
        n = max(1, round(rate * hours))
        for _ in range(n):
            idx += 1
            for _try in range(100):
                ep = make_episode(cls, idx, rng.uniform(t0 + 120, t0 + duration - 300), rng)
                ep.end = min(ep.end, t0 + duration - 5)
                # keep episodes on the same target apart, so ground truth stays unambiguous
                tgt = ep.params.get("target")
                clash = tgt and any(o.params.get("target") == tgt and ep.start < o.end + 60 and ep.end > o.start - 60
                                    for o in eps)
                if not clash:
                    break
            eps.append(ep)
    return eps


TRAIN_RATES = {"ddos_syn_flood": 1.5, "ddos_udp_reflection": 1.5, "ddos_spoofed_flood": 1.5,
               "benign_flash_crowd": 3.0, "beacon": 3.0, "dga": 2.0, "dns_tunnel": 2.0}


def demo_schedule(t0: float, rng: random.Random) -> list[Episode]:
    """30-minute demo: one of everything, spaced so the dashboard tells a story."""
    m = 60.0
    plan = [("ddos_syn_flood", 3 * m, 150), ("beacon", 4 * m, 1500), ("dga", 8 * m, 360),
            ("benign_flash_crowd", 11 * m, 150), ("dns_tunnel", 15 * m, 360),
            ("ddos_udp_reflection", 19 * m, 150), ("ddos_spoofed_flood", 25 * m, 150)]
    return [make_episode(c, i + 1, t0 + s, rng, duration=d) for i, (c, s, d) in enumerate(plan)]


def evasion_schedule(t0: float, rng: random.Random) -> list[Episode]:
    m = 60.0
    plan = [("ddos_syn_flood", 2 * m, 240), ("beacon", 3 * m, 1500), ("dns_tunnel", 10 * m, 600)]
    return [make_episode(c, i + 1, t0 + s, rng, evasion=True, duration=d) for i, (c, s, d) in enumerate(plan)]


def generate(duration_s: float, seed: int, benign_domains: list[str], episodes_fn, start_ts: float = BASE_TS,
             drift_after_s: float | None = None) -> tuple[list[dict], list[dict]]:
    rng_sched = random.Random(seed + 1000)
    gen = TrafficGenerator(seed, benign_domains,
                           drift_at=(start_ts + drift_after_s) if drift_after_s is not None else None)
    episodes = episodes_fn(start_ts, rng_sched) if episodes_fn else []
    # generate benign in 10-minute chunks to keep memory reasonable when sorting
    t = start_ts
    while t < start_ts + duration_s:
        gen.benign(t, min(t + 600, start_ts + duration_s))
        t += 600
    for ep in episodes:
        gen.inject(ep)
    gen.out.sort(key=lambda r: r["ts"])
    return gen.out, [e.to_json() for e in episodes]


def write_jsonl(records: list[dict], episodes: list[dict], path: Path, meta: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, separators=(",", ":")) + "\n")
    labels = path.with_suffix(".labels.json")
    labels.write_text(json.dumps({"meta": meta, "episodes": episodes}, indent=1), encoding="utf-8")


def read_jsonl(path: Path):
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def read_labels(path: Path) -> dict:
    lp = Path(path).with_suffix(".labels.json")
    return json.loads(lp.read_text(encoding="utf-8")) if lp.exists() else {"meta": {}, "episodes": []}
