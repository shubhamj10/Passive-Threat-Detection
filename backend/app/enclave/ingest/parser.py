"""Record parsing and flow normalisation.

Input datagrams carry newline-delimited JSON records. Ground-truth fields
(`label`, `attack_id`) and any `payload` field are DROPPED here, before any
detector can see the record.
"""
from __future__ import annotations

import json
import time

from .record import FlowRecord

STRIPPED_FIELDS = frozenset({"label", "attack_id", "payload"})
_VALID_PROTO = {"TCP", "UDP", "ICMP"}


class ParseStats:
    def __init__(self) -> None:
        self.ok = 0
        self.malformed = 0


def normalise(obj: dict, recv_wall: float | None = None) -> FlowRecord | None:
    """Turn a raw dict into a FlowRecord. Returns None if required fields are missing."""
    try:
        proto = str(obj.get("proto", "TCP")).upper()
        if proto not in _VALID_PROTO:
            return None
        q = obj.get("dns_query")
        if q is not None:
            q = str(q).strip().lower().rstrip(".") or None
        return FlowRecord(
            ts=float(obj["ts"]),
            src_ip=str(obj["src_ip"]),
            dst_ip=str(obj["dst_ip"]),
            src_port=int(obj.get("src_port", 0)),
            dst_port=int(obj.get("dst_port", 0)),
            proto=proto,
            flags=str(obj.get("flags", "")).upper(),
            packets=max(1, int(obj.get("packets", 1))),
            bytes=max(0, int(obj.get("bytes", 0))),
            dns_query=q,
            dns_qtype=(str(obj["dns_qtype"]).upper() if obj.get("dns_qtype") else None),
            dns_rcode=(str(obj["dns_rcode"]).upper() if obj.get("dns_rcode") else None),
            recv_wall=recv_wall if recv_wall is not None else time.time(),
        )
    except (KeyError, TypeError, ValueError):
        return None


def parse_line(line: bytes | str, recv_wall: float | None = None) -> FlowRecord | None:
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(obj, dict):
        return None
    for k in STRIPPED_FIELDS:
        obj.pop(k, None)
    return normalise(obj, recv_wall)


def parse_datagram(data: bytes, stats: ParseStats | None = None) -> list[FlowRecord]:
    now = time.time()
    out: list[FlowRecord] = []
    for line in data.split(b"\n"):
        if not line.strip():
            continue
        rec = parse_line(line, now)
        if rec is None:
            if stats:
                stats.malformed += 1
        else:
            out.append(rec)
            if stats:
                stats.ok += 1
    return out
