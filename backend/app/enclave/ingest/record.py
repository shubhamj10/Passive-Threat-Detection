"""Metadata-only flow record. There is deliberately NO label and NO payload field."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class FlowRecord:
    ts: float                 # event time (epoch seconds) from the sensor
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str                # "TCP" | "UDP" | "ICMP"
    flags: str = ""           # TCP flags observed in the flow, e.g. "S", "SA", "SAF"
    packets: int = 1
    bytes: int = 0
    dns_query: str | None = None
    dns_qtype: str | None = None
    dns_rcode: str | None = None
    recv_wall: float = field(default=0.0)   # wall time the enclave received it

    @property
    def is_dns(self) -> bool:
        return self.dns_query is not None
