"""Optional offline PCAP reader (needs scapy). Reads headers only; payloads are ignored.

Each packet becomes a one-packet flow record. DNS query names are taken from the
DNS question section only. This reads a FILE; it never opens a network socket.
"""
from __future__ import annotations

from typing import Iterator

from .record import FlowRecord

try:  # guarded optional import
    from scapy.all import DNS, IP, TCP, UDP, PcapReader  # type: ignore
    HAVE_SCAPY = True
except Exception:  # pragma: no cover
    HAVE_SCAPY = False


def read_pcap(path: str) -> Iterator[FlowRecord]:
    if not HAVE_SCAPY:
        raise RuntimeError("scapy is not installed: pip install scapy")
    with PcapReader(path) as reader:  # pragma: no cover - needs scapy + file
        for pkt in reader:
            if IP not in pkt:
                continue
            ip = pkt[IP]
            proto, sport, dport, flags = "ICMP", 0, 0, ""
            if TCP in pkt:
                proto, sport, dport, flags = "TCP", pkt[TCP].sport, pkt[TCP].dport, str(pkt[TCP].flags)
            elif UDP in pkt:
                proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
            q = qtype = rcode = None
            if DNS in pkt and pkt[DNS].qd is not None:
                try:
                    q = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".").lower()
                    qtype = {1: "A", 28: "AAAA", 16: "TXT", 10: "NULL", 5: "CNAME"}.get(pkt[DNS].qd.qtype, "OTHER")
                    rcode = "NXDOMAIN" if pkt[DNS].rcode == 3 else "NOERROR"
                except Exception:
                    pass
            yield FlowRecord(ts=float(pkt.time), src_ip=ip.src, dst_ip=ip.dst, src_port=int(sport),
                             dst_port=int(dport), proto=proto, flags=flags.upper(), packets=1,
                             bytes=int(len(pkt)), dns_query=q, dns_qtype=qtype, dns_rcode=rcode)
