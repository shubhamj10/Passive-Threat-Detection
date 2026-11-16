"""Best-effort converter for public flow datasets (CIC-style CSV) to the project record format.

Supports CSV files whose columns resemble CICFlowMeter output (CIC-DDoS2019,
CIC-IDS2017/2018): Source IP, Destination IP, Source Port, Destination Port,
Protocol, Timestamp, Total Fwd Packets, Total Length of Fwd Packets, Label.
Datasets with other layouts (e.g. CTU-13 binetflow) map through ALIASES.
Follow each dataset's licence and citation terms; record them in docs/datasheet.md.
"""
from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

ALIASES = {
    "src_ip": ["source ip", "src ip", "srcaddr", "src_ip", "saddr"],
    "dst_ip": ["destination ip", "dst ip", "dstaddr", "dst_ip", "daddr"],
    "src_port": ["source port", "src port", "sport", "src_port"],
    "dst_port": ["destination port", "dst port", "dport", "dst_port"],
    "proto": ["protocol", "proto"],
    "ts": ["timestamp", "starttime", "stime", "ts"],
    "packets": ["total fwd packets", "tot fwd pkts", "totpkts", "packets"],
    "bytes": ["total length of fwd packets", "totlen fwd pkts", "totbytes", "bytes"],
    "flags": ["flags", "state"],
    "label": ["label"],
}
PROTO = {"6": "TCP", "17": "UDP", "1": "ICMP", "tcp": "TCP", "udp": "UDP", "icmp": "ICMP"}
LABEL_MAP = [("syn", "ddos_syn_flood"), ("dns", "ddos_udp_reflection"), ("ntp", "ddos_udp_reflection"),
             ("ssdp", "ddos_udp_reflection"), ("ldap", "ddos_udp_reflection"), ("udp", "ddos_spoofed_flood"),
             ("ddos", "ddos_spoofed_flood"), ("botnet", "beacon"), ("bot", "beacon")]


def _ts(v: str) -> float | None:
    v = v.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %I:%M:%S %p",
                "%Y/%m/%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(v, fmt).timestamp()
        except ValueError:
            continue
    try:
        return float(v)
    except ValueError:
        return None


def _label(v: str) -> str:
    v = (v or "").strip().lower()
    if not v or v in ("benign", "normal", "background") or "normal" in v or "background" in v:
        return "benign"
    for k, lab in LABEL_MAP:
        if k in v:
            return lab
    return "unknown_attack"


def convert_public(folder: str | Path, out_dir: Path, max_rows: int | None = None) -> Path:
    folder = Path(folder)
    files = sorted(list(folder.rglob("*.csv")) + list(folder.rglob("*.binetflow")))
    if not files:
        raise FileNotFoundError(f"no .csv/.binetflow files under {folder}")
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{folder.name}.jsonl"
    n = skipped = 0
    with open(out, "w", encoding="utf-8") as fh:
        for f in files:
            with open(f, newline="", encoding="utf-8", errors="ignore") as src:
                reader = csv.DictReader(src)
                cols = {c.strip().lower(): c for c in (reader.fieldnames or [])}
                pick = {k: next((cols[a] for a in al if a in cols), None) for k, al in ALIASES.items()}
                if not (pick["src_ip"] and pick["dst_ip"] and pick["ts"]):
                    continue
                for row in reader:
                    ts = _ts(row.get(pick["ts"], ""))
                    if ts is None:
                        skipped += 1
                        continue
                    get = lambda k, d="0": (row.get(pick[k]) if pick[k] else d) or d
                    try:
                        rec = {"ts": ts, "src_ip": get("src_ip", "").strip(), "dst_ip": get("dst_ip", "").strip(),
                               "src_port": int(float(get("src_port"))), "dst_port": int(float(get("dst_port"))),
                               "proto": PROTO.get(str(get("proto", "6")).strip().lower(), "TCP"),
                               "flags": "", "packets": max(1, int(float(get("packets", "1")))),
                               "bytes": int(float(get("bytes"))), "label": _label(get("label", ""))}
                    except ValueError:
                        skipped += 1
                        continue
                    fh.write(json.dumps(rec) + "\n")
                    n += 1
                    if max_rows and n >= max_rows:
                        break
    print(f"converted {n} rows ({skipped} skipped). Sort by ts before replay: records must be roughly time-ordered.")
    return out
