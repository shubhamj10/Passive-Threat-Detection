"""No label leakage: ground truth is stripped at ingest and never read by detectors."""
import ast
import json
from pathlib import Path

from app.enclave.ingest.parser import parse_datagram, parse_line
from app.enclave.ingest.record import FlowRecord

ENCLAVE = Path(__file__).resolve().parent.parent / "app" / "enclave"


def test_parser_strips_label_and_payload():
    line = json.dumps({"ts": 1.0, "src_ip": "10.0.0.1", "dst_ip": "192.0.2.1", "src_port": 1, "dst_port": 2,
                       "proto": "tcp", "label": "beacon", "attack_id": "ep1", "payload": "secret"})
    r = parse_line(line)
    assert isinstance(r, FlowRecord)
    assert not hasattr(r, "label") and not hasattr(r, "payload") and not hasattr(r, "attack_id")
    assert r.proto == "TCP"


def test_record_has_no_label_field():
    assert "label" not in FlowRecord.__dataclass_fields__
    assert "payload" not in FlowRecord.__dataclass_fields__


def test_malformed_lines_counted():
    from app.enclave.ingest.parser import ParseStats
    st = ParseStats()
    out = parse_datagram(b'{"ts":1,"src_ip":"a","dst_ip":"b"}\nnot json\n{"x":1}', st)
    assert len(out) == 1 and st.malformed == 2


def test_detection_code_never_reads_labels():
    for sub in ("features", "detectors", "scoring", "pipeline", "alerts", "assurance"):
        for p in (ENCLAVE / sub).rglob("*.py"):
            tree = ast.parse(p.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and node.value in ("label", "attack_id"):
                    raise AssertionError(f"{p.name} references a ground-truth field")
                if isinstance(node, ast.Attribute) and node.attr in ("label", "attack_id"):
                    raise AssertionError(f"{p.name} reads .{node.attr}")
