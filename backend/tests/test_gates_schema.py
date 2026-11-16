import pytest
from pydantic import ValidationError

from app.enclave.alerts.schema import Alert
from app.enclave.assurance.assurance_alerts import AssuranceAlertManager
from app.enclave.detectors.beacon import BeaconDetector
from app.enclave.detectors.ddos import DdosDetector
from app.enclave.detectors.dns import DnsDetector


def test_ddos_gates():
    th = {"alert_threshold": 0.7, "min_flows": 300, "persistence_windows": 2}
    ok, bad = DdosDetector.gates("ddos", {"flows": 900}, {"consecutive_windows": 2}, th)
    assert bad == [] and set(ok) == {"min_evidence", "persistence", "not_allowlisted"}
    ok, bad = DdosDetector.gates("ddos", {"flows": 900}, {"consecutive_windows": 1}, th)
    assert bad == ["persistence"]
    ok, bad = DdosDetector.gates("ddos", {"flows": 50}, {"consecutive_windows": 3, "allowlisted": True}, th)
    assert set(bad) == {"min_evidence", "not_allowlisted"}


def test_ddos_subtypes():
    base = {"syn_only_ratio": 0.0, "udp_ratio": 0.0, "reflection_ratio": 0.0}
    assert DdosDetector.classify(dict(base, syn_only_ratio=0.9), {})[1] == "syn_flood"
    assert DdosDetector.classify(dict(base, udp_ratio=1.0, reflection_ratio=0.9), {})[1] == "udp_reflection"
    assert DdosDetector.classify(dict(base, udp_ratio=1.0), {})[1] == "volumetric_flood"


def test_beacon_gates():
    th = {"alert_threshold": 0.7, "min_events": 8, "min_span_s": 240}
    assert BeaconDetector.gates("x", {"events": 9, "span_s": 300}, {}, th)[1] == []
    assert BeaconDetector.gates("x", {"events": 5, "span_s": 100}, {}, th)[1] == ["min_evidence", "persistence"]


def test_dns_classify_and_gates():
    th = {"alert_threshold": 0.7, "dga_min_domains": 3, "tunnel_min_queries": 10, "tunnel_min_label_len": 24}
    assert DnsDetector.classify({"max_label_len": 50, "sub_entropy": 4.5}, th)[0] == "dns_tunnelling"
    assert DnsDetector.classify({"max_label_len": 15, "sub_entropy": 0}, th)[0] == "dga_domain"
    assert DnsDetector.gates("dga_domain", {}, {"flagged_groups": 2}, th)[1] == ["min_evidence"]
    assert DnsDetector.gates("dns_tunnelling", {"n_queries": 4, "n_unique": 4}, {}, th)[1] == \
        ["min_evidence", "persistence"]


def test_alert_schema_rejects_bad_values(runs):
    eng, _ = runs["scenario"]
    a = dict(eng.alerts[0])
    Alert(**a)
    with pytest.raises(ValidationError):
        Alert(**dict(a, confidence=1.5))
    with pytest.raises(ValidationError):
        Alert(**dict(a, threat_class="port_scan"))


def test_assurance_manager_no_duplicates(cfg):
    m = AssuranceAlertManager(cfg)
    ev = []
    for s in (90, 60, 55, 40, 65, 72, 80, 50):
        ev += [k for k, _ in m.evaluate("beacon_scorer", "1.0.0", s, None, {}, 1792576800.0)]
    # open at 60, worsen 55/40 (updates), stay open at 65/72 (below recover 75), resolve at 80, re-open at 50
    assert ev.count("assurance_alert") == 2
    assert ev.count("assurance_resolved") == 1
