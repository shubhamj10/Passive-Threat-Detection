"""Each attack class raises a correct alert; a pure-benign run raises no high-severity alert."""
from app.generator.scenario import read_labels
from app.offline.evaluation import score_alerts
from app.offline.labels import EpisodeIndex


def test_each_attack_class_detected(runs, workspace):
    eng, _ = runs["scenario"]
    eps = read_labels(workspace["data"] / "scenario.jsonl")["episodes"]
    res = score_alerts(eng.alerts, eps, 0.5)["per_class"]
    for cls in ("ddos", "botnet_c2_beaconing", "dga_domain", "dns_tunnelling"):
        assert res[cls]["detected"] == res[cls]["episodes"] > 0, (cls, res[cls])


def test_alerts_match_ground_truth_class(runs, workspace):
    eng, _ = runs["scenario"]
    idx = EpisodeIndex(read_labels(workspace["data"] / "scenario.jsonl")["episodes"])
    high = [a for a in eng.alerts if a["severity"] in ("high", "critical")]
    assert high and all(idx.match_alert(a) is not None for a in high)


def test_benign_run_no_high_severity(runs):
    eng, _ = runs["benign"]
    assert not [a for a in eng.alerts if a["severity"] in ("high", "critical")]


def test_alert_has_standard_fields(runs):
    eng, _ = runs["scenario"]
    a = eng.alerts[0]
    for k in ("alert_id", "timestamp", "flow_id", "threat_class", "confidence", "evidence", "trace", "model"):
        assert k in a
    assert a["trace"]["config_hash"].startswith("sha256:")
    assert a["evidence"]["gates_passed"]
