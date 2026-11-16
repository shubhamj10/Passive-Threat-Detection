"""Decision-trace replay reproduces threat class, confidence and evidence."""
import copy

from app.enclave.assurance.trace import replay_alert


def test_replay_reproduces_every_alert(runs, cfg, workspace):
    eng, _ = runs["scenario"]
    assert eng.alerts
    for a in eng.alerts:
        r = replay_alert(a, cfg, workspace["models"])
        assert r["reproduced"], r
        assert r["checks"]["config_hash_match"]


def test_replay_detects_tampering(runs, cfg, workspace):
    eng, _ = runs["scenario"]
    a = copy.deepcopy(eng.alerts[0])
    a["confidence"] = 0.5
    assert not replay_alert(a, cfg, workspace["models"])["reproduced"]


def test_replay_missing_model_version(runs, cfg, workspace):
    eng, _ = runs["scenario"]
    a = copy.deepcopy(eng.alerts[0])
    a["model"]["version"] = "9.9.9"
    r = replay_alert(a, cfg, workspace["models"])
    assert r["reproduced"] is False and "error" in r
