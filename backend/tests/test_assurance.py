"""Drift lowers the affected detector's trust; a stable benign run stays above the threshold."""


def test_drift_lowers_beacon_trust(runs, cfg):
    eng, mon = runs["drift"]
    below = cfg["assurance"]["trust_alert_below"]
    assert mon.status["beacon_scorer"]["trust_score"] < below
    opened = [b for k, b in eng.assurance_events if k == "assurance_alert"]
    assert [b["detector"]["name"] for b in opened] == ["beacon_scorer"]   # exactly one, no duplicates


def test_benign_run_keeps_trust(runs, cfg):
    eng, mon = runs["benign"]
    below = cfg["assurance"]["trust_alert_below"]
    for name, st in mon.status.items():
        assert st["trust_score"] is not None and st["trust_score"] >= below, (name, st)
    assert not [k for k, _ in eng.assurance_events if k == "assurance_alert"]


def test_normal_scenario_keeps_trust(runs, cfg):
    _, mon = runs["scenario"]
    assert all(s["trust_score"] >= cfg["assurance"]["trust_alert_below"] for s in mon.status.values())


def test_trust_combine_handles_insufficient_data():
    from app.enclave.assurance.trust import combine
    w = {"drift": 0.4, "volume": 0.2, "feedback_fp": 0.4}
    assert combine({"drift": None, "volume": None, "feedback_fp": None}, w) is None
    assert combine({"drift": 1.0, "volume": 1.0, "feedback_fp": None}, w) == 100
    assert combine({"drift": 0.0, "volume": 1.0, "feedback_fp": None}, w) == 33
