"""REST API smoke tests against an in-memory store filled from a scenario run."""
from fastapi.testclient import TestClient

from app.api.main import create_app
from app.api.runtime import Runtime
from app.enclave.alerts.store import AlertStore


def _client(runs, cfg, monkeypatch, workspace):
    import app.enclave.detectors.base as base
    monkeypatch.setattr(base, "MODELS_DIR", workspace["models"])
    store = AlertStore(":memory:")
    eng, mon = runs["scenario"]
    for a in eng.alerts:
        store.add_alert(a)
    rt = Runtime(cfg=cfg, store=store, monitor=mon, mode="test")
    return TestClient(create_app(rt)), eng.alerts


def test_endpoints(runs, cfg, monkeypatch, workspace):
    c, alerts = _client(runs, cfg, monkeypatch, workspace)
    with c:
        assert c.get("/api/health").json()["status"] == "ok"
        lst = c.get("/api/alerts").json()
        assert len(lst) == len(alerts)
        assert all(a["threat_class"] == "ddos" for a in c.get("/api/alerts?threat_class=ddos").json())
        aid = alerts[0]["alert_id"]
        assert c.get(f"/api/alerts/{aid}").json()["alert_id"] == aid
        assert c.get("/api/alerts/nope").status_code == 404
        assert c.post(f"/api/alerts/{aid}/feedback", json={"verdict": "false_positive"}).status_code == 200
        assert c.get(f"/api/alerts/{aid}").json()["feedback"]["verdict"] == "false_positive"
        assert c.post(f"/api/alerts/{aid}/feedback", json={"verdict": "maybe"}).status_code == 422
        assert c.post(f"/api/alerts/{aid}/replay").json()["reproduced"] is True
        ex = c.post(f"/api/alerts/{aid}/explain").json()
        assert ex["text"] and "10.1." not in ex["text"]       # redacted
        st = c.get("/api/assurance/status").json()
        assert set(st["detectors"]) == {"ddos_scorer", "beacon_scorer", "dns_scorer"}
        assert c.post("/api/replay/pause").status_code == 409   # no generator in this runtime
        assert "alerts" in c.get("/api/stats").json()


def test_websocket_sends_stats(runs, cfg, monkeypatch, workspace):
    c, _ = _client(runs, cfg, monkeypatch, workspace)
    with c, c.websocket_connect("/ws/alerts") as ws:
        assert ws.receive_json()["type"] == "stats"
