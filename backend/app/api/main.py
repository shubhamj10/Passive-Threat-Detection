"""FastAPI app: REST + WebSocket. Read-mostly view of the enclave; never touches the traffic path."""
from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from ..assistant.explainer import explain
from ..config import BACKEND_DIR, load_env, resolve
from ..enclave.assurance.trace import replay_alert
from .runtime import Runtime


class FeedbackIn(BaseModel):
    verdict: Literal["true_positive", "false_positive"]
    note: Optional[str] = None


class SpeedIn(BaseModel):
    speed: float


class StartIn(BaseModel):
    file: Optional[str] = None


def create_app(runtime: Runtime | None = None) -> FastAPI:
    load_env()
    rt = runtime or Runtime.api_only()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        task = asyncio.create_task(pump())
        yield
        task.cancel()

    app = FastAPI(title="Passive AI Threat Detection", version="1.0.0", lifespan=lifespan)
    origins = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "http://localhost:5173").split(",") if o.strip()]
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["*"], allow_headers=["*"])
    app.state.rt = rt
    clients: set[WebSocket] = set()

    async def pump():
        """Drain engine events and push them to every connected dashboard."""
        last_stats = 0.0
        interval = float(rt.cfg["api"]["ws_stats_interval_s"])
        loop = asyncio.get_running_loop()
        while True:
            msgs = []
            try:
                while len(msgs) < 500:
                    msgs.append(rt.broadcaster.q.get_nowait())
            except Exception:
                pass
            now = loop.time()
            if now - last_stats >= interval:
                last_stats = now
                msgs.append({"type": "stats", "data": rt.stats()})
            for m in msgs:
                text = json.dumps(m, default=str)
                for ws in list(clients):
                    try:
                        await ws.send_text(text)
                    except Exception:
                        clients.discard(ws)
            await asyncio.sleep(0.2)

    # ---- REST ---------------------------------------------------------------
    @app.get("/api/health")
    def health():
        return {"status": "ok", "mode": rt.mode, "pipeline_running": rt.pipeline is not None}

    @app.get("/api/alerts")
    def list_alerts(severity: Optional[str] = None, threat_class: Optional[str] = None,
                    limit: int = Query(200, le=2000), offset: int = 0):
        return rt.store.list_alerts(severity, threat_class, limit, offset)

    @app.get("/api/alerts/{alert_id}")
    def get_alert(alert_id: str):
        a = rt.store.get_alert(alert_id)
        if not a:
            raise HTTPException(404, "alert not found")
        return a

    @app.post("/api/alerts/{alert_id}/feedback")
    def feedback(alert_id: str, body: FeedbackIn):
        if not rt.store.set_feedback(alert_id, body.verdict, body.note):
            raise HTTPException(404, "alert not found")
        return {"alert_id": alert_id, "verdict": body.verdict}

    @app.post("/api/alerts/{alert_id}/replay")
    def replay(alert_id: str):
        a = rt.store.get_alert(alert_id)
        if not a:
            raise HTTPException(404, "alert not found")
        return replay_alert(a, rt.cfg)

    @app.post("/api/alerts/{alert_id}/explain")
    def explain_alert(alert_id: str):
        a = rt.store.get_alert(alert_id)
        if not a:
            raise HTTPException(404, "alert not found")
        res = explain(a)
        rt.store.set_explanation(alert_id, res["text"])
        return res

    @app.get("/api/stats")
    def stats():
        return rt.stats()

    @app.get("/api/assurance/status")
    def assurance_status():
        if rt.monitor is None:
            return {"detectors": {}, "note": "assurance monitor runs with the pipeline (run_all.py)"}
        return {"detectors": rt.monitor.snapshot(),
                "settings": {k: rt.cfg["assurance"][k] for k in ("trust_alert_below", "trust_weights", "min_feedback",
                                                                  "drift_psi_warn", "alert_volume_band")}}

    @app.get("/api/assurance/alerts")
    def assurance_alerts(status: Optional[str] = None):
        return rt.store.list_assurance_alerts(status)

    # ---- replay controls (act on the simulated production side only) ----------
    def _sender():
        if rt.sender is None:
            raise HTTPException(409, "traffic generator not running: start with run_all.py")
        return rt.sender

    @app.post("/api/replay/start")
    def replay_start(body: StartIn | None = None):
        s = _sender()
        if body and body.file:
            p = resolve(body.file)
            if not str(p.resolve()).startswith(str((BACKEND_DIR / "data").resolve())) or not p.exists():
                raise HTTPException(400, "file must exist under backend/data/")
            s.load_file(p, loop=False)
        s.start()
        return s.status()

    @app.post("/api/replay/pause")
    def replay_pause():
        s = _sender()
        s.pause() if s.state != "paused" else s.resume()
        return s.status()

    @app.post("/api/replay/speed")
    def replay_speed(body: SpeedIn):
        s = _sender()
        s.set_speed(body.speed)
        return s.status()

    @app.get("/api/replay/status")
    def replay_status():
        return _sender().status()

    @app.get("/api/replay/files")
    def replay_files():
        d = BACKEND_DIR / "data" / "synthetic"
        return sorted(f"data/synthetic/{p.name}" for p in d.glob("*.jsonl"))

    # ---- WebSocket -------------------------------------------------------------
    @app.websocket("/ws/alerts")
    async def ws_alerts(ws: WebSocket):
        await ws.accept()
        clients.add(ws)
        try:
            await ws.send_text(json.dumps({"type": "stats", "data": rt.stats()}, default=str))
            while True:
                await ws.receive_text()    # keep-alive; client messages are ignored
        except WebSocketDisconnect:
            pass
        finally:
            clients.discard(ws)

    return app


app = create_app() if os.environ.get("PTD_NO_DEFAULT_APP") != "1" else None
