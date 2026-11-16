"""SQLite alert store (threat alerts, assurance alerts, feedback, trust history)."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
  alert_id TEXT PRIMARY KEY, seq INTEGER, ts TEXT, threat_class TEXT, severity TEXT,
  confidence REAL, model_name TEXT, entity TEXT, body TEXT NOT NULL,
  feedback TEXT, feedback_note TEXT, feedback_at REAL, ai_explanation TEXT);
CREATE INDEX IF NOT EXISTS ix_alerts_seq ON alerts(seq);
CREATE TABLE IF NOT EXISTS assurance_alerts (
  id TEXT PRIMARY KEY, seq INTEGER, ts TEXT, detector TEXT, status TEXT, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS trust_history (
  event_ts REAL, detector TEXT, score INTEGER, body TEXT);
"""


class AlertStore:
    def __init__(self, path: str | Path = ":memory:"):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            if str(path) != ":memory:":
                self._db.execute("PRAGMA journal_mode=WAL")
            self._db.executescript(_SCHEMA)
            self._db.commit()

    # ---- threat alerts ---------------------------------------------------
    def max_seq(self, table: str = "alerts") -> int:
        with self._lock:
            r = self._db.execute(f"SELECT COALESCE(MAX(seq),0) FROM {table}").fetchone()
        return int(r[0])

    def add_alert(self, a: dict) -> None:
        seq = int(a["alert_id"].rsplit("-", 1)[1])
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO alerts(alert_id,seq,ts,threat_class,severity,confidence,model_name,entity,body)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (a["alert_id"], seq, a["timestamp"], a["threat_class"], a["severity"], a["confidence"],
                 a["model"]["name"], a["entity"], json.dumps(a)))
            self._db.commit()

    def _row_to_alert(self, r) -> dict:
        a = json.loads(r["body"])
        a["ai_explanation"] = r["ai_explanation"]
        a["feedback"] = ({"verdict": r["feedback"], "note": r["feedback_note"], "at": r["feedback_at"]}
                         if r["feedback"] else None)
        return a

    def list_alerts(self, severity=None, threat_class=None, limit=200, offset=0) -> list[dict]:
        q, args = "SELECT * FROM alerts WHERE 1=1", []
        if severity:
            q += " AND severity=?"; args.append(severity)
        if threat_class:
            q += " AND threat_class=?"; args.append(threat_class)
        q += " ORDER BY seq DESC LIMIT ? OFFSET ?"; args += [int(limit), int(offset)]
        with self._lock:
            rows = self._db.execute(q, args).fetchall()
        return [self._row_to_alert(r) for r in rows]

    def get_alert(self, alert_id: str) -> dict | None:
        with self._lock:
            r = self._db.execute("SELECT * FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
        return self._row_to_alert(r) if r else None

    def counts(self) -> dict:
        with self._lock:
            by_class = dict(self._db.execute("SELECT threat_class, COUNT(*) FROM alerts GROUP BY threat_class").fetchall())
            by_sev = dict(self._db.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity").fetchall())
            total = self._db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        return {"total": total, "by_class": by_class, "by_severity": by_sev}

    def set_feedback(self, alert_id: str, verdict: str, note: str | None) -> bool:
        with self._lock:
            cur = self._db.execute("UPDATE alerts SET feedback=?, feedback_note=?, feedback_at=? WHERE alert_id=?",
                                   (verdict, note, time.time(), alert_id))
            self._db.commit()
        return cur.rowcount > 0

    def feedback_stats(self, model_name: str) -> tuple[int, int]:
        with self._lock:
            r = self._db.execute(
                "SELECT COUNT(*), SUM(CASE WHEN feedback='false_positive' THEN 1 ELSE 0 END) FROM alerts "
                "WHERE model_name=? AND feedback IS NOT NULL", (model_name,)).fetchone()
        return int(r[0] or 0), int(r[1] or 0)

    def set_explanation(self, alert_id: str, text: str) -> None:
        with self._lock:
            self._db.execute("UPDATE alerts SET ai_explanation=? WHERE alert_id=?", (text, alert_id))
            self._db.commit()

    # ---- assurance -------------------------------------------------------
    def add_assurance_alert(self, a: dict) -> None:
        seq = int(a["assurance_alert_id"].rsplit("-", 1)[1])
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO assurance_alerts(id,seq,ts,detector,status,body) VALUES (?,?,?,?,?,?)",
                             (a["assurance_alert_id"], seq, a["timestamp"], a["detector"]["name"], a["status"], json.dumps(a)))
            self._db.commit()

    def list_assurance_alerts(self, status: str | None = None, limit: int = 100) -> list[dict]:
        q, args = "SELECT body FROM assurance_alerts", []
        if status:
            q += " WHERE status=?"; args.append(status)
        q += " ORDER BY seq DESC LIMIT ?"; args.append(limit)
        with self._lock:
            return [json.loads(r[0]) for r in self._db.execute(q, args).fetchall()]

    def add_trust_point(self, event_ts: float, detector: str, score: int | None, body: dict) -> None:
        with self._lock:
            self._db.execute("INSERT INTO trust_history VALUES (?,?,?,?)", (event_ts, detector, score, json.dumps(body)))
            self._db.commit()

    def clear(self) -> None:
        with self._lock:
            for t in ("alerts", "assurance_alerts", "trust_history"):
                self._db.execute(f"DELETE FROM {t}")
            self._db.commit()
