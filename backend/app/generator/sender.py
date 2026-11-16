"""One-way UDP sender: the production side of the simulated data diode.

It only ever SENDS to the enclave's port and never reads anything back.
Replay controls (start / pause / speed) act on this simulator, not on the enclave.
"""
from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path
from typing import Callable, Iterable

from .scenario import read_jsonl


def _strip_gt(r: dict, keep_labels: bool) -> dict:
    # Labels travel with the record (as a TAP would never provide them, the
    # enclave parser strips them anyway). keep_labels=False drops them at source.
    if keep_labels:
        return r
    return {k: v for k, v in r.items() if k not in ("label", "attack_id")}


class TrafficSender:
    def __init__(self, host: str, port: int, time_scale: float = 20.0, per_datagram: int = 150,
                 max_bytes: int = 60000, keep_labels: bool = True):
        self.addr = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.time_scale = float(time_scale)
        self.per_datagram = per_datagram
        self.max_bytes = max_bytes
        self.keep_labels = keep_labels
        self.source_name = ""
        self._source: Callable[[], Iterable[dict]] | None = None
        self._loop = False
        self._paused = threading.Event()
        self._stop = threading.Event()
        self._restart = threading.Event()
        self._thread: threading.Thread | None = None
        self.sent_records = 0
        self.last_event_ts = 0.0
        self.loops = 0
        self.state = "idle"

    # ---- control ---------------------------------------------------------
    def load(self, source: Callable[[], Iterable[dict]], name: str, loop: bool) -> None:
        self._source, self.source_name, self._loop = source, name, loop

    def load_file(self, path: str | Path, loop: bool = False) -> None:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(p)
        self.load(lambda: read_jsonl(p), p.name, loop)

    def start(self) -> None:
        self._paused.clear()
        if self._thread and self._thread.is_alive():
            self._restart.set()
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="traffic-sender", daemon=True)
        self._thread.start()

    def pause(self) -> None:
        self._paused.set()
        self.state = "paused"

    def resume(self) -> None:
        self._paused.clear()

    def set_speed(self, speed: float) -> None:
        self.time_scale = max(0.1, min(float(speed), 1000.0))

    def stop(self) -> None:
        self._stop.set()

    def status(self) -> dict:
        return {"state": self.state, "source": self.source_name, "speed": self.time_scale,
                "sent_records": self.sent_records, "loops": self.loops,
                "last_event_ts": self.last_event_ts}

    # ---- worker ----------------------------------------------------------
    def _run(self) -> None:
        while not self._stop.is_set():
            self._restart.clear()
            self.state = "running"
            finished = self._play_once()
            if self._stop.is_set():
                break
            if finished and not self._loop:
                self.state = "finished"
                while not (self._stop.is_set() or self._restart.is_set()):
                    time.sleep(0.2)
            self.loops += 1
        self.state = "stopped"

    def _play_once(self) -> bool:
        if self._source is None:
            return True
        it = iter(self._source())
        # shift timestamps so event time continues after anything already sent
        offset = None
        anchor_ev = anchor_wall = None
        batch: list[bytes] = []
        size = 0
        for r in it:
            if self._stop.is_set() or self._restart.is_set():
                return False
            if offset is None:
                offset = max(time.time(), self.last_event_ts + 1.0) - r["ts"]
            r = dict(_strip_gt(r, self.keep_labels), ts=round(r["ts"] + offset, 6))
            if anchor_ev is None:
                anchor_ev, anchor_wall = r["ts"], time.time()
            # pacing in event time / time_scale
            while True:
                if self._paused.is_set():
                    pause_start = time.time()
                    while self._paused.is_set() and not self._stop.is_set():
                        time.sleep(0.1)
                    anchor_wall += time.time() - pause_start
                    self.state = "running"
                due = anchor_wall + (r["ts"] - anchor_ev) / self.time_scale
                delay = due - time.time()
                if delay <= 0:
                    break
                if batch:
                    self._send(batch); batch, size = [], 0
                time.sleep(min(delay, 0.05))
                # re-anchor if speed changed while sleeping
                anchor_ev, anchor_wall = self._reanchor(anchor_ev, anchor_wall, r["ts"])
            line = json.dumps(r, separators=(",", ":")).encode()
            if size + len(line) + 1 > self.max_bytes or len(batch) >= self.per_datagram:
                self._send(batch); batch, size = [], 0
            batch.append(line); size += len(line) + 1
            self.last_event_ts = r["ts"]
            self.sent_records += 1
        if batch:
            self._send(batch)
        return True

    def _reanchor(self, anchor_ev, anchor_wall, ts):
        # keep the current event time pinned to "now" so speed changes take effect smoothly
        if not hasattr(self, "_last_scale") or self._last_scale != self.time_scale:
            now = time.time()
            cur_ev = anchor_ev + (now - anchor_wall) * getattr(self, "_last_scale", self.time_scale)
            self._last_scale = self.time_scale
            return cur_ev, now
        return anchor_ev, anchor_wall

    def _send(self, lines: list[bytes]) -> None:
        self.sock.sendto(b"\n".join(lines), self.addr)   # one-way, fire-and-forget
