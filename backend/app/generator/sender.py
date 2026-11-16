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
    # Labels travel with the record (a TAP would never provide them; the
    # enclave parser strips them anyway). keep_labels=False drops them at source.
    if keep_labels:
        return r
    return {k: v for k, v in r.items() if k not in ("label", "attack_id")}


class TrafficSender:
    def __init__(
        self,
        host: str,
        port: int,
        time_scale: float = 20.0,
        per_datagram: int = 150,
        max_bytes: int = 1200,
        keep_labels: bool = True,
    ):
        self.addr = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.time_scale = max(0.1, min(float(time_scale), 1000.0))
        self.per_datagram = per_datagram
        # Hard cap for one datagram payload. 1200 stays safely under typical MTU.
        # self.max_bytes = min(int(max_bytes), 65000)
        self.max_bytes = min(int(max_bytes), 8192)
        self.keep_labels = keep_labels
        self.source_name = ""
        self._source: Callable[[], Iterable[dict]] | None = None
        self._loop = False
        self._paused = threading.Event()
        self._stop = threading.Event()
        self._restart = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_scale = self.time_scale
        self.sent_records = 0
        self.last_event_ts = 0.0
        self.loops = 0
        self.state = "idle"
        self.last_error = ""

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
        self._restart.clear()
        self.last_error = ""
        self._thread = threading.Thread(
            target=self._run, name="traffic-sender", daemon=True
        )
        self._thread.start()

    def pause(self) -> None:
        self._paused.set()
        self.state = "paused"

    def resume(self) -> None:
        self._paused.clear()
        if self._thread and self._thread.is_alive():
            self.state = "running"

    def set_speed(self, speed: float) -> None:
        self.time_scale = max(0.1, min(float(speed), 1000.0))

    def stop(self) -> None:
        self._stop.set()

    def status(self) -> dict:
        return {
            "state": self.state,
            "source": self.source_name,
            "speed": self.time_scale,
            "sent_records": self.sent_records,
            "loops": self.loops,
            "last_event_ts": self.last_event_ts,
            "error": self.last_error,
        }

    # ---- worker ----------------------------------------------------------
    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                self._restart.clear()
                self.state = "running"
                sent_before = self.sent_records

                finished = self._play_once()

                if self._stop.is_set():
                    break

                if not finished:
                    # Restart requested: begin a fresh pass immediately.
                    continue

                self.loops += 1

                if self._loop:
                    # Guard against a busy loop on an empty source.
                    if self.sent_records == sent_before:
                        time.sleep(0.2)
                else:
                    self.state = "finished"
                    while not (self._stop.is_set() or self._restart.is_set()):
                        time.sleep(0.2)
        except Exception as exc:  # surface errors instead of dying silently
            self.last_error = f"{type(exc).__name__}: {exc}"
            self.state = "error"
            return

        self.state = "stopped"

    def _play_once(self) -> bool:
        """Play the source once. Returns True if it ran to completion."""
        if self._source is None:
            return True

        offset = None
        anchor_ev = anchor_wall = None
        batch: list[bytes] = []
        size = 0
        self._last_scale = self.time_scale

        def flush() -> None:
            nonlocal batch, size
            if batch:
                self._send(batch)
                batch, size = [], 0

        for r in self._source():
            if self._stop.is_set() or self._restart.is_set():
                flush()
                return False

            # Shift timestamps so event time continues after anything already sent.
            if offset is None:
                offset = max(time.time(), self.last_event_ts + 1.0) - r["ts"]

            r = dict(
                _strip_gt(r, self.keep_labels),
                ts=round(r["ts"] + offset, 6),
            )

            if anchor_ev is None:
                anchor_ev, anchor_wall = r["ts"], time.time()

            # Pacing: event time / time_scale.
            while True:
                if self._stop.is_set() or self._restart.is_set():
                    flush()
                    return False

                if self._paused.is_set():
                    flush()
                    self.state = "paused"
                    pause_start = time.time()
                    while (
                        self._paused.is_set()
                        and not self._stop.is_set()
                        and not self._restart.is_set()
                    ):
                        time.sleep(0.1)
                    anchor_wall += time.time() - pause_start
                    if self._stop.is_set() or self._restart.is_set():
                        return False
                    self.state = "running"

                # Pick up speed changes smoothly.
                anchor_ev, anchor_wall = self._reanchor(anchor_ev, anchor_wall)

                due = anchor_wall + (r["ts"] - anchor_ev) / self.time_scale
                delay = due - time.time()
                if delay <= 0:
                    break

                # About to wait: don't hold buffered records back.
                flush()
                time.sleep(min(delay, 0.05))

            line = json.dumps(r, separators=(",", ":")).encode("utf-8")

            # A single record must fit in one datagram.
            if len(line) > self.max_bytes:
                raise ValueError(
                    f"Single record size ({len(line)} bytes) exceeds "
                    f"max_bytes ({self.max_bytes})"
                )

            # Flush before adding a record that would exceed byte/count limits.
            if batch and (
                size + len(line) + 1 > self.max_bytes
                or len(batch) >= self.per_datagram
            ):
                flush()

            size += len(line) + (1 if batch else 0)
            batch.append(line)

            self.last_event_ts = r["ts"]
            self.sent_records += 1

        flush()
        return True

    def _reanchor(self, anchor_ev: float, anchor_wall: float) -> tuple[float, float]:
        """Keep the current event time pinned to "now" when the speed changes."""
        if self._last_scale != self.time_scale:
            now = time.time()
            cur_ev = anchor_ev + (now - anchor_wall) * self._last_scale
            self._last_scale = self.time_scale
            return cur_ev, now
        return anchor_ev, anchor_wall

    def _send(self, lines: list[bytes]) -> None:
        """Send newline-delimited JSON as one UDP datagram (batch is pre-sized)."""
        if not lines:
            return
        payload = b"\n".join(lines)
        if len(payload) > self.max_bytes:
            raise ValueError(
                f"Datagram payload ({len(payload)} bytes) exceeds "
                f"max_bytes ({self.max_bytes})"
            )
        self.sock.sendto(payload, self.addr)