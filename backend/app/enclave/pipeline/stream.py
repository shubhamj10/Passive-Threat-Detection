"""Bounded stream queue between the receive-only socket and the engine (two threads)."""
from __future__ import annotations

import queue
import threading
import time
from collections import deque

from ..diode.receiver import ReceiveOnlySocket
from ..ingest.parser import ParseStats, parse_datagram
from .engine import Engine


class StreamPipeline:
    def __init__(self, engine: Engine, host: str, port: int, maxsize: int, bufsize: int = 65535):
        self.engine = engine
        self.q: queue.Queue = queue.Queue(maxsize=maxsize)
        self.sock = ReceiveOnlySocket(host, port, bufsize=bufsize)
        self.parse_stats = ParseStats()
        self.dropped = 0
        self.datagrams = 0
        self._stop = threading.Event()
        self._rate: deque = deque(maxlen=20)   # (wall, records processed)
        self.engine_lock = threading.Lock()
        self._threads = [threading.Thread(target=self._recv_loop, name="diode-recv", daemon=True),
                         threading.Thread(target=self._work_loop, name="engine", daemon=True)]

    def start(self) -> None:
        for t in self._threads:
            t.start()

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=2)
        self.sock.close()

    def _recv_loop(self) -> None:
        while not self._stop.is_set():
            data = self.sock.recv()
            if data is None:
                continue
            self.datagrams += 1
            for rec in parse_datagram(data, self.parse_stats):
                try:
                    self.q.put_nowait(rec)
                except queue.Full:            # bounded: drop oldest, keep newest
                    try:
                        self.q.get_nowait()
                    except queue.Empty:
                        pass
                    self.dropped += 1
                    self.q.put_nowait(rec)

    def _work_loop(self) -> None:
        idle_since = None
        while not self._stop.is_set():
            try:
                rec = self.q.get(timeout=0.2)
            except queue.Empty:
                # idle: once the stream pauses, let the watermark catch up so windows close
                if idle_since is None:
                    idle_since = time.time()
                elif time.time() - idle_since > 3 and self.engine.max_ts > float("-inf"):
                    with self.engine_lock:
                        self.engine.flush()
                    idle_since = None
                continue
            idle_since = None
            with self.engine_lock:
                self.engine.process(rec)

    def flows_per_s(self) -> float:
        now = time.time()
        self._rate.append((now, self.engine.records))
        while len(self._rate) > 2 and now - self._rate[0][0] > 5:
            self._rate.popleft()
        if len(self._rate) < 2:
            return 0.0
        (t0, n0), (t1, n1) = self._rate[0], self._rate[-1]
        return (n1 - n0) / (t1 - t0) if t1 > t0 else 0.0
