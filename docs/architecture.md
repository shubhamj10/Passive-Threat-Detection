# Architecture

```
generator/scenario.py  ->  generator/sender.py  ==UDP, one way==>  enclave/diode/receiver.py
                                                                        |
                                    enclave/ingest/parser.py (strip labels, normalise)
                                                                        |
                                    enclave/pipeline/stream.py (bounded queue, 2 threads)
                                                                        |
                                    enclave/pipeline/engine.py
                                      ├─ features/ddos.py    10 s tumbling windows per internal destination
                                      ├─ features/beacon.py  600 s sliding window, 60 s hop, per host pair
                                      └─ features/dns.py     60 s tumbling windows per (host, base domain)
                                                                        |
                                    detectors/*  RandomForest -> Platt calibration -> class rule -> gates
                                                                        |
                                    alerts/dedup.py -> alerts/builder.py (decision trace) -> alerts/store.py
                                                                        |
                                    assurance/monitor.py (drift, volume, feedback -> trust -> assurance alerts)
                                                                        |
                                    api/main.py  REST + WebSocket  ->  React dashboard
                                    assistant/explainer.py  (optional, finished alerts only, redacted)
```

## Threads (run_all.py)
- `traffic-sender`: the simulated production side. Paces records by event time / `time_scale`.
- `diode-recv`: receive-only socket -> parse -> bounded queue (drop-oldest when full).
- `engine`: consumes the queue, runs windows, detectors, assurance. Single writer to SQLite.
- uvicorn event loop: REST + WebSocket; a pump task drains the engine's event queue.

## Event time
All windows use the record timestamps (event time) with a watermark of `max_ts - lateness`.
Records arriving for an already-closed window are counted and dropped. When the stream goes
idle for 3 s, the engine flushes so the last windows close.

## Why the same Engine everywhere
`Engine` runs online (fed by the socket) and offline (evaluate, benchmark, tests, alert-volume
baseline). Offline results therefore describe the exact code path that runs live.
