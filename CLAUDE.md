# Build specification (for Claude Code)

Read README.md first. Rules that must hold for every change:

1. **Read-only enclave.** Nothing under `backend/app/enclave/` may send, connect or import a network
   client. Only `diode/receiver.py` may import `socket`, and only to bind and receive.
   `tests/test_readonly.py` enforces this with an AST scan. Only `app/assistant/` may call out.
2. **Metadata only.** Records carry IPs, ports, flags, sizes, timings and DNS names. Never payloads.
3. **No label leakage.** `label`/`attack_id` are stripped in `ingest/parser.py`. Ground truth is used
   only in `app/offline/` (training, evaluation). `tests/test_labels.py` enforces this.
4. **Replayable decisions.** Detector `classify()` and `gates()` must stay pure functions of
   (features, context, thresholds). Every alert stores all features, thresholds, context, model
   version and config hash. Calibration is stored as two floats so replays are exact.
5. **Pluggable detectors.** New threat class = feature extractor in `enclave/features/`, detector
   subclass in `enclave/detectors/`, register in `make_extractors()` and `make_detectors()`.
6. **Honest numbers.** Quote throughput only from `reports/benchmark.json`, accuracy only from
   `reports/metrics.json`.
7. **Humans decide.** The system informs; it never blocks or acts on traffic.

Layout: `backend/` (Python 3.10+, FastAPI, scikit-learn), `frontend/` (React + Vite + Tailwind v4).
Checks before finishing: `cd backend && pytest` and `cd frontend && npm run build && npm run lint`.
