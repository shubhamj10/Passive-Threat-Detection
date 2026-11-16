# Decisions

| Date | Decision | Why |
|---|---|---|
| 2026-11 | RandomForest + Platt calibration for all detectors; xgboost not used | Fast on a laptop CPU, no extra native dependency, works with SHAP TreeExplainer |
| 2026-11 | SHAP optional (`requirements-optional.txt`); fallback = importance × standardised deviation | `pip install shap` can fail on some machines; evidence method is recorded per alert |
| 2026-11 | Calibration stored as two floats | Bit-exact replay across sklearn versions |
| 2026-11 | Shared `Engine` for live, evaluation, benchmark and tests | Offline numbers describe the live code path |
| 2026-11 | Records are NetFlow-like flow records, batched in UDP datagrams | Realistic for TAP-fed sensors; keeps Python throughput reasonable |
| 2026-11 | Drift measured on rows judged normal, against benign training rows | Attacks are not drift; a quiet network must not look "drifted" |
| 2026-11 | Low alert volume at most halves the volume component | Silence is weaker evidence of model failure than a flood; keeps benign runs above threshold |
| 2026-11 | Added `app/offline/` and `app/config.py` beyond the README tree | Shared code for scripts and tests, kept out of the detection path |
| 2026-11 | Spoofed sources use 198.18.0.0/15 | Reserved range large enough for realistic source entropy |
