# Continuous AI assurance

Implementation: `backend/app/enclave/assurance/`. Runs inside the enclave, makes no outbound connections.

## 1. Decision trace (`trace.py`)
Each alert stores model name + version, config hash (SHA-256 of the `detection:` section),
data window, ALL feature values, thresholds, gate context and the raw model score.
`POST /api/alerts/{id}/replay` reloads the exact model version file, re-scores the stored
features, re-applies the class rule and gates, and reports which checks matched.

## 2. Health signals (`monitor.py`, every `check_interval_s` of event time)
| Signal | How | Component score |
|---|---|---|
| Feature drift | PSI of each feature over the last `drift_window_s`, using only rows the model judged normal (attacks are not drift), against quantile bins of benign training rows. Signal = mean of the 3 largest PSIs. | 1 below `warn/2`, 0 at `2.5×warn`, linear between |
| Alert volume | alerts in the window ÷ expected (training baseline rate × window, floor 1) | 1 inside `alert_volume_band`; above → falls to 0 at 4× the upper bound; below (only when ≥ 3 expected) → at most halves |
| Live FP rate | analyst "false positive" share once `min_feedback` labels exist | `1 − rate/0.5` |

Trust score = 100 × weighted mean of the components that have enough data (`trust_weights`).
No component with data → "insufficient data".

## 3. Assurance alerts (`assurance_alerts.py`)
Raised when trust < `trust_alert_below`; at most one open alert per detector (worse scores
update it); resolved when trust ≥ `trust_recover_above`.

## Demo
`python scripts/make_dataset.py --scenario drift` creates traffic where, from minute 5, a new
telemetry service polls every 60 s from 24 hosts and web transfer sizes grow. The beaconing
detector both drifts (size features) and over-alerts, its trust falls far below 70 and one
assurance alert is raised. Tests: `tests/test_assurance.py`.

Mapping: ISO/IEC 42001 (operation and monitoring of AI systems), NIST AI RMF MEASURE/MANAGE
(post-deployment monitoring, traceability).
