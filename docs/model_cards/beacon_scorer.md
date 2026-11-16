# Model card: beacon_scorer 1.0.0
- **Task**: does this host pair show C2-like periodic check-ins over the last 10 minutes? (binary)
- **Model**: RandomForest + Platt calibration. Features: interval and size regularity (docs/features.md).
- **Training data**: synthetic, 2 h, includes benign periodic traffic (NTP allowlisted, chat heartbeats, pollers).
- **Gates**: ≥ `min_events`, span ≥ `min_span_s`, destination not allowlisted.
- **Known weaknesses**: heavy jitter (CV ≳ 0.3), long sleep intervals, legitimate new telemetry services (see drift demo).
- **Intended use**: inform analysts. Not for automatic blocking.
