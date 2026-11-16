# Model card: ddos_scorer 1.0.0
- **Task**: is this 10-second window of traffic to one internal destination a DDoS? (binary)
- **Model**: RandomForest (120 trees, depth 10) + Platt calibration. Features: see docs/features.md.
- **Training data**: synthetic, 2 h, time-based 60/20/20 split. Metrics: `models/ddos_scorer-1.0.0.meta.json`.
- **Gates**: ≥ `min_flows` flows, ≥ `persistence_windows` consecutive suspicious windows, not allowlisted.
- **Known weaknesses**: slow-and-low floods below `min_flows`; benign flash crowds can look similar.
- **Intended use**: inform analysts. Not for automatic blocking.
