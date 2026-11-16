# Training and validation

1. `make_dataset.py` writes seeded synthetic traffic with attack episodes (ground truth in
   `*.labels.json`). Training data: 2 h with randomised episodes, plus benign hard negatives
   (flash crowds, exactly periodic NTP, irregular app polling, jittery chat heartbeats).
2. `train.py` replays the training file through the SAME feature extractors used live, then
   labels each feature row by matching it to an episode (entity + time overlap).
3. **Time-based split** per detector: first 60 % of the timeline trains a RandomForest, the
   next 20 % fits Platt calibration, the last 20 % is the test set (`metrics.test`). No random split.
4. Allowlisted destinations are removed from training (they are suppressed by a gate anyway).
5. Drift baselines: quantile bins of each feature over complete, benign, training rows.
6. Alert-volume baseline: the full pipeline (gates + dedup) is run over the later 40 % of the
   training timeline and alerts per minute are stored with each model.

`evaluate.py` then runs the full pipeline on held-out files generated with other seeds:
`scenario_01` (one of each attack + a flash crowd), `evasion` (slow-and-low flood, heavily
jittered beacon, low-rate tunnel) and `benign_scenario`. It reports per-class recall
(episodes detected), alert precision, false alerts per hour, detection latency and a
confusion matrix, in `reports/metrics.json`.

**Read the numbers honestly.** The synthetic data is cleaner than real traffic, so near-perfect
scores here do not transfer. The evasion set is expected to be missed in part; that is the point.
