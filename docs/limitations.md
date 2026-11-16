# Known limitations

- **Synthetic data is simpler than real traffic.** Accuracy on real networks must be validated separately.
- **Encrypted DNS** (DoH/DoT) hides query names; the DNS detector then sees nothing.
- **Asymmetric routing**: some flows are seen in one direction only; SYN-only ratios can mislead.
- **Base domain** uses the last two labels; real traffic needs a public-suffix list (e.g. `co.uk`).
- **Evasion**: slow-and-low floods under `min_flows`, beacons with heavy jitter (CV ≳ 0.3) or
  long intervals (< 8 events in 10 min), and low-rate DNS tunnels under `tunnel_min_queries`
  are missed by design of the gates. See `reports/metrics.json` → `alert_level.evasion`.
- **Flow records, not packets**: the generator emits NetFlow-like records; a PCAP reader is
  provided (needs scapy) but builds one record per packet.
- **Single process**: throughput is limited by one Python engine thread. See `reports/benchmark.json`.
- **Trust score** needs warm-up: drift needs `drift_min_samples` rows, volume needs
  `volume_min_elapsed_s`, feedback needs `min_feedback` analyst labels.
- **Scope**: three threat classes. Port scanning, exfiltration and TLS-metadata detection are future work.
