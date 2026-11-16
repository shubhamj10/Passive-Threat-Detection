# Risk register

| # | Risk | Impact | Mitigation | Owner |
|---|---|---|---|---|
| R1 | Enclave code gains an outbound path | Breaks the one-way guarantee | Receive-only socket, AST scan in CI, hardware diode in production | Engineering |
| R2 | Model degrades after network changes | Missed attacks or alert floods | Continuous assurance: drift, volume, feedback → trust score → assurance alert | SOC lead |
| R3 | Label leakage inflates metrics | False confidence | Labels stripped at ingest; label tests; time-based split; held-out seeds | ML |
| R4 | Attackers evade thresholds | Missed detections | Evasion tests reported; thresholds tunable; future sequence models | ML |
| R5 | Sensitive data sent to the LLM | Privacy breach | Assistant optional; redacted summaries, pseudonymised IPs, no domains/payloads | Security |
| R6 | Analysts over-trust the AI | Wrong actions | Human-in-the-loop, confidence + trust shown on every alert, plain explanations | SOC lead |
| R7 | Alert flood overwhelms analysts | Fatigue | Gates, deduplication cooldowns, severity levels, volume monitoring | SOC lead |
| R8 | Unreproducible decisions | Audit failure | Decision trace + replay endpoint, versioned model files, config hash | Engineering |
| R9 | Throughput claims overstated | Under-sized deployment | Quote only benchmark.json with machine details | Engineering |
