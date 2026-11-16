# Datasheet

## Synthetic traffic (default)
- **Generator**: `backend/app/generator/scenario.py`, seeded (same seed → same data).
- **Content**: NetFlow-like metadata records: timestamp, src/dst IP and port, protocol, TCP flags,
  packets, bytes; DNS records add query name, type and response code. No payloads.
- **Addresses**: 10.0.0.0/8 internal; 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 external;
  198.18.0.0/15 for spoofed sources (all reserved ranges).
- **Names**: `.example` / `.test` / `.invalid` pseudo-domains unless `data/benign_domains.txt` is provided.
- **Ground truth**: per-record `label` + `attack_id`, and `<file>.labels.json` episodes.
- **Files**: `train.jsonl` (2 h), `scenario_01.jsonl`, `evasion.jsonl`, `drift_scenario.jsonl`, `benign_scenario.jsonl` (30 min each).

## Benign domain list (optional)
| Name | Version / date | Licence | Citation |
|---|---|---|---|
| e.g. Tranco top sites | TODO | TODO | TODO |

## Public datasets (optional)
| Dataset | Version | Licence | Citation | Local path |
|---|---|---|---|---|
| CIC-DDoS2019 | TODO | per provider's terms | TODO | data/raw/cic-ddos2019 |
| CTU-13 | TODO | TODO | TODO | data/raw/ctu-13 |
| CIC-Bell-DNS-2021 | TODO | TODO | TODO | data/raw/cic-bell-dns-2021 |

Convert with `python scripts/make_dataset.py --source public --path data/raw/<name>`.
