# Features

All features are computed from metadata only.

## DDoS (`ddos_scorer`), per internal destination, 10 s window
| Feature | Meaning |
|---|---|
| flows | flow records to the destination |
| pkts_per_s | packets per second |
| bytes_per_pkt | mean packet size |
| unique_src | distinct source IPs |
| src_entropy | Shannon entropy (bits) of the source-IP distribution: spoofed floods are high |
| syn_only_ratio | TCP flows with SYN but no ACK |
| udp_ratio | UDP share |
| reflection_ratio | UDP flows from reflection ports (53, 123, 1900, 11211, ...) |
| unique_dst_ports | distinct destination ports (random-port floods are high) |
| flows_per_src | flows per source |

Subtype rule: `syn_flood` (syn_only_ratio ≥ 0.5), `udp_reflection` (UDP and reflection ≥ 0.5), else `volumetric_flood`.

## Beaconing (`beacon_scorer`), per (internal src, external dst, port), 600 s sliding window
| Feature | Meaning |
|---|---|
| events | connections in the window (candidate needs ≥ `min_events`) |
| interval_mean | mean time between connections |
| interval_cv | std / mean of intervals: beacons are very low |
| interval_mad_ratio | median absolute deviation / median: robust version |
| periodicity | share of intervals within ±10 % of the median |
| size_mean, size_cv | bytes per connection and its variation |
| span_s | first to last connection |
| pkts_mean | packets per connection |

## DNS (`dns_scorer`), per (internal src, base domain), 60 s window
| Feature | Meaning |
|---|---|
| n_queries, n_unique, unique_ratio | volume and repetition |
| mean_qname_len, max_label_len | long labels suggest encoded data (tunnelling) |
| sld_len, sld_entropy | length and character entropy of the registrable label |
| sub_entropy | entropy of the subdomain part |
| sld_bigram_ll | mean character-bigram log-likelihood under a model built ONLY from the benign domain list |
| digit_ratio | digits in the names |
| nx_ratio | NXDOMAIN share (DGA lookups mostly fail) |
| txt_ratio | TXT/NULL queries (tunnels favour them) |

Class rule: `dns_tunnelling` if max_label_len ≥ `tunnel_min_label_len` and sub_entropy ≥ 3, else `dga_domain`.
DGA alerts aggregate per host: at least `dga_min_domains` suspicious names in one window.

Base domain = last two labels (simplification; use a public-suffix list on real traffic).
