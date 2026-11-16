# Model card: dns_scorer 1.0.0
- **Task**: are this host's queries for one base domain in one minute DGA or tunnelling? (binary + rule for the class)
- **Model**: RandomForest + Platt calibration; character-bigram model built only from benign names.
- **Training data**: synthetic, 2 h; pseudo-benign `.example`/`.test` names unless a real list is provided.
- **Gates**: DGA ≥ `dga_min_domains` suspicious names per host per window; tunnelling ≥ `tunnel_min_queries`.
- **Known weaknesses**: DoH/DoT hides names; dictionary-word DGAs; low-rate tunnels; CDN hash subdomains.
- **Intended use**: inform analysts. Not for automatic blocking.
