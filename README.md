# Passive AI Threat Detection for Unidirectional IP Traffic

An AI/ML pipeline that detects cyber threats from a **one-way copy** of network traffic (as provided by a TAP, SPAN port or hardware data diode). The detection system runs inside a monitoring enclave, can **never send anything back** to the traffic source or destination, and works from **metadata only** (no payload decryption).

It detects three threat classes and shows alerts, with severity, confidence and evidence, on a live dashboard:

| Threat | How it is detected |
|---|---|
| DDoS (SYN flood, UDP reflection, spoofed-source flood) | Flow rate and source-IP entropy statistics |
| Botnet C2 beaconing | Inter-arrival time and periodicity analysis |
| DGA domains and DNS tunnelling | Entropy, n-gram and query-pattern analysis of DNS names |

It also includes **continuous AI assurance**: every alert can be traced and replayed, each detector's health is monitored after deployment, and the system raises an **assurance alert** when one of its own models stops being reliable. See [AI Assurance: continuous monitoring](#ai-assurance-continuous-monitoring).

> This is a software-only prototype. The one-way link is simulated in software. In a real deployment the software sits behind the customer's TAP or hardware data diode.

---

## Table of contents

1. [Architecture](#architecture)
2. [Project structure](#project-structure)
3. [Prerequisites](#prerequisites)
4. [Quick start](#quick-start)
5. [Backend setup (Python)](#backend-setup-python)
6. [Frontend setup (React + Tailwind CSS)](#frontend-setup-react--tailwind-css)
7. [Dataset handling](#dataset-handling)
8. [Train, evaluate, benchmark](#train-evaluate-benchmark)
9. [Configuration](#configuration)
10. [API overview](#api-overview)
11. [AI Assurance: continuous monitoring](#ai-assurance-continuous-monitoring)
12. [Testing and the read-only proof](#testing-and-the-read-only-proof)
13. [Troubleshooting](#troubleshooting)
14. [Design constraints](#design-constraints)

---

## Architecture

```
[Traffic generator / PCAP replay]      "production side" (simulated)
        |  one-way UDP on localhost    software data diode
        v
[Receive-only ingest] -> [Flow normaliser] -> [Stream queue]
        v
[Windowed features] -> [Detectors: DDoS | Beaconing | DNS]
        v
[Calibration + SHAP evidence] -> [Validation gates] -> [Alert builder + decision trace]
        v                                                   |
[SQLite alert store] <---- [Assurance monitor: drift | alert volume | analyst FP rate
        |                   -> trust score per detector -> assurance alerts]
        v
[FastAPI REST + WebSocket]  ---->  [React dashboard]
        v (optional, background, redacted alerts only)
[Azure OpenAI explainer]
```

- **ML models** inside the enclave decide whether traffic is an attack.
- **The assurance monitor** watches the models themselves and warns when a detector may no longer be reliable. It runs inside the enclave and makes no outbound connections.
- **The optional Azure OpenAI assistant** only explains finished alerts. It never detects anything and never runs on the detection path.

---

## Project structure

Backend and frontend are separate folders and are run separately.

```
passive-threat-detection/
├── README.md
├── CLAUDE.md                     # build specification for Claude Code
├── .gitignore
├── .env.example                  # copy to backend/.env
│
├── backend/                      # everything Python
│   ├── requirements.txt
│   ├── config.yaml               # subnets, windows, thresholds, time_scale, throughput target
│   ├── run_all.py                # starts generator + pipeline + API
│   ├── app/
│   │   ├── generator/            # traffic generator and UDP sender ("production side")
│   │   ├── enclave/
│   │   │   ├── diode/            # receive-only socket
│   │   │   ├── ingest/           # record parsing, flow normaliser, optional PCAP reader
│   │   │   ├── pipeline/         # stream queue, event-time windowing
│   │   │   ├── features/         # ddos.py, beacon.py, dns.py
│   │   │   ├── detectors/        # base.py, ddos.py, beacon.py, dns.py
│   │   │   ├── scoring/          # calibration, SHAP evidence, severity
│   │   │   ├── alerts/           # schema, builder, dedup, SQLite store
│   │   │   └── assurance/        # trace.py, drift.py, trust.py, assurance_alerts.py
│   │   ├── api/                  # FastAPI app, REST routes, WebSocket
│   │   └── assistant/            # optional Azure OpenAI explainer + offline fallback
│   ├── scripts/                  # make_dataset.py, train.py, evaluate.py, benchmark.py
│   ├── data/
│   │   ├── benign_domains.txt    # you provide (optional but recommended)
│   │   ├── raw/                  # downloaded public datasets (git-ignored)
│   │   ├── synthetic/            # generated traffic + labels (git-ignored)
│   │   └── processed/            # feature tables for training (git-ignored)
│   ├── models/                   # trained model files + metadata + training baselines for drift
│   ├── reports/                  # metrics.json, benchmark.json (generated)
│   └── tests/
│
├── frontend/                     # React + Tailwind CSS dashboard
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   └── src/
│       ├── main.jsx
│       ├── App.jsx
│       ├── index.css             # Tailwind import
│       ├── api/                  # REST client and WebSocket hook
│       ├── components/           # AlertFeed, SeverityBadge, ConfidenceBar, charts, panels
│       ├── pages/                # Dashboard, AlertDetail, Replay
│       └── hooks/
│
└── docs/
    ├── architecture.md
    ├── features.md
    ├── training_validation.md
    ├── readonly_proof.md
    ├── limitations.md
    ├── risk_register.md
    ├── datasheet.md
    ├── continuous_assurance.md
    ├── DECISIONS.md
    └── model_cards/
```

---

## Prerequisites

| Tool | Needed for | Check with |
|---|---|---|
| Python 3.10 or newer | Backend and ML | `python --version` |
| Node.js (current LTS) and npm | Frontend | `node --version` |
| Git | Version control | `git --version` |

No Docker, GPU or special hardware is required.

---

## Quick start

Open **two terminals**.

**Terminal 1: backend**

```bash
cd backend
python -m venv .venv
# activate: see "Backend setup" below for your OS
pip install -r requirements.txt
cp ../.env.example .env            # Windows PowerShell: Copy-Item ..\.env.example .env
python scripts/make_dataset.py     # generate synthetic data
python scripts/train.py            # train and save models
python run_all.py --mode demo      # start generator + pipeline + API on http://localhost:8000
```

**Terminal 2: frontend**

```bash
cd frontend
npm install
npm run dev                        # dashboard on http://localhost:5173
```

Open the dashboard at `http://localhost:5173`. You should see alerts appear as simulated DDoS, beaconing and DNS attacks are injected.

---

## Backend setup (Python)

Create the virtual environment **inside `backend/`**.

**Windows (PowerShell):**
```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```
If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.

**macOS / Linux:**
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Notes:
- Activate the virtual environment in every new terminal before running backend commands.
- `.venv/` is git-ignored.
- To leave the environment, run `deactivate`.
- Optional libraries (`shap` for SHAP evidence, `scapy` for PCAP reading, `openai` for the Azure assistant) are guarded imports, so the project runs without them. Install them with `pip install -r requirements-optional.txt`.

Run the backend pieces individually if needed:

```bash
uvicorn app.api.main:app --reload --port 8000   # API only
python run_all.py --mode demo                    # generator + pipeline + API
python run_all.py --mode replay --file data/synthetic/scenario_01.jsonl
```

---

## Frontend setup (React + Tailwind CSS)

The dashboard is a React app built with Vite and styled with Tailwind CSS. Only follow the creation steps below if the `frontend/` folder does not exist yet. If Claude Code has already generated it, run `npm install` and `npm run dev`.

```bash
# from the project root
npm create vite@latest frontend -- --template react
cd frontend
npm install
npm install tailwindcss @tailwindcss/vite
```

Add the Tailwind plugin in `frontend/vite.config.js`:

```js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8000',
      '/ws': { target: 'ws://localhost:8000', ws: true },
    },
  },
})
```

Import Tailwind at the top of `frontend/src/index.css`:

```css
@import "tailwindcss";
```

Then run:

```bash
npm run dev       # development server
npm run build     # production build in frontend/dist
```

If these commands differ for your Tailwind version, follow Tailwind's official "Install with Vite" guide.

**Dashboard features:** live alert feed, severity badges and confidence bars, per-threat panels (DDoS, beaconing, DNS), timeline, top talkers, alert detail with evidence and SHAP features, throughput and latency widget, replay controls, and an IP pseudonymise toggle. An **AI Assurance panel** shows the trust score for each detector, its trend, and any open assurance alerts.

---

## Dataset handling

There are two kinds of data. The project works with synthetic data alone.

| Data | Who provides it | Location |
|---|---|---|
| **Synthetic traffic** (benign background plus injected DDoS, beaconing, DGA/tunnelling, with ground-truth labels) | Generated by the project | `backend/data/synthetic/` |
| **Benign domain list** (improves the DGA detector) | You download it | `backend/data/benign_domains.txt` |
| **Public datasets** (optional, to strengthen evaluation) | You download them | `backend/data/raw/<dataset_name>/` |
| **Processed training tables** | Created by scripts | `backend/data/processed/` |

### Generate synthetic data

```bash
cd backend
python scripts/make_dataset.py --seed 42
python scripts/make_dataset.py --seed 42 --scenario drift   # optional: changed traffic pattern for the assurance demo
```

The generator is seeded, so the same seed recreates the same dataset. Do not commit generated data to git.

### Add a benign domain list (recommended)

1. Download a top-sites list such as the Tranco list from its official site.
2. Save one domain per line as `backend/data/benign_domains.txt`.

If the file is missing, the project uses a built-in pseudo-benign name generator and logs a warning. Real domain names make the DGA detector more credible.

### Add public datasets (optional)

Examples: CIC-DDoS2019, CTU-13, CIC-Bell-DNS-2021, and published DGA domain lists.

1. Download from the project's **official page**. Large files are common (several GB).
2. Read and follow the dataset's **licence and citation terms**.
3. Place the files in `backend/data/raw/<dataset_name>/`.
4. Convert to the project's record format:

```bash
python scripts/make_dataset.py --source public --path data/raw/<dataset_name>
```

Record dataset names, versions and licences in `docs/datasheet.md`.

### Data rules

- Ground-truth `label` fields are used **only** for training and evaluation. The ingest path strips them before detectors see any record.
- Never store payloads. Only metadata (IPs, ports, flags, sizes, timings, DNS names).
- Use reserved example addresses (`10.0.0.0/8`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and `example.com`-style names in synthetic data.
- Never commit anything under `data/raw/`, `data/synthetic/` or `data/processed/`.

---

## Train, evaluate, benchmark

Run from `backend/` with the virtual environment active.

```bash
python scripts/train.py        # build features, train, calibrate, save to models/ (also saves drift baselines)
python scripts/make_dataset.py --scenario benign   # optional: pure-benign file used by evaluate.py
python scripts/evaluate.py     # time-based evaluation, writes reports/metrics.json
python scripts/benchmark.py    # throughput and latency, writes reports/benchmark.json
```

- **Time-based split:** train on earlier traffic, validate on the middle, test on the latest. Random splits are not used.
- **Metrics:** per-class precision, recall, F1, false-positive rate, detection latency and confusion matrix.
- **Evasion tests:** jittered beacons, slow-and-low floods and low-rate DNS tunnelling are tested and reported honestly.
- Training uses small tree and linear models and runs on a laptop CPU in seconds to minutes.
- **Throughput:** quote only numbers from `reports/benchmark.json`, together with the machine details it records. The target in `config.yaml` is a goal, not a result.

---

## Configuration

**`backend/.env`** (copy from `.env.example`; never commit):

```
# API
API_HOST=127.0.0.1
API_PORT=8000
ALLOWED_ORIGINS=http://localhost:5173

# Optional Azure OpenAI assistant (leave empty to use the offline fallback)
AZURE_OPENAI_ENDPOINT=
AZURE_OPENAI_API_KEY=
AZURE_OPENAI_DEPLOYMENT=
AZURE_OPENAI_API_VERSION=
```

**`backend/config.yaml`:** internal subnets, window sizes, detector thresholds, validation gates, `time_scale` for fast replays, and throughput targets. Thresholds are starting values and must be tuned on your data.

It also holds the assurance settings:

```yaml
assurance:
  check_interval_s: 60          # how often the assurance monitor runs
  drift_psi_warn: 0.2           # feature drift (PSI) above this lowers the trust score
  alert_volume_band: [0.2, 5.0] # alert count outside 0.2x to 5x the baseline is suspicious
  min_feedback: 20              # analyst labels needed before the live FP rate is used
  trust_weights: {drift: 0.4, volume: 0.2, feedback_fp: 0.4}
  trust_alert_below: 70         # raise an assurance alert under this score
```

The Azure OpenAI assistant is optional. Without a key the dashboard still works and uses template explanations. When enabled, it receives only redacted alert summaries (pseudonymised IPs, no payloads, no raw traffic).

---

## API overview

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | Service health |
| `GET /api/alerts` | List alerts (filter by severity or threat class) |
| `GET /api/alerts/{id}` | Alert detail with evidence |
| `GET /api/stats` | Counts, flows/s, p95 latency, queue depth |
| `POST /api/alerts/{id}/feedback` | Analyst marks true or false positive |
| `POST /api/replay/start`, `/pause`, `/speed` | Demo replay controls |
| `POST /api/alerts/{id}/replay` | Re-run the alert's decision trace and confirm the same result |
| `GET /api/assurance/status` | Trust score and health signals for each detector |
| `GET /api/assurance/alerts` | Open and past assurance alerts |
| `WS /ws/alerts` | Live alert stream (threat and assurance alerts) |

### Alert schema

```json
{
  "alert_id": "a-20261021-000123",
  "timestamp": "2026-10-21T10:15:32.412Z",
  "flow_id": "10.1.2.3:51514->198.51.100.7:443/TCP",
  "threat_class": "botnet_c2_beaconing",
  "severity": "high",
  "confidence": 0.91,
  "model": {"name": "beacon_scorer", "version": "1.0.0"},
  "evidence": {
    "features": {"interarrival_cv": 0.04, "events": 42},
    "thresholds": {"interarrival_cv": 0.15, "min_events": 8},
    "gates_passed": ["min_evidence", "persistence", "not_allowlisted"],
    "top_shap_features": ["interarrival_cv", "size_cv"]
  },
  "trace": {
    "config_hash": "sha256:9f2c...e41a",
    "data_window": {"start": "2026-10-21T10:10:32Z", "end": "2026-10-21T10:15:32Z"},
    "detector_trust_score": 92
  },
  "mitre_attack": "T1071",
  "recommended_action": "Analyst review: investigate source host",
  "ai_explanation": null
}
```

The `model` and `trace` fields together form the **decision trace** (see below).

---

## AI Assurance: continuous monitoring

Testing a model before launch only shows it worked on the data available at that time. Real networks keep changing: new apps, new cloud services, new attacker techniques. A detector that scored well at launch can quietly get worse over the following months, and nobody notices because it keeps producing alerts.

**Continuous assurance** means checking the models after they go live, not just before. Pre-launch testing is the crash test. Continuous assurance is the dashboard warning lights and the service history.

It has three parts.

### 1. Decision trace (the "black box recorder")

Every alert saves exactly what produced it:

| Field | What it records | Example |
|---|---|---|
| Model version | Which version of which detector | `beacon_scorer 1.0.0` |
| Config hash | Fingerprint of the settings and thresholds in use | `sha256:9f2c...e41a` |
| Feature values | The numbers the model saw | `interarrival_cv 0.04` over `42` events |
| Data window | The exact time slice of traffic analysed | `10:10:32` to `10:15:32` UTC |

**Why it matters:** if an auditor asks months later why an alert fired, or an analyst says it was wrong, the alert can be replayed with the same data, model and settings to get the same result:

```bash
curl -X POST http://localhost:8000/api/alerts/a-20261021-000123/replay
```

Every decision can be reproduced and defended.

### 2. Drift and trust monitoring (the "health check")

The assurance monitor watches three signals for each detector:

| Signal | Question it answers | Example of a problem |
|---|---|---|
| **Feature drift** | Does today's traffic look statistically different from the training data? | A new video service changes normal flow sizes, so the model sees traffic it was never trained on |
| **Alert volume** | Is the detector behaving unusually? | The DDoS detector usually raises 5 alerts a day, then suddenly raises 200 or drops to zero |
| **Live false-positive rate** | How accurate is it in the real world, according to analysts? | 40% of beacon alerts are being marked as false positives |

These combine into one **trust score (0 to 100) per detector**, for example DDoS 92, Beacon 61, DNS 88, shown on the dashboard. Analysts can see at a glance which detectors to trust today. Weights and limits are set in `config.yaml` under `assurance`.

### 3. Assurance alerts (the "warning light")

Assurance alerts are separate from threat alerts:

- A **threat alert** says the network may be under attack.
- An **assurance alert** says one of the AI models may no longer be reliable.

For example, after a network change the beacon detector's trust score falls from 90 to 55, so the system raises an assurance alert:

```json
{
  "assurance_alert_id": "aa-20261104-000007",
  "timestamp": "2026-11-04T09:12:00Z",
  "detector": {"name": "beacon_scorer", "version": "1.0.0"},
  "trust_score": {"previous": 90, "current": 55, "threshold": 70},
  "signals": {"feature_drift_psi": 0.31, "alert_volume_ratio": 3.8, "feedback_fp_rate": 0.40},
  "recommended_action": "Review, retune or retrain beacon_scorer. Treat its alerts with extra caution and use manual review until resolved."
}
```

The team then knows to check that detector and retune or retrain it. In the meantime, they treat its alerts with more caution or rely on manual review. The system only reports; humans decide what to do.

### See it in the demo

```bash
python scripts/make_dataset.py --seed 42 --scenario drift
python run_all.py --mode replay --file data/synthetic/drift_scenario.jsonl
```

Watch the AI Assurance panel: the affected detector's trust score falls and an assurance alert appears on the dashboard.

### Why it matters

Most security AI stops at "the model has high accuracy". This system **knows when it is becoming unreliable and says so**. This matches what ISO/IEC 42001 and the NIST AI RMF expect: post-deployment monitoring, traceability and accountability. It maps to the **Monitoring** and **Explainability and Auditability** pillars of the AI Assurance Platform. Full details are in `docs/continuous_assurance.md`.

---

## Testing and the read-only proof

```bash
cd backend
pytest
```

Key tests:

- **Read-only ingest:** the receive-only socket raises an error on any send or connect attempt.
- **Static scan:** no module under `app/enclave/` imports network client libraries or opens outbound connections. Only `app/assistant/` may.
- **No label leakage:** detectors never read ground-truth labels.
- **Schema, features and gates:** unit tests for each.
- **End to end:** each of the three attack classes raises a correct alert, and a pure-benign run raises no high-severity alert.
- **Decision trace replay:** replaying a stored alert gives the same threat class, confidence and evidence.
- **Drift and trust:** the drift scenario lowers the affected detector's trust score, and a stable benign run keeps every score above the threshold.
- **Assurance alerts:** a trust score below `trust_alert_below` raises exactly one assurance alert, with no duplicates.

Software enforcement demonstrates the **design** is read-only. In production, real assurance comes from a hardware TAP or data diode. See `docs/readonly_proof.md`.

Frontend checks:

```bash
cd frontend
npm run build
npm run lint
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `python` not found or wrong version | Install Python 3.10+, and use `python3` on macOS/Linux |
| Activation blocked in PowerShell | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| `pip install` fails for `xgboost` or `shap` | The project falls back to scikit-learn models and feature-importance evidence. Note it in `docs/DECISIONS.md` |
| Dashboard shows no alerts | Check the backend is running on port 8000, run `make_dataset.py` and `train.py` first, and check `ALLOWED_ORIGINS` |
| Browser blocks API calls (CORS) | Make sure the Vite proxy is set in `vite.config.js` and `ALLOWED_ORIGINS` includes `http://localhost:5173` |
| UDP port already in use | Change the diode port in `config.yaml` |
| Windows Firewall prompt | Allow Python on private networks (localhost traffic only) |
| No Azure key | Leave the variables empty. The offline explainer is used |
| Trust score shows "insufficient data" | Normal at start-up. The live FP rate needs `min_feedback` analyst labels first |

---

## Design constraints

1. **Read-only ingest:** no return path, live query or inline blocking.
2. **No payload decryption:** metadata only, and payloads are never stored.
3. **Streaming, not batch:** incremental processing with bounded alert latency.
4. **Stated throughput:** measured by `scripts/benchmark.py` and reported from `reports/benchmark.json`.
5. **Standard alert schema:** timestamp, flow identifier, threat class, confidence score and supporting evidence.
6. **Human in the loop:** the system only informs. Analysts decide any action.
7. **Continuous assurance:** every alert is traceable and replayable, each detector has a live trust score, and the system flags its own models when they become unreliable.

---

## Known limitations

- DNS over HTTPS/TLS hides query names.
- Asymmetric routing means some flows are seen in one direction only.
- Synthetic data is simpler than real traffic, so accuracy on real networks must be validated separately.
- Scope is three threat classes. Port scanning, data exfiltration and TLS-metadata detection are future work. The detector interface is pluggable.

Full details are in `docs/limitations.md`.

---

## License and contributors

TODO: add licence and team members.
