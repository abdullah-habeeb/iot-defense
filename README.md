# IoT Defense

## Purpose
This project implements a modular, agent-based cyber-defense framework for residential IoT networks. The initial foundation is intentionally scoped to a working vertical slice that demonstrates the end-to-end flow:

Mininet IoT Network -> Monitoring Agent -> Feature Extraction -> Detection Agent -> Decision Agent -> Response / Deception -> Observability / Metrics.

## Current architecture
- Mininet network simulation
- Monitoring agent for packet observations
- Feature extraction pipeline
- Rule-based detection layer
- Decision agent for response selection
- Response/deception handlers
- Logging and metrics collection

## Environment
- Ubuntu 24.04.4 LTS
- Python 3.12.3
- Mininet 2.3.0
- Open vSwitch 3.3.9

## Current implementation status
The prototype now includes a validated Mininet traffic-to-response vertical slice, configurable Stackelberg policy reasoning, and a small CPU-only PPO policy trained on a standalone decision simulator. PPO does not train against Mininet traffic and does not execute responses; the live runner compares RuleBased, Stackelberg, and PPO decisions while retaining the existing response path.

The PPO environment uses a deterministic normalized security-context observation and a four-action mapping: `ALLOW=0`, `ALERT=1`, `ISOLATE=2`, and `DECOY=3`. Reward coefficients are modelling assumptions, not objective security values. Train a short model with:

```bash
python -m iot_defense.simulation.train_ppo --timesteps 512 --output models/ppo_defense
```

The generated model is ignored by Git. `PPODefensePolicy` fails clearly when it is absent unless an explicit fallback policy is provided. The trained policy should not be interpreted as learning real-world attacker behaviour or general autonomous cyber defense.

## Controlled ML detection experiment
Phase 6B adds a reproducible controlled dataset and Random Forest detector. Generate labelled rows from fresh Mininet runs with:

```bash
sudo -E env PYTHONPATH="/home/abdullah/iot-defense/.venv/lib/python3.12/site-packages:/home/abdullah/iot-defense/src" \
	/usr/bin/python3 -m iot_defense.ml.generate_dataset --runs 20 --seed 7 \
	--output data/ml/controlled_flows.csv
```

Train and evaluate on run-held-out groups with:

```bash
python -m iot_defense.ml.train_random_forest \
	--dataset data/ml/controlled_flows.csv \
	--model models/random_forest_detector.joblib --seed 7
```

The model uses only the 12 behavioural `FlowFeatures` columns; IP addresses, run identifiers, timestamps, metadata, and labels remain audit fields. The current experiment is a small synthetic Mininet study covering normal traffic and bounded reconnaissance scans, so its held-out metrics must not be generalized to arbitrary IoT traffic.

## Planned future components
- Random Forest / SVM detection models
- Broader learned detection and evaluation datasets
- PPO policy evaluation against measured scenarios
- Richer honeypot and deception flows
- Enhanced evaluation metrics and dashboards

## Dashboard

The dashboard is a read-only, browser-based operations console for observing the live pipeline during a demonstration. It is served by FastAPI and pushes updates to the browser over Server-Sent Events (SSE) — no React/Vue/Node/Docker/database, and no internet access is required to view it.

### Architecture
`DemoController` (in `src/iot_defense/demo/controller.py`) drives the real pipeline (Mininet network → traffic generation → packet capture → feature aggregation → detection → `SecurityContext` → policy comparison → response execution → restoration) and publishes every state change onto an in-process `asyncio.Queue`. `src/iot_defense/dashboard/server.py` exposes that state over HTTP/SSE and serves the static frontend from `data/dashboard/static/`. The dashboard never runs its own attack/defense logic — it only renders the controller's real state, falling back to "N/A" for any field that is absent.

### Prerequisites
```bash
cd /home/abdullah/iot-defense
source .venv/bin/activate
```
`fastapi`, `uvicorn`, and `httpx` are declared in `pyproject.toml` / `requirements.txt`.

### Start the dashboard server
```bash
cd /home/abdullah/iot-defense
source .venv/bin/activate
PYTHONPATH=src uvicorn iot_defense.dashboard.server:app --host 127.0.0.1 --port 8000
```
Then open **http://127.0.0.1:8000** in a browser.

### Run the live demo (requires Mininet, typically sudo)
```bash
cd /home/abdullah/iot-defense
source .venv/bin/activate
sudo -E env PYTHONPATH="$(pwd)/.venv/lib/python3.12/site-packages:$(pwd)/src"     "$(pwd)/.venv/bin/python" -m iot_defense.demo.controller
```
The dashboard server and the demo process share `data/dashboard/state.json` and the controller's SSE event queue when run together as one process; run the dashboard server itself with the demo controller instantiated once (as `server.py` does) so browser clients observe the same controller instance.

### Dashboard sections
Header (phase, connection status, clock) · pipeline flow strip · network topology (5-node SVG: sensor, camera, smart plug, attacker, decoy) · live packet feed · threat detection panel with flow features · BDI-style security context (beliefs / desires / intention) · policy comparison (Rule-Based, Stackelberg, PPO) with selected action · response & containment (decoy / isolation / restoration detail) · event timeline · metrics.

### Live demo sequence
1. `STARTING_NETWORK` — Mininet topology comes up, all 5 nodes go `ONLINE`.
2. `BASELINE` / `OBSERVING` — benign traffic is generated and captured; a normal `ThreatEvent` is built and `ALLOW`ed.
3. `THREAT_DETECTED` / `DECIDING` — a bounded reconnaissance port-scan is generated and captured; Rule-Based, Stackelberg, and PPO policies are each evaluated against the same `SecurityContext`.
4. `RESPONDING` → `DECOY_ACTIVE` or `ISOLATED` — the selected action is actually executed inside Mininet (decoy redirect or interface isolation).
5. `RESTORING` → `RESTORED` — connectivity is verified and restored.
6. `COMPLETE` → `CLEANUP` — Mininet and any redirect/isolation state are torn down.

### Cleanup
The controller's `cleanup()` tears down the response executor (removing any iptables redirect rules and restoring isolated interfaces) and stops the Mininet network on completion or on error. If a run is interrupted, `sudo mn -c` clears any leftover Mininet state.

### Known limitations
- The dashboard is read-only by design — scenarios are triggered from the terminal via `DemoController`, not from browser buttons, to avoid duplicating attack/defense logic in JavaScript.
- The Random Forest detector reflects a preliminary evaluation on a small controlled Mininet dataset (see "Controlled ML detection experiment" above) and should not be generalized to arbitrary IoT traffic.
- The PPO policy is trained in a lightweight simulated decision environment, not against live Mininet traffic; it does not execute responses directly.
- Stackelberg utilities are configured/modelled values (see `config/policies.yaml`), not measured real-world costs.

## Virtual environment
```bash
cd /home/abdullah/iot-defense
source .venv/bin/activate
```

## Run tests
```bash
cd /home/abdullah/iot-defense
source .venv/bin/activate
pytest -q
```
