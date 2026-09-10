# IoT Defense

## Purpose
This project implements a modular, agent-based cyber-defense framework for residential IoT networks, demonstrating the end-to-end flow:

Mininet IoT Network -> Monitoring Agent -> Feature Extraction -> Detection Agent -> Decision Agent -> Response / Deception -> Observability / Metrics.

For a research-style comparison of the 3-policy system against simpler baselines on real Mininet trials -- methodology, results, and honest limitations -- see [EVALUATION.md](EVALUATION.md).

## Current architecture
- Mininet network simulation (5 hosts: sensor, camera, smart plug, attacker, decoy)
- Monitoring agent for packet observations
- Feature extraction pipeline (12 behavioural `FlowFeatures` columns)
- **Attack scenario registry** (`src/iot_defense/attacks/registry.py`) — a single `AttackScenario` definition per attack type. Every dependent module (detection, decision policy, the Stackelberg payoff lookup, PPO's observation encoding, dataset generation, the demo controller) derives its per-attack behaviour from this one registry instead of hardcoding it separately in each place.
- Attack-type-agnostic rule-based detection layer (`UnifiedRuleBasedDetector`) — classifies captured traffic purely from its shape (rate, port diversity, payload size), never from which attack was requested
- Decision agent comparing three independent policies (rule-based, Stackelberg game-theoretic, PPO reinforcement-learned) for response selection
- Response/deception handlers, all executing real changes inside the Mininet network (real interface isolation, real decoy redirection, real connection-rate limiting)
- Logging and metrics collection

## Environment
- Ubuntu 24.04.4 LTS
- Python 3.12.3
- Mininet 2.3.0
- Open vSwitch 3.3.9

## Attack types
Five attack types are currently registered, selectable at demo start via `--attack <key>`:

| Key | Label | Signature | Preferred response |
|---|---|---|---|
| `reconnaissance` | Port scan | Many destination ports, moderate rate | `DECOY` |
| `dos` | DDoS flood | Single port, very high packet rate | `ISOLATE` |
| `brute_force` | Credential stuffing | Single port, moderate sustained rate, many attempts | `THROTTLE` |
| `exfiltration` | Data exfiltration | Reversed direction (device → attacker), few packets, large payloads | `ISOLATE` |
| `exploit` | Exploit payload injection | Single port, few packets, unusually large payload | `DECOY` |

`exploit` is DECOY's second scenario: reconnaissance's decoy only observes a scan already known to be harmless probing, while this one redirects an unconfirmed, potentially dangerous payload away from the real device and captures it for analysis — a genuinely different reason to prefer deception, not the same one repeated.

Adding a new attack means adding one `AttackScenario` entry to the registry, plus its own traffic generator and rule-based detector — not touching every dependent file by hand.

## Defense actions
Five actions are available to all three decision policies: `ALLOW`, `ALERT`, `ISOLATE`, `DECOY`, `THROTTLE`. `THROTTLE` rate-limits new incoming connection attempts to a target via a real `iptables hashlimit` rule — not a bandwidth cap (an earlier `tc qdisc`-based approach was built, measured against real traffic, and found to have no real effect: a single SYN packet is too small for byte-rate shaping to meaningfully delay, and egress shaping doesn't touch incoming traffic at all). Verified against real Mininet traffic: an unthrottled attacker completed 56/56 connection attempts in a 3-second window; the same traffic under a 2/sec hashlimit completed only 7.

## PPO reinforcement-learned policy
The PPO environment uses a deterministic normalized security-context observation and a five-action mapping: `ALLOW=0`, `ALERT=1`, `ISOLATE=2`, `DECOY=3`, `THROTTLE=4`. Reward coefficients are modelling assumptions, not objective security values.

Two training passes exist:

1. **Synthetic base training** — fast, deterministic, never touches Mininet:
   ```bash
   python -m iot_defense.simulation.train_ppo --timesteps 3000 --output models/ppo_defense
   ```
2. **Real-Mininet fine-tuning** — loads the synthetic model as a warm start and continues training against `RealMininetDefenseEnv`, where every step's reward comes from an actually-executed, actually-verified Mininet outcome (a real ping check for `ISOLATE`, a real redirected connection for `DECOY`, a real installed-rule check for `THROTTLE`) rather than an assumed reward table. Each step costs several real seconds, so this is intentionally bounded (tens of timesteps, not thousands):
   ```bash
   sudo .venv/bin/python3 -m iot_defense.simulation.train_ppo_real \
       --base-model models/ppo_defense --output models/ppo_defense_real --timesteps 64
   ```
   Saves to a separate file by default and never silently overwrites the deployed model — promote it manually (copy over `models/ppo_defense.zip`) only after verifying it behaves sensibly across all five scenarios.

The generated models are ignored by Git. `PPODefensePolicy` fails clearly when a model is absent unless an explicit fallback policy is provided. The trained policy should not be interpreted as learning real-world attacker behaviour or general autonomous cyber defense — it is a bounded, controlled-environment demonstration.

## Controlled ML detection experiment
A reproducible controlled dataset and Random Forest detector. The dataset-generation pipeline (`ml/generate_dataset.py`, `ml/schema.py`) is registry-driven and covers all five registered attacks (6 classes with `normal`). Generate labelled rows from fresh Mininet runs with:

```bash
sudo .venv/bin/python3 -m iot_defense.ml.generate_dataset --runs 150 --seed 42 \
    --output data/ml/controlled_flows_6class.csv
```

Train and evaluate on run-held-out groups with:

```bash
sudo .venv/bin/python3 -m iot_defense.ml.train_random_forest \
    --dataset data/ml/controlled_flows_6class.csv \
    --model models/random_forest_detector.joblib --seed 7
```

The model uses only the 12 behavioural `FlowFeatures` columns; IP addresses, run identifiers, timestamps, metadata, and labels remain audit fields. The rule-based comparison baseline reported alongside RF's own metrics uses the same `UnifiedRuleBasedDetector` the live demo calls, scored on the identical multi-class labels — not a separate binary question. This remains a small, controlled Mininet study; its held-out metrics must not be generalized to arbitrary IoT traffic. In the live demo, the trained RF model is consulted only as a confirmation step when the rule-based detector independently concludes reconnaissance — the one signature with the fuzziest rule-based boundary; every other registered attack has been proven reliable across many live Mininet runs without needing RF confirmation. Because RF is a confirmation step and not a second vote, it may only override the rule-based verdict when it agrees, or disagrees with real confidence (≥70%) — a low-confidence disagreement never downgrades an already-detected attack to "normal".

The currently deployed `data/ml/controlled_flows_6class.csv` and `models/random_forest_detector.joblib` cover all six classes, perfectly balanced (156 rows, 26 per class: normal + reconnaissance/dos/brute_force/exfiltration/exploit). On a held-out test split (22 rows) RF reaches 100% accuracy against a rule-based baseline of 86.4% — a real, trustworthy gap now that every traffic generator behind the dataset delivers its intended payload (see "Known limitations" below for the two traffic-generator payload-delivery bugs this figure depends on having fixed).

## Planned future components
- A genuinely new detection dimension (e.g. inter-arrival timing regularity) to support attacks that aren't a traffic-volume pattern at all, such as malware C2 beaconing
- ARP spoofing / MITM detection (needs tracking IP-to-MAC mappings over time, not flow statistics — architecturally distinct from every attack currently registered)
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
PYTHONPATH=src uvicorn iot_defense.dashboard.server:app --host 0.0.0.0 --port 8000
```
Then open **http://<host>:8000** in a browser.

### Run the live demo (requires Mininet, typically sudo)
```bash
cd /home/abdullah/iot-defense
sudo .venv/bin/python3 -m iot_defense.demo.controller --attack <reconnaissance|dos|brute_force|exfiltration|exploit>
```
Omit `--attack` to be prompted interactively. The dashboard server and the demo process share `data/dashboard/state.json` and the controller's SSE event queue when run together as one process; run the dashboard server itself with the demo controller instantiated once (as `server.py` does) so browser clients observe the same controller instance.

### Dashboard sections
Header (phase, connection status, attack-mode badge, clock) · pipeline flow strip · network topology (5-node SVG: sensor, camera, smart plug, attacker, decoy) · live packet feed · threat detection panel with flow features · BDI-style security context (beliefs / desires / intention) · policy comparison (Rule-Based, Stackelberg, PPO) with selected action, generic over however many actions are registered · response & containment (decoy / isolation / rate-limit / restoration detail) · event timeline · metrics.

### Live demo sequence
1. `STARTING_NETWORK` — Mininet topology comes up, all 5 nodes go `ONLINE`.
2. `BASELINE` / `OBSERVING` — benign traffic is generated and captured; a normal `ThreatEvent` is built and `ALLOW`ed.
3. `THREAT_DETECTED` / `DECIDING` — the selected attack's real traffic is generated and captured; Rule-Based, Stackelberg, and PPO policies are each evaluated against the same `SecurityContext`, without being told which attack was requested.
4. `RESPONDING` → `DECOY_ACTIVE` / `ISOLATED` / `THROTTLED` — the selected action is actually executed inside Mininet (decoy redirect, interface isolation, or connection-rate limiting).
5. `RESTORING` → `RESTORED` — connectivity is verified and restored.
6. `COMPLETE` → `CLEANUP` — Mininet and any redirect/isolation/rate-limit state are torn down.

### Cleanup
The controller's `cleanup()` tears down the response executor (removing any iptables redirect/rate-limit rules and restoring isolated interfaces) and stops the Mininet network on completion or on error. If a run is interrupted, `sudo mn -c` clears any leftover Mininet state.

### Known limitations
- The dashboard is read-only by design — scenarios are triggered from the terminal via `DemoController`, not from browser buttons, to avoid duplicating attack/defense logic in JavaScript.
- The Random Forest detector reflects a preliminary evaluation on a small controlled Mininet dataset (156 rows across 6 classes; see "Controlled ML detection experiment" above) and should not be generalized to arbitrary IoT traffic.
- The PPO policy's base training is a lightweight synthetic decision simulator, not live Mininet traffic. A bounded real-Mininet fine-tuning pass exists and has been run (see "PPO reinforcement-learned policy" above), but it is a short, warm-started refinement on top of the synthetic policy, not training from scratch against real traffic.
- Stackelberg utilities are configured/modelled values (see `config/policies.yaml`), not measured real-world costs.
- Only two attack signatures (reconnaissance, credential-stuffing) are genuinely distinguished by connection *rate/pattern*; the flood and exfiltration signatures rely more heavily on volume and direction, and `exploit` relies on payload size rather than any of those. A malware C2 beaconing attack or similar timing-based signature is not currently detectable — it would need a new flow feature (inter-arrival timing regularity) this project doesn't compute yet.
- `exploit`'s rule-based detector separates a single oversized request from ordinary low-volume traffic almost entirely by `average_packet_size` — packet_count and port diversity alone overlap with real observed normal-traffic values, so this signature has the least headroom of any currently registered detector if normal traffic patterns ever shift. A live capture of `generate_exploit_mininet_traffic` measured `average_packet_size=442` against a detection window of 250-550 and real normal traffic's observed max of 111.6 (see `data/ml/controlled_flows_6class.csv`) — real margin on both sides today, not a coin flip, but a narrower gap than the other four attacks have.

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
