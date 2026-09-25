# IoT Defense

## Purpose
This project implements a modular, agent-based cyber-defense framework for residential IoT networks, demonstrating the end-to-end flow:

Mininet IoT Network -> Monitoring Agent -> Feature Extraction -> Detection Agent -> Decision Agent -> Response / Deception -> Observability / Metrics.

For a research-style comparison of the 3-policy system against simpler baselines on real Mininet trials -- methodology, results, and honest limitations -- see [EVALUATION.md](EVALUATION.md).

## Current architecture
- Mininet network simulation (5 hosts: sensor, camera, smart plug, attacker, decoy)
- Monitoring agent for packet observations
- Feature extraction pipeline (13 behavioural `FlowFeatures` columns -- 12 feed ML training; the 13th, `inter_arrival_cv`, is a deliberate scope boundary, see "Attack types" below)
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
Sixteen attack types are currently registered, selectable at demo start via `--attack <key>`. Every rule-based detector's numeric thresholds were hand-placed in a real, unclaimed gap between its neighbors' own thresholds (not guessed), and cross-checked two ways: a generic test runs every attack's own synthetic signature through the *complete* detector sweep (not just its own detector) and confirms no earlier-registered one claims it first, and real live Mininet runs (repeated across many rounds) confirm the same holds under real-world timing variance, not just on paper.

| Key | Label | Signature | Preferred response |
|---|---|---|---|
| `reconnaissance` | Port scan | Many destination ports, moderate rate | `DECOY` |
| `dos` | DDoS flood | Single port, very high packet rate | `ISOLATE` |
| `brute_force` | Credential stuffing | Single port, moderate sustained rate, many attempts | `BLOCK_SOURCE` |
| `exfiltration` | Data exfiltration | Reversed direction (device → attacker), few packets, large payloads | `ISOLATE` |
| `exploit` | Exploit payload injection | Single port, few packets, unusually large payload | `DECOY` |
| `syn_flood` | TCP SYN flood | Refused connects, one port, no completed handshakes | `ISOLATE` |
| `icmp_flood` | ICMP ping flood | Padded, high-volume ICMP echo traffic | `THROTTLE` |
| `slow_loris` | Slowloris connection exhaustion | Many concurrent held-open connections, many source ports | `THROTTLE` |
| `dns_amplification` | DNS amplification / reflection | Oversized inbound UDP responses | `BANDWIDTH_CAP` |
| `dns_tunneling` | DNS tunneling (covert-channel exfiltration) | Many small, frequent outbound UDP queries (reversed direction) | `DECOY` |
| `mqtt_flood` | MQTT message flood | Many real completed TCP connections to the broker port | `THROTTLE` |
| `firmware_tampering` | Firmware / configuration tampering | Periodic oversized outbound pushes (reversed direction) | `QUARANTINE` |
| `buffer_overflow` | Buffer-overflow / fuzzing probe | Sustained campaign of oversized TCP payloads, one connection | `RESET_SESSIONS` |
| `replay_attack` | Credential / command replay | Repeated uniform small UDP payload | `BLOCK_SOURCE` |
| `rogue_beacon` | Rogue configuration beacon | Frequent small outbound pattern, low confidence (reversed direction) | `FORENSIC_CAPTURE` |
| `c2_beacon` | Command-and-control beaconing | Regular, low-jitter periodic UDP timing (`inter_arrival_cv`), not shape or volume | `ISOLATE` |

`exploit` is DECOY's second scenario: reconnaissance's decoy only observes a scan already known to be harmless probing, while this one redirects an unconfirmed, potentially dangerous payload away from the real device and captures it for analysis — a genuinely different reason to prefer deception, not the same one repeated. `rogue_beacon` remains this registry's deliberately lowest-confidence signature — every more disruptive response costs more legitimate-service value than the signal actually warrants — but its preferred response is `FORENSIC_CAPTURE` rather than a plain `ALERT` log line: gathering real evidence (a pcap plus connection/neighbor state) is strictly more useful than logging alone while staying exactly as non-disruptive. See "Defense actions" below for why `brute_force`, `dns_amplification`, `firmware_tampering`, `buffer_overflow`, and `replay_attack` moved off their original preferred actions too.

`c2_beacon` is this registry's only timing-based (not shape- or volume-based) signature: `inter_arrival_cv`, the coefficient of variation of a flow's inter-packet gaps, distinguishes a periodic beacon from organic traffic in a way no existing feature could -- its numeric window (`packet_count` 15-60, `packets_per_second` 0.1-1.5, `average_packet_size` 300-500, <=2 destination ports, `inter_arrival_cv` <=0.15) was found by sweeping `UnifiedRuleBasedDetector` across 432 synthetic feature combinations rather than hand-reasoning through the other 15 detectors' own windows.

`slow_loris` relies on `unique_source_ports` — many concurrent connections each claiming a fresh ephemeral port — a signal none of the first five attacks' detectors use. Three attacks (`dns_tunneling`, `firmware_tampering`, `rogue_beacon`) reverse traffic direction like `exfiltration` does, but with genuinely different shapes: `dns_tunneling` is many small frequent queries (the shape a naive payload-size-only exfiltration detector would miss), `firmware_tampering` is larger, less frequent pushes, and `rogue_beacon` is the same size range as `dns_tunneling` at a meaningfully higher frequency. `mqtt_flood`, `buffer_overflow`, and `replay_attack` were all originally paced into the same narrow packets-per-second gap `syn_flood` occupies (strictly between `brute_force`'s and `dos`'s own thresholds); repeated live runs found that gap genuinely too narrow for more than one attack under this project's own real Mininet timing variance, so `mqtt_flood`, `buffer_overflow`, and `replay_attack` were moved to a much wider, uncontested sub-1.0-packets-per-second rate instead — see each one's own traffic-generator docstring in `simulation/traffic.py` for the real live numbers behind that call.

ML dataset generation (`ml/generate_dataset.py`) covers all 16 registered attacks -- each of the 10 added after the original 5 reuses its own already-calibrated `AttackScenario.generate_traffic` directly rather than a second, bespoke generator, avoiding an un-synced copy of logic the live demo already tunes. `c2_beacon` is the one exception: its defining signal, `inter_arrival_cv`, is deliberately *not* in `ml/schema.py`'s `FEATURE_COLUMNS` (see "Controlled ML detection experiment" below for why), so the rule-based baseline can never correctly classify it through the CSV round-trip -- a real, documented, bounded gap, not an oversight. The **deployed** dataset/model (`data/ml/controlled_flows_17class.csv`, `models/random_forest_detector.joblib`) cover the full 17-class registry.

Adding a new attack means adding one `AttackScenario` entry to the registry, plus its own traffic generator and rule-based detector — not touching every dependent file by hand.

## Defense actions
Ten actions are available to all three decision policies, all deriving their count and iteration order from the `DefenseAction` enum (`src/iot_defense/defense/decision.py`) — Stackelberg's strategy set, PPO's action space/observation size, and the dashboard's badge styling all grow automatically when a new action is added there; only `config/policies.yaml`'s own Stackelberg payoff numbers and each attack's `preferred_action` in the registry are deliberate per-action judgment calls, not auto-derived.

| Action | Real mechanism | Verified by |
|---|---|---|
| `ALLOW` | No enforcement | N/A — real no-op |
| `ALERT` | Log only, no network change | N/A |
| `ISOLATE` | `ip link set dev <iface> down` on the target | Polls `ip link show` for `state DOWN` |
| `DECOY` | Real TCP banner service + iptables NAT redirect to it | A real redirected socket connection and response |
| `THROTTLE` | `iptables hashlimit` rate limit on new connection attempts to the target — protocol-aware (TCP SYN / UDP / ICMP echo-request) | Verified against real traffic: an unthrottled attacker completed 56/56 connection attempts in 3s; the same traffic under a 2/sec hashlimit completed only 7 |
| `BLOCK_SOURCE` | `iptables` DROP on one specific, already-identified attacker source at the target — everyone else stays fully reachable | Polls `iptables -L INPUT` for the installed rule |
| `QUARANTINE` | Default-deny `iptables` policy (INPUT+OUTPUT) with an explicit ACCEPT allowlist for the network's other known-legitimate hosts | Polls `iptables -L` on both chains for the DROP policy |
| `RESET_SESSIONS` | `ss -K` — real kernel socket destruction, no standing rule left behind | Polls `ss -tn state established` until the connection is gone |
| `FORENSIC_CAPTURE` | Preserves the detection pipeline's own already-captured pcap (falls back to a fresh live capture only if none exists) + a `ss -tapn`/`ip neigh` state snapshot, both real files — zero enforcement action | Requires strictly more than a bare 24-byte pcap header — a genuinely empty capture now fails instead of silently "succeeding" |
| `BANDWIDTH_CAP` | `tc tbf` egress rate cap installed on the **attacker's** own interface, not the target's | Polls `tc qdisc show` for the installed `tbf` qdisc |

`FORENSIC_CAPTURE` originally always opened a fresh live capture, which turned out to be structurally unable to produce real evidence: a response only ever runs after detection has already classified the attack's *complete* capture, so the attack's own traffic has already finished by the time this action starts — a fresh capture opens onto a quiet network. Every real pcap it produced this way measured exactly 24 bytes (a valid but completely empty libpcap header), and the original "non-empty file" check couldn't tell that apart from real evidence. Fixed to preserve the detection pipeline's own real capture instead.

`THROTTLE`'s hashlimit approach was chosen over a `tc qdisc`-based bandwidth cap on the target's ingress after that was built, measured against real traffic, and found to have no real effect: a single SYN packet is too small for byte-rate shaping to meaningfully delay, and egress shaping doesn't touch incoming traffic at all. `BANDWIDTH_CAP` revisits that same `tc tbf` mechanism deliberately — applied instead to the *attacker's* egress, for attacks whose real mechanism is bulk byte volume (`dns_amplification`'s ~570-byte reflected UDP responses) rather than tiny per-packet floods, where it genuinely does bite. Verifying this needs care: UDP's `sendto()` is fire-and-forget and returns instantly regardless of any qdisc downstream, so measuring the *attacker's own send timing* shows no real difference (confirmed directly: 3.7ms uncapped vs. 2.5ms capped on a 300-packet burst). The cap's real effect only shows up in what the *receiver* actually gets — measured directly with a real listener: 300/300 packets delivered uncapped vs. 20/300 delivered under the same cap.

Five attacks were reassigned off their original preferred action once a better-fitting mechanism existed, each a real, live-verified improvement rather than churn:
- `brute_force`, `replay_attack`: `THROTTLE` → `BLOCK_SOURCE`. Both this lab's traffic patterns come from one fixed, identifiable attacker host, so blocking it outright stops every attempt (not just most of them, the way a rate limit does) while every other source stays completely unaffected — the same "legitimate access preserved" property `THROTTLE` offers, done more completely. (This also sidesteps a real bug found and fixed this pass: `THROTTLE`'s `iptables` rule was originally hardcoded to TCP SYNs, so it silently matched none of `replay_attack`'s real UDP traffic despite reporting "success" — `THROTTLE` is now protocol-aware, which separately fixed the same gap for `icmp_flood`.)
- `dns_amplification`: `ISOLATE` → `BANDWIDTH_CAP`. This attack's real mechanism is bulk byte volume from the reflector/attacker's own egress, not raw packet count — capping it at the source constrains the actual flood while the target stays fully reachable throughout, something full `ISOLATE` can't offer.
- `firmware_tampering`: `ISOLATE` → `QUARANTINE`. A tampered device is one you want to *remediate*, not just cut off — `ISOLATE` blocks the very remediation path a corrective push would need; `QUARANTINE` keeps it reachable to the network's other known-legitimate peers while cutting it off from the attacker specifically.
- `buffer_overflow`: `ISOLATE` → `RESET_SESSIONS`. This attack's entire campaign runs over one persistent TCP connection (see `generate_buffer_overflow_mininet_traffic`'s own docstring) — killing exactly that connection is more surgical than taking the whole interface down, with no standing rule left behind.

Every one of the 17 registered threat types (`normal` + 16 attacks) has a full, reasoned Stackelberg payoff entry for all 10 actions in `config/policies.yaml` — the solver's own selection was verified to independently agree with each attack's registered `preferred_action` for all 17, not just for the five originally registered ones.

## PPO reinforcement-learned policy
The PPO environment uses a deterministic normalized security-context observation and a ten-action mapping, derived from `DefenseAction`'s own declaration order: `ALLOW=0`, `ALERT=1`, `ISOLATE=2`, `DECOY=3`, `THROTTLE=4`, `BLOCK_SOURCE=5`, `QUARANTINE=6`, `RESET_SESSIONS=7`, `FORENSIC_CAPTURE=8`, `BANDWIDTH_CAP=9`. Reward coefficients are modelling assumptions, not objective security values.

The policy network's own capacity matters as much as training time: at 17 scenarios/10 actions the reward function gives every non-preferred, non-ALLOW action the same penalty regardless of which one, making this effectively a contextual-bandit problem, and the original `net_arch=[32, 32]` reliably mis-routed the `normal` scenario to `DECOY` no matter how long training ran (confirmed at 12750, 20000, and 35000 timesteps) -- doubling to `net_arch=[64, 64]` (with `ent_coef=0.01` for exploration) converged all 17 scenarios to their own registered `preferred_action` at this project's own fixed `seed=7`. That fix is NOT seed-independent, though -- a direct 3-seed sweep found 2 of 3 other seeds still produced 1-2 mismatches at the same timestep budget, so `seed=7` is currently load-bearing for correctness, not just reproducibility. `tests/test_ppo.py::test_synthetic_training_converges_every_scenario_to_its_preferred_action` trains for real against the project's actual config and fails loudly if this regresses again -- see `simulation/train_ppo.py`'s own comment for the full reproduction.

Two training passes exist:

1. **Synthetic base training** — fast, deterministic, never touches Mininet:
   ```bash
   python -m iot_defense.simulation.train_ppo --output models/ppo_defense  # timesteps default comes from config/policies.yaml
   ```
2. **Real-Mininet fine-tuning** — loads the synthetic model as a warm start and continues training against `RealMininetDefenseEnv`, where every step's reward comes from an actually-executed, actually-verified Mininet outcome (a real ping check for `ISOLATE`, a real redirected connection for `DECOY`, a real installed-rule check for `THROTTLE`) rather than an assumed reward table. Each step generates a full real attack traffic sample and executes/verifies a real response -- measured directly at roughly 200s/step on this project's 2-CPU VM, not "several seconds" -- so this is intentionally bounded (tens of timesteps, not thousands):
   ```bash
   sudo .venv/bin/python3 -m iot_defense.simulation.train_ppo_real \
       --base-model models/ppo_defense --output models/ppo_defense_real --timesteps 30
   ```
   Saves to a separate file by default and never silently overwrites the deployed model — promote it manually (copy over `models/ppo_defense.zip`) only after verifying it behaves sensibly across every registered scenario.

The generated models are ignored by Git. `PPODefensePolicy` fails clearly when a model is absent unless an explicit fallback policy is provided. The trained policy should not be interpreted as learning real-world attacker behaviour or general autonomous cyber defense — it is a bounded, controlled-environment demonstration.

## Controlled ML detection experiment
A reproducible controlled dataset and Random Forest detector. The dataset-generation pipeline (`ml/generate_dataset.py`, `ml/schema.py`) is registry-driven and covers all 16 registered attacks (17 classes with `normal`; `c2_beacon` generates real traffic and labels correctly, but see "Attack types" above for why its own detecting feature is excluded from `FEATURE_COLUMNS`). Generate labelled rows from fresh Mininet runs with:

```bash
sudo .venv/bin/python3 -m iot_defense.ml.generate_dataset --runs 255 --seed 42 \
    --output data/ml/controlled_flows_17class.csv
```

(`--runs 255` is deliberately `17 classes x 15` -- the same per-class trial count this project's own evaluation harness uses, for direct comparability rather than an arbitrary round number.)

Train and evaluate on run-held-out groups with:

```bash
sudo .venv/bin/python3 -m iot_defense.ml.train_random_forest \
    --dataset data/ml/controlled_flows_17class.csv \
    --model models/random_forest_detector.joblib --seed 7
```

The model uses only the 12 behavioural `FlowFeatures` columns; IP addresses, run identifiers, timestamps, metadata, and labels remain audit fields. The rule-based comparison baseline reported alongside RF's own metrics uses the same `UnifiedRuleBasedDetector` the live demo calls, scored on the identical multi-class labels — not a separate binary question. This remains a small, controlled Mininet study; its held-out metrics must not be generalized to arbitrary IoT traffic. In the live demo, the trained RF model is consulted only as a confirmation step when the rule-based detector independently concludes reconnaissance — the one signature with the fuzziest rule-based boundary; every other registered attack has been proven reliable across many live Mininet runs without needing RF confirmation. Because RF is a confirmation step and not a second vote, it may only override the rule-based verdict when it agrees, or disagrees with real confidence (≥70%) — a low-confidence disagreement never downgrades an already-detected attack to "normal".

The currently deployed `data/ml/controlled_flows_17class.csv` and `models/random_forest_detector.joblib` cover the full registry (260 rows, 255 real Mininet runs, 15/class -- 20 for `normal`, since the normal bucket is sampled slightly more often by the generator's own cycling logic; 0 failed runs, 0 anomalies). On a held-out test split (40 rows across all 17 classes -- small per-class, and the per-class numbers below should be read with that in mind) RF reaches **97.5% accuracy** (precision 91.2%, recall 92.2%, f1 91.0%) against a rule-based baseline of **90.0%** (precision 78.8%, recall 80.4%, f1 78.7%) on the identical split -- a real, measured 7.5-point accuracy gap, this project's first genuine full-registry measurement of it (the original 6-class, 100%-vs-86.4% figure predates the 10-attack registry expansion and is superseded by this one, not additional to it). Two classes show real, small-sample weaknesses worth disclosing rather than smoothing over: `exploit_payload_injection` scored 0 precision/recall for RF on this specific test split, and `dns_tunneling_exfiltration` scored 0.5 precision (1.0 recall) -- at ~2-3 test rows per class on average, a single misclassified row swings a class's own metric by a large margin, and this is reported as a real, small-sample-driven result, not a claim that RF specifically fails to learn either attack's signature.

## Planned future components
- ARP spoofing / MITM detection (needs tracking IP-to-MAC mappings over time, not flow statistics — architecturally distinct from every attack currently registered)
- Richer honeypot and deception flows

## Dashboard

The dashboard is a browser-based operations console for observing the live pipeline during a demonstration, with one interactive control: a dropdown + "Run attack" button that starts a real run without the terminal. It is served by FastAPI and pushes updates to the browser over Server-Sent Events (SSE) — no React/Vue/Node/Docker/database, and no internet access is required to view it.

### Architecture
`DemoController` (in `src/iot_defense/demo/controller.py`) drives the real pipeline (Mininet network → traffic generation → packet capture → feature aggregation → detection → `SecurityContext` → policy comparison → response execution → restoration) and publishes every state change onto an in-process `asyncio.Queue`. `src/iot_defense/dashboard/server.py` exposes that state over HTTP/SSE and serves the static frontend from `data/dashboard/static/`. The dashboard never runs its own attack/defense logic — it only renders the controller's real state, falling back to "N/A" for any field that is absent. `GET /attacks` lists the registry for the run-control dropdown; `POST /run` validates the requested key against `ATTACK_SCENARIOS` before ever building a subprocess argv (never shell-interpolated) and spawns `sudo -n <venv-python> -m iot_defense.demo.controller --attack <key>`, guarded by a single in-process lock since Mininet's fixed topology names can't support two concurrent runs; `GET /run/status` reports whether one is active.

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
sudo .venv/bin/python3 -m iot_defense.demo.controller --attack <key>
# <key> is any registered key -- see "Attack types" above for the full list of 16, or trigger a run from the dashboard's own "Run attack" control instead
```
Omit `--attack` to be prompted interactively. The dashboard server and the demo process share `data/dashboard/state.json` and the controller's SSE event queue when run together as one process; run the dashboard server itself with the demo controller instantiated once (as `server.py` does) so browser clients observe the same controller instance.

### Dashboard sections
Header (phase, connection status, attack-mode badge, run-control dropdown + button, clock) · pipeline flow strip · network topology (5-node SVG: sensor, camera, smart plug, attacker, decoy) · live packet feed · threat detection panel with flow features · BDI-style security context (beliefs / desires / intention) · policy comparison (Rule-Based, Stackelberg, PPO) with selected action, generic over however many actions are registered · response & containment (decoy / isolation / rate-limit / restoration detail) · event timeline · metrics.

### Live demo sequence
1. `STARTING_NETWORK` — Mininet topology comes up, all 5 nodes go `ONLINE`.
2. `BASELINE` / `OBSERVING` — benign traffic is generated and captured; a normal `ThreatEvent` is built and `ALLOW`ed.
3. `THREAT_DETECTED` / `DECIDING` — the selected attack's real traffic is generated and captured; Rule-Based, Stackelberg, and PPO policies are each evaluated against the same `SecurityContext`, without being told which attack was requested.
4. `RESPONDING` → `DECOY_ACTIVE` / `ISOLATED` / `THROTTLED` / `BLOCKED_SOURCE` / `QUARANTINED` / `SESSIONS_RESET` / `FORENSICS_CAPTURED` / `BANDWIDTH_CAPPED` — the selected action is actually executed inside Mininet, one dedicated phase per registered `DefenseAction` beyond `ALLOW`/`ALERT`.
5. `RESTORING` → `RESTORED` — connectivity is verified and restored.
6. `COMPLETE` → `CLEANUP` — Mininet and any redirect/isolation/rate-limit state are torn down.

### Cleanup
The controller's `cleanup()` tears down the response executor (removing any iptables redirect/rate-limit rules and restoring isolated interfaces) and stops the Mininet network on completion or on error. If a run is interrupted, `sudo mn -c` clears any leftover Mininet state.

### Known limitations
- The Random Forest detector reflects a preliminary evaluation on a small controlled Mininet dataset (260 rows across all 17 classes; see "Controlled ML detection experiment" above) and should not be generalized to arbitrary IoT traffic. The held-out test split (40 rows across 17 classes) is small enough per class that individual class-level metrics carry real sample-size noise -- the aggregate accuracy/precision/recall figures are more trustworthy than any single class's own numbers.
- The PPO policy's base training is a lightweight synthetic decision simulator, not live Mininet traffic. A bounded real-Mininet fine-tuning pass exists and has been run (see "PPO reinforcement-learned policy" above), but it is a short, warm-started refinement on top of the synthetic policy, not training from scratch against real traffic.
- Stackelberg utilities are configured/modelled values (see `config/policies.yaml`), not measured real-world costs.
- Only two attack signatures (reconnaissance, credential-stuffing) are genuinely distinguished by connection *rate/pattern*; the flood and exfiltration signatures rely more heavily on volume and direction, and `exploit` relies on payload size rather than any of those. `c2_beacon` adds a third, genuinely different axis -- inter-packet timing regularity (`inter_arrival_cv`) -- rather than rate, volume, or size (see "Attack types" above).
- `exploit`'s rule-based detector separates a single oversized request from ordinary low-volume traffic almost entirely by `average_packet_size` — packet_count and port diversity alone overlap with real observed normal-traffic values, so this signature has the least headroom of any currently registered detector if normal traffic patterns ever shift. A live capture of `generate_exploit_mininet_traffic` measured `average_packet_size=442` against a detection window of 250-550 and real normal traffic's observed max of 111.6 (see `data/ml/controlled_flows_6class.csv`) — real margin on both sides today, not a coin flip, but a narrower gap than the other four attacks have.
- Run durations vary a lot across the 16 attacks, by design, not by accident — most finish in 4-25s, but `mqtt_flood` takes ~110s, `buffer_overflow` ~40s, and `c2_beacon` ~33s (its fixed 1.5s beacon interval is the signal being detected, not an incidental slowdown): the first two were deliberately slowed down to a real, wide-margin sub-1.0 packets-per-second rate after live runs found the alternative (a faster, narrower rate shared with other attacks) intermittently misclassified under this VM's own real timing variance. A slower, longer, reliable run was preferred over a faster, occasionally-wrong one.
- The `--attack` CLI choice is registry-driven (`ATTACK_SCENARIOS`), so all 16 keys are always available at the live demo (and the dashboard's own run-control) and always exercise the real detection/decision/response pipeline. ML dataset *generation* now covers all 16, but the **deployed** RF model is still trained only on the original 6 classes (see "Attack types" and "Controlled ML detection experiment" above).

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
