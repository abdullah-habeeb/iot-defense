# IoT Defense

## Purpose
This project implements a modular, agent-based cyber-defense framework for residential IoT networks, demonstrating the end-to-end flow:

Mininet IoT Network -> Monitoring Agent -> Feature Extraction -> Detection Agent -> Decision Agent -> Response / Deception -> Observability / Metrics.

For a research-style comparison of the 3-policy system against simpler baselines on real Mininet trials -- methodology, results, and honest limitations -- see [EVALUATION.md](EVALUATION.md). **Taking this project over? Read [HANDOVER.md](HANDOVER.md) first.**

## Status and what the evidence shows
This is a research prototype (a college major project), not a product. Every result comes from one 5-host Mininet lab, plus replays of public IoT-23 captures; do not generalise it to other networks, devices or attackers. Numbers, confidence intervals and caveats are in [EVALUATION.md](EVALUATION.md); the research framing and future work are in [docs/FUTURE_WORK.md](docs/FUTURE_WORK.md); the physical demo is in [docs/LIVE_DEMO.md](docs/LIVE_DEMO.md).

- **A measured-outcome benchmark** (the 693-row "record book", `data/outcomes/outcome_table.jsonl`): each of 10 responses applied to each of 21 situations (normal traffic plus 20 attacks) in live Mininet, three repetitions, scored by one objective (`5 x containment + 3 x service kept + 2 x intelligence - cost`).
- **Three response-selection policies graded against it**: a rule-based playbook, a Stackelberg game that models the attacker's reaction, and PPO. The playbook loses about 3.0 utility points of regret to the measured-best response (best in 4 of 21 situations). Stackelberg, built from mechanism priors alone, loses 0.04 (best in 20 of 21); the same priors without the attacker's reaction lose 0.55. Trained on the measurements, PPO and Stackelberg tie in live paired trials (p = 0.69), so **the results do not show that "Stackelberg is best"**. A PPO trained on the table it is graded on is circular and is labelled as such.
- **An evidence-based arbiter** that executes the candidate response with the best measured evidence, and a **live defender** that applies real `iptables` rules on the machine it runs on. The arbiter also scores every response the device can perform, not only the policies' proposals; on 168 fresh live trials this raised mean utility on the live defender from 6.07 to 6.52 (paired +0.44, 95% CI [+0.33, +0.57]).
- **A detector evaluation.** The live defender names all 16 single-source lab attacks correctly with a 60 s window and re-decision (a development-set result: thresholds were tuned on those captures). The detector does not transfer to real traffic: on 5.5 hours of a benign Amazon Echo it would take about 17 to 21 firewall actions per hour, and command-and-control traffic is noticed but never named a beacon.
- **Limits that apply to everything above:** three repetitions per cell, scripted attackers, Stackelberg priors written by authors who knew the lab (not blind), nothing re-measured on physical IoT hardware.

## Current architecture
- Mininet network simulation (5 hosts: sensor, camera, smart plug, attacker, decoy)
- Monitoring agent for packet observations
- Feature extraction pipeline (13 behavioural `FlowFeatures` columns -- 12 feed ML training; the 13th, `inter_arrival_cv`, is a deliberate scope boundary, see "Attack types" below)
- **Attack scenario registry** (`src/iot_defense/attacks/registry.py`) — a single `AttackScenario` definition per attack type. Every dependent module (detection, decision policy, the Stackelberg payoff lookup, PPO's observation encoding, dataset generation, the demo controller) derives its per-attack behaviour from this one registry instead of hardcoding it separately in each place.
- Attack-type-agnostic rule-based detection layer (`UnifiedRuleBasedDetector`) — classifies captured traffic purely from its shape (rate, port diversity, payload size), never from which attack was requested
- Decision agent comparing three independent policies (rule-based, Stackelberg game-theoretic, PPO reinforcement-learned) for response selection, and an evidence-based arbiter (`defense/arbiter.py`) that executes the best-evidenced candidate
- Response/deception handlers, all executing real changes inside the Mininet network (real interface isolation, real decoy redirection, real connection-rate limiting)
- Logging and metrics collection
- Live physical-demo defender (`src/iot_defense/live/`): the same detectors, policies and arbiter on real packets, applying real `iptables` rules on one machine ([docs/LIVE_DEMO.md](docs/LIVE_DEMO.md))
- Evaluation tooling (`src/iot_defense/evaluation/`): the measured-outcome table and harness, outcome report, held-out arbiter evaluation, detector evaluation, pcap and public-data replay

## Environment
- Ubuntu 24.04.4 LTS
- Python 3.12.3
- Mininet 2.3.0
- Open vSwitch 3.3.9

## Attack types
Sixteen single-source attack types are registered, plus four distributed (spoofed-source) variants described below (20 attack conditions; 21 situations with `normal`), selectable at demo start via `--attack <key>`. Every rule-based detector's numeric thresholds were hand-placed in a real, unclaimed gap between its neighbors' own thresholds (not guessed), and cross-checked two ways: a generic test runs every attack's own synthetic signature through the *complete* detector sweep (not just its own detector) and confirms no earlier-registered one claims it first, and real live Mininet runs (repeated across many rounds) confirm the same holds under real-world timing variance, not just on paper.

| Key | Label | Signature | Playbook response (rule-based default) |
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

### Distributed variants (spoofed sources)
Four further conditions are registered after the sixteen above: `dos_distributed`, `syn_flood_distributed`, `icmp_flood_distributed` and `replay_distributed` (attack types `dos_flood_distributed`, `tcp_syn_flood_distributed`, `icmp_ping_flood_distributed`, `credential_replay_distributed`). Each is the same attack sent from **six source addresses** -- the attacker host's real one plus five spoofed -- using raw packets from the one physical attacker host (`simulation/traffic.py`; UDP, SYN-only TCP and ICMP, since a TCP handshake cannot complete toward a spoofed address, which is why `brute_force` has no distributed form). They exist to break the lab's easy answer: a per-source response (`BLOCK_SOURCE`, which dominates every single-source inbound attack) reaches only one of the six sources.

No single flow reveals them -- every source is a small trickle -- so they are recognized by an aggregate stage in `UnifiedRuleBasedDetector.detect_flows` (`destination_aggregates` plus `RuleBasedDistributedSourcesDetector`, which needs at least four distinct sources to one destination; ordinary traffic here has two). They are flagged `per_flow_detectable=False`, so they stay out of the per-flow ML dataset and classifier. Delivered traffic is measured from all six source addresses. Their `preferred_action` values are only the rule-based arm's expert defaults; Stackelberg reasons about them through two extra model classes (`distributed_flood`, `distributed_trickle`) with priors written before any distributed measurement.

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

The Stackelberg arm's payoffs are generated, not hand-tuned per attack: `defense/game_model.py` builds them from an a-priori mechanism model in `config/policies.yaml` (`policy.game_model`: what each response can mechanically do against each attack *class*) and the shared operator objective (`policy.objective`). It never reads an attack's registered `preferred_action` or any measured outcome, so its choices can genuinely differ from the rule-based arm's and be wrong in ways the measured evaluation exposes (see "Evaluation methodology").

## PPO reinforcement-learned policy
PPO observes a normalized security-context vector (detector label, score, confidence, packet rate, port diversity, device criticality, history, intention) and picks one of ten actions, mapped from `DefenseAction`'s declaration order: `ALLOW=0`, `ALERT=1`, `ISOLATE=2`, `DECOY=3`, `THROTTLE=4`, `BLOCK_SOURCE=5`, `QUARANTINE=6`, `RESET_SESSIONS=7`, `FORENSIC_CAPTURE=8`, `BANDWIDTH_CAP=9`. Its observation contains no other policy's output.

It is trained **only from measured outcomes**: `defense/ppo_env.py` is a contextual bandit over the live-Mininet outcome table (`data/outcomes/outcome_table.jsonl`, built by `evaluation/outcome_table.py`). Each step draws a true condition, shows PPO a noisy and sometimes mislabelled detector observation of it (`policy.ppo.label_error_rate`, score/feature jitter, random device-criticality), and rewards the chosen action with a realized utility measured in Mininet for the *true* condition. No registered `preferred_action` is read anywhere in training. `gamma=0` and a 1020-step rollout are deliberate: steps are independent (a bandit), and a smaller rollout let the policy collapse onto `ALLOW` -- see the comment in `simulation/train_ppo.py` for the measured reasons.

```bash
python -m iot_defense.simulation.train_ppo --output models/ppo_defense  # needs data/outcomes/outcome_table.jsonl
python -m iot_defense.evaluation.ppo_seed_robustness                    # regret vs the measured table across 10 seeds
```

A model trained against an older observation layout is rejected with a clear error (retrain it).

The generated models are ignored by Git. `PPODefensePolicy` fails clearly when a model is absent unless an explicit fallback policy is provided. The trained policy should not be interpreted as learning real-world attacker behaviour or general autonomous cyber defense — it is a bounded, controlled-environment demonstration.

## Evaluation methodology (measured outcomes)
Policies are compared on **what their responses measurably do**, not on whether they pick an action the registry labels "preferred". For every response, `RealMininetDefenseEnv.measure_response()` applies it in live Mininet, replays the same condition's traffic, and measures (1) attack packets that survive to an `iptables` counter appended *after* the response on the host receiving the flow (the sensor for inbound attacks, the attacker host for the five outbound ones; a packet capture would miss every firewall-based response), relative to the un-responded (`ALLOW`) run of the same trial, (2) legitimate camera-to-sensor ping loss, (3) verified intelligence (a real decoy interaction or a non-empty evidence capture). The shared objective in `config/policies.yaml` (`policy.objective`) scores that vector as `containment x contained + service x kept + intelligence x verified - action_cost`.

Three arms, three independent information sources: **rule-based** = hand-set expert thresholds; **Stackelberg** = a-priori mechanism model solved as a leader-follower game; **PPO** = learned from the measured outcome table. They are scored on **fresh held-out** trials (`evaluation/harness.py`) that never read that table. `evaluation/outcome_report.py` reports paired utility differences (bootstrap CIs, Wilcoxon and sign tests, Holm-corrected), how often the arms actually choose different actions, the same measurements re-scored under other objective weights, and the Stackelberg prior's error against measurement. Detection accuracy is reported separately (`evaluation/report.py`); it belongs to the shared detector, not to any policy.

`preferred_action` in the registry is the rule-based arm's expert default and a diagnostic column (`matches_preferred_action`); it is not ground truth for response quality anywhere.

Run order (the `sudo` steps need Mininet root; the first is a short smoke test to validate the probes before the multi-hour runs):
```bash
sudo .venv/bin/python3 -m iot_defense.evaluation.outcome_table --reps 1 --conditions dos_flood normal --output /tmp/smoke.jsonl
.venv/bin/python3 -m iot_defense.evaluation.outcome_table --summarize --output /tmp/smoke.jsonl
sudo .venv/bin/python3 -m iot_defense.evaluation.outcome_table --reps 2        # the measured outcome table (resumable)
.venv/bin/python3 -m iot_defense.simulation.train_ppo                          # PPO from measurements
sudo .venv/bin/python3 -m iot_defense.evaluation.harness --trials-per-condition 8   # held-out trials
.venv/bin/python3 -m iot_defense.evaluation.outcome_report                     # statistics
.venv/bin/python3 -m iot_defense.evaluation.report                             # detection summary
```

## Which response the demo executes: the arbiter
The three policies each propose an action; the live demo does not favour one of them. `defense/arbiter.py` scores each proposed **action** by what was measured when that action was applied against this kind of attack in live Mininet (the outcome table): mean realized utility minus `risk_aversion` x its run-to-run spread, so an erratic action loses to a dependable one. It executes the best-scoring candidate. With `policy.arbiter.consider_all_supported: true` (the default) the candidates are the policies' proposals **plus every response the device can perform** (all ten in the Mininet lab, the five the live defender supports), so a proposal the device cannot apply no longer forces a fallback to ALERT; set it to `false` for the earlier proposals-only behaviour. The arbiter never reads `preferred_action`, and with no measured evidence for any candidate (an attack label never measured, or no outcome table) it falls back to Stackelberg and says so in its reasoning (`policy.arbiter` in `config/policies.yaml`). Held-out-block results for the change are in EVALUATION.md ("Arbiter candidates").

```bash
sudo .venv/bin/python3 -m iot_defense.demo.controller --attack dos_distributed                  # arbiter (default)
sudo .venv/bin/python3 -m iot_defense.demo.controller --attack dos_distributed --policy ppo     # force one policy: arbiter|stackelberg|rule_based|ppo
```

`python -m iot_defense.evaluation.arbiter_eval` scores the proposals-only arbiter on the held-out harness trials without a new live run (it only ever executes one of the three proposals, and the harness measured every distinct proposal); `python -m iot_defense.evaluation.arbiter_candidates_eval` compares proposals-only with every-supported-response by holding out each measurement block; see EVALUATION.md.

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

## Pre-registered test: does Stackelberg transfer to attacks nobody measured?
The strongest open question about the 20-attack benchmark is that the Stackelberg priors were written by people who knew the lab. `src/iot_defense/experiments/new_attacks/` is the experiment that answers it: two new attacks (`ssdp_reflection`, an inbound SSDP/UPnP reflection, and `telnet_scan_outbound`, a compromised device scanning for Telnet) that exist nowhere in the benchmark. A person who has seen no measurement of them writes the priors and the playbook entries; those are committed, hashed and frozen (`FREEZE.json`) and pushed; only then are all ten responses measured three times per attack; each policy is graded on regret against the pre-registered criteria. Stackelberg does not learn from the measurements: it decides from the frozen priors alone.

Nothing is added to the real attack registry (that would resize PPO's observation and invalidate the benchmark); the two attacks are registered only inside the experiment's own process. A hash-chained run log, a verification of every frozen file and GitHub's own push times make later tampering detectable, and `evidence.py` generates the demo-ready report from those artefacts. **Status: run on 2026-10-27, verdict PASS on both attacks** (Stackelberg and a blind playbook both chose the best measured response, regret 0.00; all 13 evidence checks pass; two attacks demonstrate, they do not establish, and the playbook tied, so this does not show Stackelberg beating a playbook). Results, caveats and the evidence report are in EVALUATION.md ("Transfer to two attacks nobody had measured"). Read [docs/NEW_ATTACKS_PROTOCOL.md](docs/NEW_ATTACKS_PROTOCOL.md) (steps, commands, what each outcome means) and, if you are the author of the priors, only [docs/NEW_ATTACKS_BLIND_AUTHOR_BRIEF.md](docs/NEW_ATTACKS_BLIND_AUTHOR_BRIEF.md).

## Planned future components
The research roadmap (what the physical demo does and does not show, and how others can build on this) is in [docs/FUTURE_WORK.md](docs/FUTURE_WORK.md).

- ARP spoofing / MITM detection (needs tracking IP-to-MAC mappings over time, not flow statistics — architecturally distinct from every attack currently registered)
- Richer honeypot and deception flows

## Dashboard

The dashboard is a browser-based operations console for observing the live pipeline during a demonstration, with one interactive control: a dropdown + "Run attack" button that starts a real run without the terminal. It is served by FastAPI and pushes updates to the browser over Server-Sent Events (SSE) — no React/Vue/Node/Docker/database, and no internet access is required to view it.

### Architecture
`DemoController` (in `src/iot_defense/demo/controller.py`) drives the real pipeline (Mininet network → traffic generation → packet capture → feature aggregation → detection → `SecurityContext` → policy comparison → response execution → restoration) and publishes every state change onto an in-process `asyncio.Queue`. `src/iot_defense/dashboard/server.py` exposes that state over HTTP/SSE and serves the static frontend from `data/dashboard/static/`. The dashboard never runs its own attack/defense logic — it only renders the controller's real state, falling back to "N/A" for any field that is absent. `GET /attacks` lists the registry for the run-control dropdown; `POST /run` validates the requested key against `ATTACK_SCENARIOS` before ever building a subprocess argv (never shell-interpolated) and spawns `sudo -n <venv-python> -m iot_defense.demo.controller --attack <key>`, guarded by a single in-process lock since Mininet's fixed topology names can't support two concurrent runs; `GET /run/status` reports whether one is active.

### Prerequisites
```bash
cd iot-defense   # the repository root
source .venv/bin/activate
```
`fastapi`, `uvicorn`, and `httpx` are declared in `pyproject.toml` / `requirements.txt`.

### Start the dashboard server
```bash
cd iot-defense   # the repository root
source .venv/bin/activate
PYTHONPATH=src uvicorn iot_defense.dashboard.server:app --host 0.0.0.0 --port 8000
```
Then open **http://<host>:8000** in a browser.

### Run the live demo (requires Mininet, typically sudo)
```bash
cd iot-defense   # the repository root
sudo .venv/bin/python3 -m iot_defense.demo.controller --attack <key>
# <key> is any registered key -- see "Attack types" above for the full list of 20, or trigger a run from the dashboard's own "Run attack" control instead
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
- The PPO policy trains from a *measured* outcome table, but one built in a single 5-host lab with fixed attacker/target placement and a handful of repetitions per (attack, action) cell; it learns this lab's responses, not real-world attacker behaviour.
- The shared objective's weights and per-action operational costs (`policy.objective`) are declared operator preferences, not measured costs; the evaluation re-scores the same measurements under other weightings (`outcome_report` sensitivity) to show how much the ranking depends on them. Stackelberg's mechanism priors are a-priori estimates, and the report prints their error against measurement.
- Only two attack signatures (reconnaissance, credential-stuffing) are genuinely distinguished by connection *rate/pattern*; the flood and exfiltration signatures rely more heavily on volume and direction, and `exploit` relies on payload size rather than any of those. `c2_beacon` adds a third, genuinely different axis -- inter-packet timing regularity (`inter_arrival_cv`) -- rather than rate, volume, or size (see "Attack types" above).
- `exploit`'s rule-based detector separates a single oversized request from ordinary low-volume traffic almost entirely by `average_packet_size` — packet_count and port diversity alone overlap with real observed normal-traffic values, so this signature has the least headroom of any currently registered detector if normal traffic patterns ever shift. A live capture of `generate_exploit_mininet_traffic` measured `average_packet_size=442` against a detection window of 250-550 and real normal traffic's observed max of 111.6 (see `data/ml/controlled_flows_6class.csv`) — real margin on both sides today, not a coin flip, but a narrower gap than the other four attacks have.
- Run durations vary a lot across the 16 attacks, by design, not by accident — most finish in 4-25s, but `mqtt_flood` takes ~110s, `buffer_overflow` ~40s, and `c2_beacon` ~33s (its fixed 1.5s beacon interval is the signal being detected, not an incidental slowdown): the first two were deliberately slowed down to a real, wide-margin sub-1.0 packets-per-second rate after live runs found the alternative (a faster, narrower rate shared with other attacks) intermittently misclassified under this VM's own real timing variance. A slower, longer, reliable run was preferred over a faster, occasionally-wrong one.
- The `--attack` CLI choice is registry-driven (`ATTACK_SCENARIOS`), so all 20 keys are always available at the live demo (and the dashboard's own run-control) and always exercise the real detection/decision/response pipeline. ML dataset *generation* covers the 16 single-source attacks and the **deployed** RF model is trained on all 17 classes (16 attacks plus `normal`; see "Controlled ML detection experiment" above). The four distributed variants are not per-flow detectable, so they are recognised by the rule-based aggregate stage and stay out of the per-flow classifier.
- The limits of the policy comparison and of the detector evaluation (three repetitions per cell, one lab, priors not blind, in-sample lab accuracy, no transfer to real device traffic) are listed under "Limitations" in [EVALUATION.md](EVALUATION.md).

## Virtual environment
```bash
cd iot-defense   # the repository root
source .venv/bin/activate
```

## Run tests
```bash
cd iot-defense   # the repository root
source .venv/bin/activate
pytest -q
```
The full suite (about 900 tests, roughly 4 to 8 minutes on a two-vCPU VM) needs neither Mininet nor root: tests that touch the network use fakes, and every test builds its own data. Run it with nothing else using the CPU: a few tests (the live defender, policy decision latency) are timing-sensitive.

## What is and is not in git
- **Tracked:** the source, tests, config, docs, the measured outcome tables (`data/outcomes/outcome_table.jsonl`, `adaptive_table.jsonl`), and the small result files behind the claims in `EVALUATION.md` (force-added from `data/evaluation/`: held-out and live arbiter evaluations, detector and public-data results, the harness rows for the fresh live trials).
- **Ignored, regenerated:** `models/` (retrain PPO with `python -m iot_defense.simulation.train_ppo`; the RF detector needs `ml.generate_dataset` and `ml.train_random_forest`, which need Mininet and root), `data/ml/`, the rest of `data/evaluation/` (harness runs and pcaps), logs, runtime state (`data/dashboard/state.json`, `live_state.json`).
- **Attached to a GitHub release, not in git:** `data/external/iot23/` holds the public IoT-23 captures used by `evaluation/public_eval.py` (Garcia, Parmisano and Erquiaga, 2020, Stratosphere Laboratory, CTU Prague; CC BY 4.0, <https://doi.org/10.5281/zenodo.4743746>; please cite it). Two of the files exceed GitHub's 100 MB limit, so all 14 (581 MB: six malware captures 3-1, 34-1, 20-1, 21-1, 8-1, 42-1, saved as `m03.pcap` and so on, and one benign Amazon Echo capture, each with its `.conn.log.labeled`) are assets of the release `data-iot23-v1`. `scripts/fetch_iot23.sh` downloads them into place and verifies their checksums.
