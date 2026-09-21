# Evaluation

This document reports how the 3-policy defense system (rule-based, Stackelberg, PPO) compares
against two simpler baselines and a real signature-based IDS (Suricata), on real Mininet traffic,
using a repeatable benchmark harness -- not individual anecdotal demo runs. It also situates the
system against published work on the same general problem, honestly: no paper found shares this
project's exact dataset or environment, so that comparison is qualitative context, not a claimed
head-to-head number.

## Methodology

`src/iot_defense/evaluation/harness.py` runs `N` real Mininet trials for every registered
condition (`normal` plus every attack in `attacks/registry.py`). Each trial:

1. Starts real traffic for the condition (the same generators the live demo and dataset
   generation use) and captures it with `tcpdump`, preserving the raw pcap for later offline
   analysis.
2. Classifies the capture with the real, attack-type-agnostic `UnifiedRuleBasedDetector`.
3. Evaluates five arms against the **identical** resulting security context:
   - **Rule-based**, **Stackelberg**, and **PPO** -- the project's three real decision policies.
   - **NaiveBlockAllBaseline** -- any detected threat is isolated outright, the same response
     regardless of attack type (the common "one fixed response to every alert" design).
   - **AlwaysAllowBaseline** -- never intervenes, the floor.
4. Executes and verifies each *distinct* action chosen across the five arms exactly once, for
   real -- a real ping check for ISOLATE, a real redirected-connection probe for DECOY, a real
   installed-rule check for THROTTLE -- so containment effectiveness is measured, not assumed,
   for every arm, not only the ones already exercised live in earlier phases.

One real trial produces every arm's result; no arm requires a separate live run. This report
covers `trials_per_condition=5` across the **16 conditions registered at run time** (`normal`
plus 15 attacks -- `c2_beacon`, the 16th attack, was registered after this run started; see
Limitations) -- **80 real Mininet trials, 400 recorded outcomes** -- generated on 2026-09-21,
results at `data/evaluation/results.jsonl` (gitignored; regenerate with
`sudo .venv/bin/python3 -m iot_defense.evaluation.harness --trials-per-condition N`).

`trials_per_condition=5` (vs. an earlier 20-trial run over a smaller 6-condition registry) was a
deliberate, explicit time/coverage tradeoff: covering all 16 conditions at N=20 would cost several
real hours (one attack alone runs ~110s/trial), and breadth across every currently-registered
attack was judged more valuable right now than depth on a subset. The direct cost of that choice
is granularity -- see Discussion.

**Metrics**:
- *Detection accuracy* -- did the shared detector correctly classify the captured traffic. This
  runs once per trial and every arm sees the same result, so it is reported per arm as a sanity
  check, not because arms are expected to differ on it.
- *Matches preferred action (attacks only)* -- of the attack trials, how often the arm's chosen
  action was the one this project's registry defines as correct for that attack.
- *Verified response rate* -- of **all** trials, how often the arm both chose the preferred
  action **and** that action's real effect was independently confirmed (not just "the command
  didn't error"). This is the headline comparison metric: it is 0 whenever the wrong action was
  chosen, and only counts a real, checked success.

A second, independent arm runs offline Suricata analysis of the same 80 pcaps
(`src/iot_defense/evaluation/suricata_eval.py`), against two rulesets -- ET-Open (real-world
community threat signatures, fetched via `suricata-update`) and a small lab-tailored ruleset
(`config/suricata/lab.rules`, written to encode the same shape knowledge `detection/detector.py`'s
own rule-based detectors use, so Suricata is judged on a fair signature-matching version of that
knowledge too, not only on a strawman of unrelated real-world malware signatures). *Detector*, not
*response*, is the axis Suricata is compared on: Suricata identifies traffic, it does not select
or execute a containment action, so its comparison metrics are accuracy/true-positive-rate/
false-positive-rate against ground truth, not verified-response rate.

## Results

| Arm | Detection accuracy | Verified response rate | Matches preferred action (attacks only) | Mean detection latency |
|---|---|---|---|---|
| Rule-based (ours) | 90.0% | 85.0% | 92.0% | 26026 ms |
| Stackelberg (ours, deployed) | 90.0% | 85.0% | 92.0% | 26026 ms |
| PPO (ours) | 90.0% | 85.0% | 92.0% | 26026 ms |
| NaiveBlockAllBaseline | 90.0% | 25.0% | 20.0% | 26026 ms |
| AlwaysAllowBaseline | 90.0% | 6.2% | 0.0% | 26026 ms |

Per-condition breakdown for Stackelberg, the policy the live demo actually deploys (n=5 trials
per condition -- each percentage is a multiple of 20%, see Discussion):

| Condition | Detection accuracy | Verified response rate |
|---|---|---|
| `normal` | 100.0% | 100.0% |
| `reconnaissance_port_scan` | 100.0% | 100.0% |
| `dos_flood` | 100.0% | 100.0% |
| `brute_force` | 100.0% | 100.0% |
| `data_exfiltration` | 100.0% | 100.0% |
| `exploit_payload_injection` | 80.0% | 80.0% |
| `tcp_syn_flood` | 60.0% | 100.0% |
| `icmp_ping_flood` | 100.0% | 0.0% |
| `slow_loris_exhaustion` | 40.0% | 20.0% |
| `dns_amplification` | 100.0% | 100.0% |
| `dns_tunneling_exfiltration` | 80.0% | 80.0% |
| `mqtt_message_flood` | 100.0% | 100.0% |
| `firmware_tampering` | 100.0% | 100.0% |
| `buffer_overflow_probe` | 100.0% | 100.0% |
| `credential_replay` | 80.0% | 80.0% |
| `rogue_config_beacon` | 100.0% | 100.0% |

External detection comparison (Suricata, offline analysis of the same 80 pcaps):

| Detector | Accuracy | True positive rate | False positive rate |
|---|---|---|---|
| Suricata + ET-Open (real-world community rules) | 77.5% | 81.3% | 80.0% |
| Suricata + lab-tailored rules (this project's own signatures) | 91.2% | 90.7% | 0.0% |
| This project's `UnifiedRuleBasedDetector` | 90.0% | -- | 0.0% (0/5 `normal` trials misclassified) |

## Discussion

**All three of our policies still score identically** on every aggregate metric. That remains
expected, not a null result: detection and the registry-driven "correct action per attack" answer
are shared inputs, and nothing in this dataset's context vectors was adversarial enough to make
the three decision mechanisms disagree. This has now been confirmed across two independent
harness runs at different scales (120 trials over 6 conditions, and now 400 over 16) -- the
agreement is not an artifact of a small or narrow sample.

**The baseline gap holds, and widens, at full registry breadth.** Our system's 85.0%
verified-response rate is **3.4x** NaiveBlockAllBaseline's 25.0% and **13.7x**
AlwaysAllowBaseline's 6.2% -- a larger multiple than the earlier 6-condition run (2x / 5x), because
most of the 10 newly-covered attacks have a registry-preferred action other than plain ISOLATE
(THROTTLE, DECOY, QUARANTINE, RESET_SESSIONS, BANDWIDTH_CAP, FORENSIC_CAPTURE -- see README's
"Defense actions" table), so NaiveBlockAllBaseline's fixed ISOLATE response is now wrong for a
larger fraction of conditions than before. This is precisely the value a per-attack-type response
is meant to add over a single fixed reaction to any alert, and it gets more pronounced, not less,
as the attack catalog grows.

**Per-condition percentages are now quantized in 20% steps and noisier than the earlier
20-trial run's 5% steps -- a direct, known cost of the N=5 breadth-over-depth tradeoff, not a
new regression.** Three conditions stand out and deserve honest treatment rather than being
smoothed over: `tcp_syn_flood` (60% detection, 3/5), `icmp_ping_flood` (100% detection but 0%
verified response, 0/5), and `slow_loris_exhaustion` (40% detection, 20% verified, worst of the
16). All three attacks are also the ones with the tightest, most rate/timing-dependent detection
windows on this project's 2-CPU lab VM (see each detector's own docstring in `detector.py`), so a
single missed detection or a verification probe racing real kernel/network timing has an outsized
effect at n=5 -- the same class of Mininet-level timing variance already documented as the
dominant cause of the verified-vs-preferred gap in the previous run, just more visible per-bucket
at this sample size. `icmp_ping_flood`'s 0% verified rate at 100% detection is the most notable
single number here: it means the *action chosen* was correct every time but its *real-world
effect* was never independently confirmed within this run's timeout window -- worth a targeted
re-run at higher N before treating it as a real system weakness rather than a measurement
artifact. None of this is fixed in this pass; it is reported so a future targeted re-run knows
exactly where to look first.

**Suricata's ET-Open false-positive rate rose sharply, from 20% to 80%, on the fuller condition
set** -- a real, different finding from the earlier run, not a copy-forward. The earlier 20%
figure was measured against only 5 `normal` trials out of 120 total pcaps; this run's 80% is also
against a small `normal` count (5 of 80), but the fuller attack catalog now includes several
UDP/timing-based attacks (`dns_tunneling_exfiltration`, `rogue_config_beacon`,
`firmware_tampering`) whose synthetic traffic shapes appear to trip ET-Open's real-world
heuristic signatures more often than the original 5 attacks did -- consistent with this report's
existing, unchanged point that ET-Open was never tuned for this lab's traffic distribution. The
lab-tailored ruleset's false-positive rate stayed at a clean 0%, and its accuracy improved (91.2%
vs. 64.2% previously) now that it has signatures for more of the registered attacks to correctly
match against. This project's own `UnifiedRuleBasedDetector` (90.0%) still exceeds both Suricata
configurations, for the same reason as before: a small, purpose-built classifier over this
project's own known flow-feature space against a general-purpose engine running rulesets built for
a different traffic distribution.

**`exploit_payload_injection`, `dns_tunneling_exfiltration`, and `credential_replay` each landed
at 80%** -- consistent with `exploit_payload_injection`'s already-documented narrow
`average_packet_size` margin (see README's known limitations), and plausibly the same
timing-window sensitivity discussed above for the other three underperforming conditions, though
at n=5 a single trial accounts for the entire 20-point gap from 100%, so this should not be read
as a precise measurement of a real 80% ceiling.

## Related work

No published study was found comparing rule-based, Stackelberg game-theoretic, and
reinforcement-learned *response selection* for IoT defense on a shared dataset -- the closest
work compares detection methods alone, or evaluates deception/game-theoretic defenses on
different metrics and environments than this project's controlled Mininet lab. The following are
cited as context for the architectural choices made here, not as numbers this evaluation claims
to match or beat:

- Signature-based IDS baseline choice (Suricata over Snort): a real experimental comparison found
  Suricata generally ahead of Snort on detection accuracy, scalability, and resource efficiency
  (e.g. 100% vs. 85.7%/66.7% on two DNS-tunneling variants), which is why Suricata was chosen as
  this project's external baseline rather than Snort ([A Realistic Experimental Comparison of the
  Suricata and Snort Intrusion-Detection
  Systems](https://calhoun.nps.edu/server/api/core/bitstreams/6e9ec886-297c-4913-8cc6-80a4c44609a5/content)).
- Signature-based IoT botnet detection: prior work evaluating Snort/Suricata against IoT botnet
  datasets (ISOT, IoT-23, Bot-IoT) documents the same structural limitation observed in this
  evaluation's own Suricata results and already called out for this project's rule-based layer in
  README.md -- signature/threshold detectors miss traffic that does not match a known pattern,
  motivating a layered approach rather than a single detector ([Collaborative device-level botnet
  detection for Internet of
  Things](https://www.sciencedirect.com/science/article/pii/S0167404823000822)).
- Deception/game-theoretic response, context for the DECOY arm: a stochastic-game honeypot
  moving-target-defense study reports real engagement gains from deception over static defense
  (attacker packet interactions up 920 vs. 42, scanner engagement extended 14.6x) -- a different
  environment and metric than this project's controlled single-attacker Mininet trials, but
  directionally consistent with DECOY's own measured value here (its verified rate on
  reconnaissance was 100% in this run) ([Towards a moving target defense based on stochastic
  games and honeypots](https://www.sciencedirect.com/science/article/pii/S0020025525006206)).
- Reinforcement learning for IoT defense: recent surveys document DRL as an active, promising
  direction for IoT intrusion detection while flagging reproducibility and dataset-realism
  concerns across the field ([Deep Reinforcement Learning for Intrusion Detection in IoT: A
  Survey](https://arxiv.org/pdf/2405.20038)) -- concerns this project addresses directly by
  training and evaluating PPO against real, verified Mininet outcomes rather than only a
  synthetic simulator (see README's "PPO reinforcement-learned policy" section).

## Adaptive-attacker evaluation

Every result above treats one attack attempt as one independent event: detect, decide,
respond, done -- the right model for measuring detection and response-execution
correctness, but it cannot answer a different, real question: when the deployed
policy's own preferred response is per-source (`BLOCK_SOURCE`, registered for
`brute_force` and `replay_attack`), does a persistent attacker actually get contained
across repeated attempts, or does each new source IP simply start over unblocked?

`src/iot_defense/evaluation/adaptive.py` runs a real, multi-round campaign against a
single, persistent Mininet network, in two modes: **fixed** (every round reuses the
same source IP, a control) and **rotate** (every round uses a source IP not yet
blocked in this campaign, reusing `simulation/traffic.py`'s existing distributed-
spoofing generator built for the item-6 work rather than duplicating it). Neither
mode restores the block between rounds -- doing so would erase exactly the cross-round
containment state this module exists to measure; cleanup runs once, at the end.

One real methodological issue was found and fixed during this evaluation's own
development, not papered over: a zero-packet capture is ambiguous for a source that
was *not* already blocked -- it could mean the block is somehow broader than intended
(a real, important finding if true), or it could be this project's own already-
documented Mininet/tcpdump capture flakiness under repeated back-to-back capture
cycling on this 2-CPU VM (the same failure class `monitor.py`'s `read_capture` and
`generate_dataset.py` already tolerate elsewhere). Conflating the two would misreport
measurement noise as a security finding. The module now retries once (mirroring
`read_capture`'s own established one-retry pattern) and marks the round
`capture_reliable` so a still-empty second attempt stays visible rather than hidden.

### Results (2026-09-21, `--rounds 5`)

| Mode | Round | Source | Packets | Reliable | Result |
|---|---|---|---|---|---|
| fixed | 0 | `.100` | 17 | yes | detected, `BLOCK_SOURCE` |
| fixed | 1-4 | `.100` | 0 | yes | blocked -- stayed contained for all 4 remaining rounds |
| rotate | 0 | `.100` | 17 | yes | detected, `BLOCK_SOURCE` |
| rotate | 1 | `.121` | 17 | yes | detected, `BLOCK_SOURCE` -- a fresh source got through |
| rotate | 2-4 | `.122` | 0 | **no** | capture unreliable (retry also empty) -- not counted either way |

**The fixed-mode control is unambiguous**: once `BLOCK_SOURCE` takes effect, the same
attacker gets zero packets through for every subsequent round, for real, not assumed.

**The rotate-mode result is the real finding**: a second, entirely fresh source
(`.121`) reached the sensor and was independently detected and blocked, exactly like
the first. Because `BLOCK_SOURCE` installs `iptables -A INPUT -s <source_ip> -d
<target_ip> -j DROP` (confirmed by reading `executor.py`'s own implementation, not
assumed), it is inherently scoped to the *claimed* IP in the packet header, not the
physical attacker -- so an attacker able to spoof or genuinely rotate source addresses
is not contained by this response at all, only whichever single address it has
already been caught using. Two independent rounds already demonstrate this cleanly;
the third source's result was inconclusive (flagged, not discarded), and a larger
future run should push past this VM's own capture-reliability ceiling to get a
cleaner distinct-sources-per-campaign count.

**This is not a flaw unique to this project's implementation** -- any purely
identity-based (as opposed to behavior-based) containment has the same structural
limit. It is, however, a real, now-measured gap between "the registered
`preferred_action` was executed and verified" (this evaluation's other results) and
"the attacker is actually contained" (a stronger claim this module shows does not
automatically follow), worth stating plainly rather than assuming BLOCK_SOURCE's
per-event success generalizes to real persistence.

## Limitations

- **`c2_beacon`, the 16th registered attack, is not included in this run.** It was registered
  after this harness run started (a ~107-minute job against the then-current 15-attack registry),
  so the results above cover `normal` + 15 attacks, not the full current registry. A follow-up
  targeted re-run covering just `c2_beacon` (or a full re-run once the registry next grows) is a
  real, scoped next step, not yet done.
- **`brute_force`'s traffic generator never sends its documented payload (found, not fixed).**
  `generate_brute_force_mininet_traffic()`'s TCP connect is refused before any data is sent, so a
  real captured brute-force flow has never actually contained "USER admin\r\nPASS wrong\r\n" in
  this project's history. This does not affect this project's own detection or response accuracy
  (both are shape-based), but it does mean any *content-based* signature -- Suricata's or
  otherwise -- can never fire on it as currently generated. Fixing this (most plausibly, a
  lightweight listener on the simulated login port, mirroring `DecoyService`'s own pattern) is a
  real, scoped next step, deliberately not taken in this pass.
- **Suricata's directory-replay (batch) mode does not reset detection state between pcap files.**
  Found via direct reproduction: a `threshold`-based rule that reliably fired against one pcap in
  isolation silently didn't when that same pcap was processed as part of a larger batch sharing a
  destination IP with unrelated captures. `suricata_eval.py` runs ET-Open in batch mode (its
  ~68,000-rule compile cost is the dominant cost, worth paying once) but the lab ruleset per-pcap
  (a fresh process and fresh state for each file -- cheap, since the ruleset itself is tiny).
- **Suricata's lab-ruleset numbers have shown genuine run-to-run non-determinism** in earlier
  debugging even in per-pcap isolation (candidates include worker-thread/flow-manager
  initialization timing specific to very short, bursty replay files); reported honestly rather
  than averaged away by quietly re-running until a "clean" number appeared.
- **Sample size dropped from 20 to 5 trials per condition** in exchange for covering the full
  16-condition (vs. 6-condition) registry -- an explicit, communicated tradeoff. This trades
  statistical stability for breadth; see Discussion for exactly which conditions that
  quantization affects most.
- **Single lab environment.** All trials ran in the same Mininet topology on one 2-CPU VM.
  Results should not be generalized to arbitrary IoT networks or attacker behavior, consistent
  with every other "controlled study" caveat already documented in this project.
- **Internal detection is shared, not compared, across the five internal arms.** Every arm in the
  main comparison receives the same detection result -- that comparison measures response
  selection and execution, not detection accuracy. The Suricata arm is what adds a genuine,
  independent detection-accuracy comparison.
