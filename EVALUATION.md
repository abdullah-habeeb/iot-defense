# Evaluation

> **Stale as of 2026-09-20 -- read before trusting any number below.** This report's numbers
> (120 trials, generated 2026-09-10) describe a 6-condition, 5-defense-action version of this
> system: `normal` + the original 5 attacks, `ALLOW`/`ALERT`/`ISOLATE`/`DECOY`/`THROTTLE` only.
> The registry has since grown to 16 conditions (10 more attacks) and 10 defense actions (5 more,
> plus 5 attacks reassigned to a better-fitting one -- see README's "Defense actions" section).
> The `UnifiedRuleBasedDetector`/Stackelberg/PPO comparison mechanics below are all still
> accurate and unchanged; only the specific numbers and per-condition table are out of date.
> Regenerating this report against the full current registry is a real, multi-hour undertaking
> (one of the new attacks alone runs ~110s per trial) and has not been done yet -- treat every
> number below as historical, not current, until it is.

This document reports how the 3-policy defense system (rule-based, Stackelberg, PPO) compares
against two simpler baselines and a real signature-based IDS (Suricata), on real Mininet traffic,
using a repeatable benchmark harness -- not individual anecdotal demo runs. It also situates the
system against published work on the same general problem, honestly: no paper found shares this
project's exact dataset or environment, so that comparison is qualitative context, not a claimed
head-to-head number.

## Methodology

`src/iot_defense/evaluation/harness.py` runs `N` real Mininet trials for every registered
condition (`normal` plus every attack in `attacks/registry.py` -- 6 conditions total today,
generic over however many are registered). Each trial:

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
covers `trials_per_condition=20` -- **120 real Mininet trials, 600 recorded outcomes** --
generated on 2026-09-10, results at `data/evaluation/results.jsonl` (gitignored; regenerate with
`sudo .venv/bin/python3 -m iot_defense.evaluation.harness --trials-per-condition 20`).

**Metrics**:
- *Detection accuracy* -- did the shared detector correctly classify the captured traffic. This
  runs once per trial and every arm sees the same result, so it is reported per arm as a sanity
  check, not because arms are expected to differ on it.
- *Matches preferred action (attacks only)* -- of the attack trials, how often the arm's chosen
  action was the one this project's registry defines as correct for that attack (THROTTLE for
  brute-force, DECOY for reconnaissance/exploit, ISOLATE for dos/exfiltration).
- *Verified response rate* -- of **all** trials, how often the arm both chose the preferred
  action **and** that action's real effect was independently confirmed (not just "the command
  didn't error"). This is the headline comparison metric: it is 0 whenever the wrong action was
  chosen, and only counts a real, checked success.

A second, independent arm was added after the internal comparison was already running: offline
Suricata analysis of the same 120 pcaps (`src/iot_defense/evaluation/suricata_eval.py`), against
two rulesets -- ET-Open (real-world community threat signatures, fetched via `suricata-update`)
and a small lab-tailored ruleset (`config/suricata/lab.rules`, written to encode the same shape
knowledge `detection/detector.py`'s own rule-based detectors use, so Suricata is judged on a fair
signature-matching version of that knowledge too, not only on a strawman of unrelated real-world
malware signatures). *Detector*, not *response*, is the axis Suricata is compared on: Suricata
identifies traffic, it does not select or execute a containment action, so its comparison metrics
are accuracy/true-positive-rate/false-positive-rate against ground truth, not verified-response
rate.

## Results

| Arm | Detection accuracy | Verified response rate | Matches preferred action (attacks only) | Mean detection latency |
|---|---|---|---|---|
| Rule-based (ours) | 97.5% | 85.8% | 97.0% | 6198 ms |
| Stackelberg (ours, deployed) | 97.5% | 85.8% | 97.0% | 6198 ms |
| PPO (ours) | 97.5% | 85.8% | 97.0% | 6198 ms |
| NaiveBlockAllBaseline | 97.5% | 44.2% | 40.0% | 6198 ms |
| AlwaysAllowBaseline | 97.5% | 16.7% | 0.0% | 6198 ms |

Per-condition breakdown for Stackelberg, the policy the live demo actually deploys:

| Condition | Detection accuracy | Verified response rate |
|---|---|---|
| `normal` | 100.0% | 100.0% |
| `reconnaissance_port_scan` | 100.0% | 100.0% |
| `dos_flood` | 100.0% | 85.0% |
| `brute_force` | 100.0% | 65.0% |
| `data_exfiltration` | 100.0% | 80.0% |
| `exploit_payload_injection` | 85.0% | 85.0% |

External detection comparison (Suricata, offline analysis of the same 120 pcaps):

| Detector | Accuracy | True positive rate | False positive rate |
|---|---|---|---|
| Suricata + ET-Open (real-world community rules) | 62.5% | 59.0% | 20.0% |
| Suricata + lab-tailored rules (this project's own signatures) | 64.2% | 57.0% | 0.0% |
| This project's `UnifiedRuleBasedDetector` | 97.5% | -- | 0.0% (0/20 `normal` trials misclassified) |

## Discussion

**All three of our policies score identically** on every metric in this run. That is expected,
not a null result: detection and the registry-driven "correct action per attack" answer are
shared inputs, and this dataset's context vectors were not adversarial enough to make the three
decision mechanisms disagree. The three policies were already independently confirmed to agree
on all 6 registered scenarios before this evaluation (each policy re-verified against the live
Mininet outcome, not just against each other) -- what this evaluation adds is confirming that
agreement holds under repeated real execution at scale (120 trials), not just single spot-checks.

**The real differentiator is the baselines, not the three policies against each other.** Our
system's 85.8% verified-response rate is roughly **2x** NaiveBlockAllBaseline's 44.2% and **5x**
AlwaysAllowBaseline's 16.7% -- consistent with the smaller (48-trial) run this evaluation started
with, and holding at more than double the sample size. The per-condition breakdown shows exactly
where that gap comes from: NaiveBlockAllBaseline's fixed ISOLATE response happens to be correct
for `dos_flood` and `data_exfiltration` (both genuinely prefer ISOLATE), so it scores reasonably
there -- but it cannot differentiate `reconnaissance`, `brute_force`, or
`exploit_payload_injection`, where the registry-driven preferred response is DECOY or THROTTLE,
not ISOLATE. That is precisely the value a per-attack-type response is meant to add over a single
fixed reaction to any alert.

**Suricata's own rule-based detection -- both rulesets -- lands well below this project's own
`UnifiedRuleBasedDetector`** (62-64% accuracy vs. 97.5%), which is worth being precise about
*why*, not just reporting the gap. This project's detector is a single, small, purpose-built
5-class classifier over 12 behavioural flow features, run once against the one flow already known
to matter for a given trial. Suricata is a general packet-inspection engine running two rulesets
that were never built around this project's specific traffic; ET-Open's ~68,000 signatures target
real-world malware and CVEs, and even the lab-tailored ruleset had to be reverse-engineered from
the same traffic-shape knowledge this project's own detector already encodes. This is not "our
detector beats a production IDS" in any general sense -- it is a small, task-specific classifier
outperforming a general-purpose engine at a narrow task it was never specialized for, which is an
expected and unsurprising result, reported for completeness rather than as a strong claim.

**Suricata's own false-positive rates diverge in an informative way**: ET-Open alerted on 20% of
`normal` trials (a real-world ruleset reacting to something in ordinary Mininet housekeeping
traffic -- ARP, IPv6 neighbour discovery -- that looks superficially unusual to signatures tuned
for the open internet), while the lab-tailored ruleset had 0% false positives, since it was
written with this exact traffic in mind. Neither number should be read as "Suricata is bad at
this" -- both reflect a ruleset evaluated well outside the traffic distribution it was designed
or tuned for.

**The gap between "matches preferred action" (97.0%) and "verified response rate" (85.8%) is
mostly execution reliability, not decision quality** -- with one real, confirmed exception found
by this evaluation. Our policies pick the objectively correct action 97% of the time on attack
trials; most of the drop to the verified rate reflects genuine Mininet-level timing variance in
the independent verification checks themselves (a single ping, interaction probe, or rule-check
racing real network/kernel timing under repeated cycling on one shared lab network). `brute_force`
is a partial exception: investigating why its lab-tailored Suricata signature never fired led to
discovering that `simulation/traffic.py`'s `generate_brute_force_mininet_traffic()` never actually
delivers its documented "USER admin" login payload onto the wire in a live Mininet run -- the TCP
`connect()` to the sensor's simulated login port is refused (nothing listens there outside an
active DECOY response), so `sendall()` never executes, and only bare SYN/RST packets are ever
captured. This has been true since brute-force was added and was never caught, because this
project's own `RuleBasedBruteForceDetector` is purely shape-based (rate, port, packet count) and
never needed the payload content to work correctly -- it's a real gap, found only because this
evaluation's Suricata comparison needed content to actually be present, not something the
project's own detection accuracy was ever affected by. **Reported, not fixed, in this pass** --
see Limitations.

**`exploit_payload_injection` is this evaluation's weakest internal-detection condition** (85.0%,
3 misses in 20 trials). This matches the honest limitation already documented in README.md: its
rule-based detector separates a single oversized request from ordinary low-volume traffic almost
entirely by `average_packet_size`, the narrowest real margin of any currently registered detector.

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

## Limitations

- **`brute_force`'s traffic generator never sends its documented payload (found, not fixed).**
  See Discussion above -- `generate_brute_force_mininet_traffic()`'s TCP connect is refused before
  any data is sent, so a real captured brute-force flow has never actually contained
  "USER admin\r\nPASS wrong\r\n" in this project's history. This does not affect this project's
  own detection or response accuracy (both are shape-based), but it does mean any *content-based*
  signature -- Suricata's or otherwise -- can never fire on it as currently generated. Fixing this
  (most plausibly, a lightweight listener on the simulated login port, mirroring `DecoyService`'s
  own pattern) is a real, scoped next step, deliberately not taken in this pass since this
  evaluation's own scope was the comparison, not a traffic-generator redesign.
- **Suricata's directory-replay (batch) mode does not reset detection state between pcap files.**
  Found via direct reproduction: a `threshold`-based rule that reliably fired against one pcap in
  isolation silently didn't when that same pcap was processed as part of a 120-file batch sharing
  a destination IP with unrelated captures. `suricata_eval.py` runs ET-Open in batch mode (its
  ~68,000-rule compile cost is the dominant cost, worth paying once) but the lab ruleset per-pcap
  (a fresh process and fresh state for each file -- cheap, since the ruleset itself is tiny).
- **The `dos_flood` lab-tailored signature showed genuine run-to-run non-determinism even in
  per-pcap isolation** -- the exact same Suricata invocation against the exact same single pcap
  alerted on some runs and not others during this evaluation's own debugging. The underlying cause
  was not fully isolated (candidates include worker-thread/flow-manager initialization timing
  specific to very short, bursty replay files); reported honestly rather than averaged away by
  quietly re-running until a "clean" number appeared. The `lab` ruleset's reported 57% true
  positive rate should be read with this specific caveat, not as a precise, fully reproducible
  figure the way this project's own internal harness numbers are.
- **Sample size is real but modest.** 20 trials per condition is enough to see a clear, stable,
  repeated pattern (the baseline gap held consistently across four separate runs during this
  evaluation's own development, at 2, 3, 8, and 20 trials per condition), not enough for tight
  statistical confidence intervals. Scaling further is a straightforward re-run, not a redesign.
- **Single lab environment.** All trials ran in the same 5-host Mininet topology on one VM.
  Results should not be generalized to arbitrary IoT networks or attacker behavior, consistent
  with every other "controlled study" caveat already documented in this project.
- **Internal detection is shared, not compared, across the five internal arms.** Every arm in the
  main comparison receives the same detection result -- that comparison measures response
  selection and execution, not detection accuracy. The Suricata arm is what adds a genuine,
  independent detection-accuracy comparison.
- **This evaluation exposed and fixed five real bugs in the production code**, across three
  separate rounds of scaling up (a leaked shell notification corrupting an unrelated command, an
  overly broad failure check in `throttle()`, single-flow detection blindness to background noise,
  `restore()` never tearing down decoy state between actions, and a pcap-filename path-matching
  bug in the Suricata analysis code itself) -- all five are described in their respective commit
  messages and are now covered by regression tests. Four were only found because this evaluation
  is the first code path in the project to execute multiple distinct real responses back-to-back
  on one long-lived Mininet network; the live demo and PPO's real-Mininet fine-tune each only ever
  execute one action before their network is torn down. The `brute_force` payload gap above is a
  sixth, found but not yet fixed. This is reported here because it is itself a genuine finding
  about this evaluation methodology's value, not only about the system under test.
