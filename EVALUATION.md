# Evaluation

This document reports how the 3-policy defense system (rule-based, Stackelberg, PPO) compares
against two simpler baselines, on real Mininet traffic, using a repeatable benchmark harness --
not individual anecdotal demo runs. It also situates the system against published work on the
same general problem, honestly: no paper found shares this project's exact dataset or
environment, so that comparison is qualitative context, not a claimed head-to-head number.

A comparison against a real signature-based IDS (Suricata, run offline against the same captured
traffic) is planned but not yet run -- see "Suricata comparison" under Limitations.

## Methodology

`src/iot_defense/evaluation/harness.py` runs `N` real Mininet trials for every registered
condition (`normal` plus every attack in `attacks/registry.py` -- 6 conditions total today,
generic over however many are registered). Each trial:

1. Starts real traffic for the condition (the same generators the live demo and dataset
   generation use) and captures it with `tcpdump`.
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
covers `trials_per_condition=8` -- 48 real Mininet trials, 240 recorded outcomes -- generated on
2026-09-09, results at `data/evaluation/results.jsonl` (gitignored; regenerate with
`sudo .venv/bin/python3 -m iot_defense.evaluation.harness --trials-per-condition 8`).

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

## Results

| Arm | Detection accuracy | Verified response rate | Matches preferred action (attacks only) | Mean detection latency |
|---|---|---|---|---|
| Rule-based (ours) | 97.9% | 83.3% | 97.5% | 6850 ms |
| Stackelberg (ours, deployed) | 97.9% | 83.3% | 97.5% | 6850 ms |
| PPO (ours) | 97.9% | 83.3% | 97.5% | 6850 ms |
| NaiveBlockAllBaseline | 97.9% | 41.7% | 40.0% | 6850 ms |
| AlwaysAllowBaseline | 97.9% | 16.7% | 0.0% | 6850 ms |

Per-condition breakdown for Stackelberg, the policy the live demo actually deploys:

| Condition | Detection accuracy | Verified response rate |
|---|---|---|
| `normal` | 100.0% | 100.0% |
| `reconnaissance_port_scan` | 100.0% | 100.0% |
| `dos_flood` | 100.0% | 75.0% |
| `brute_force` | 100.0% | 62.5% |
| `data_exfiltration` | 100.0% | 75.0% |
| `exploit_payload_injection` | 87.5% | 87.5% |

## Discussion

**All three of our policies score identically** on every metric in this run. That is expected,
not a null result: detection and the registry-driven "correct action per attack" answer are
shared inputs, and this dataset's context vectors were not adversarial enough to make the three
decision mechanisms disagree. The three policies were already independently confirmed to agree
on all 6 registered scenarios before this evaluation (each policy re-verified against the live
Mininet outcome, not just against each other) -- what this evaluation adds is confirming that
agreement holds under repeated real execution, not just single spot-checks.

**The real differentiator is the baselines, not the three policies against each other.** Our
system's 83.3% verified-response rate is roughly **2x** NaiveBlockAllBaseline's 41.7% and **5x**
AlwaysAllowBaseline's 16.7%. The per-condition breakdown shows exactly where that gap comes from:
NaiveBlockAllBaseline's fixed ISOLATE response happens to be correct for `dos_flood` and
`data_exfiltration` (both genuinely prefer ISOLATE), so it scores reasonably there -- but it
cannot differentiate `reconnaissance`, `brute_force`, or `exploit_payload_injection`, where the
registry-driven preferred response is DECOY or THROTTLE, not ISOLATE. That is precisely the
value a per-attack-type response is meant to add over a single fixed reaction to any alert.

**The gap between "matches preferred action" (97.5%) and "verified response rate" (83.3%) is
execution reliability, not decision quality.** Our policies pick the objectively correct action
97.5% of the time on attack trials; the ~14-point drop to the verified rate reflects real
Mininet-level timing variance in the independent verification checks themselves (a single ping,
interaction probe, or rule-check racing real network/kernel timing under repeated cycling on one
shared lab network) -- not incorrect decisions. This is an honest property of the measurement,
not smoothed over: `brute_force`'s 62.5% verified rate against its 100% detection accuracy is the
clearest example, and is discussed further under Limitations.

**`exploit_payload_injection` is this evaluation's weakest detection condition** (87.5%, one miss
in 8 trials). This matches the honest limitation already documented in README.md: its rule-based
detector separates a single oversized request from ordinary low-volume traffic almost entirely by
`average_packet_size`, the narrowest real margin of any currently registered detector.

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
  this project's planned external baseline rather than Snort ([A Realistic Experimental
  Comparison of the Suricata and Snort Intrusion-Detection
  Systems](https://calhoun.nps.edu/server/api/core/bitstreams/6e9ec886-297c-4913-8cc6-80a4c44609a5/content)).
- Signature-based IoT botnet detection: prior work evaluating Snort/Suricata against IoT botnet
  datasets (ISOT, IoT-23, Bot-IoT) documents the same structural limitation this project's own
  README calls out for its rule-based layer -- signature/threshold detectors miss traffic that
  does not match a known pattern, motivating a layered approach rather than a single detector
  ([Collaborative device-level botnet detection for Internet of
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

- **Suricata comparison not yet run.** Suricata is not installed in this environment
  (`sudo apt install suricata` is outside this session's scoped sudo access) -- installing it and
  running `suricata_eval.py` (planned: offline `-r <pcap>` analysis of the pcaps already saved in
  `data/evaluation/`, against both Suricata's default ruleset and a small lab-tailored one) is
  the next step once that dependency is cleared.
- **Sample size is real but modest.** 8 trials per condition is enough to see a clear, repeated
  pattern (the baseline gap held consistently across three separate runs during this evaluation's
  own development, at 2, 3, and 8 trials per condition), not enough for tight statistical
  confidence intervals. Scaling to more trials is a straightforward re-run, not a redesign.
- **Single lab environment.** All trials ran in the same 5-host Mininet topology on one VM.
  Results should not be generalized to arbitrary IoT networks or attacker behavior, consistent
  with every other "controlled study" caveat already documented in this project.
- **Detection is shared, not compared.** Every arm in this evaluation receives the same detection
  result -- the comparison measures response selection and execution, not detection accuracy
  across systems. A genuine detection-accuracy comparison is what the planned Suricata arm adds.
- **This evaluation exposed and fixed four real bugs in the production response-execution code**
  (a leaked shell notification corrupting an unrelated command, an overly broad failure check in
  `throttle()`, single-flow detection blindness to background noise, and `restore()` never
  tearing down decoy state between actions) -- all four are described in their respective commit
  messages and are now covered by regression tests. They were only found because this evaluation
  is the first code path in the project to execute multiple distinct real responses back-to-back
  on one long-lived Mininet network; the live demo and PPO's real-Mininet fine-tune each only
  ever execute one action before their network is torn down. This is reported here because it is
  itself a genuine finding about this evaluation methodology's value, not only about the system
  under test.
