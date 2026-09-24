# Evaluation

This document reports how the 3-policy defense system (rule-based, Stackelberg, PPO) compares
against two simpler baselines and a real signature-based IDS (Suricata), on real Mininet traffic,
using a repeatable benchmark harness -- not individual anecdotal demo runs. It also situates the
system against published work on the same general problem, honestly: no paper found shares this
project's exact dataset or environment, so that comparison is qualitative context, not a claimed
head-to-head number.

**Scope boundary, stated once here and not repeated as a caveat on every table below:** every
number in this document comes from **one topology, on one 2-CPU/~2.9GB lab VM, running Mininet**.
No claim in this document should be read as "this generalizes to arbitrary IoT networks, hardware,
or attacker populations" -- it has not been tested on more than this single environment, and this
project does not have the infrastructure to test that here. Every table and every percentage below
describes *this system, on this VM, on this topology* -- a controlled, internally-valid comparison
between the arms tested, not an externally-valid claim about IoT security in general. Where a
result plausibly reflects VM-specific timing/resource variance rather than the system's actual
behavior (flagged explicitly where it occurs, e.g. the Discussion's treatment of
`icmp_ping_flood`/`slow_loris_exhaustion`), that ambiguity is disclosed, not resolved in the
system's favor.

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
different metrics and environments than this project's controlled Mininet lab. This document
makes no claim to outperform, or be directly comparable to, any of the papers below -- each is
cited as architectural or methodological context, on its own dataset/environment/metric, not as a
number this evaluation's own results are benchmarked against. Two papers came closest to this
project's own combination of ideas and are named explicitly so that closeness, and its limits, are
stated plainly rather than left for a reviewer to find:

- **Closest single match for the Stackelberg arm**: a 2025 paper models collaborative IoT
  packet-sampling against DDoS as a Stackelberg game and derives a sampling-rate lower bound that
  deters an attacker -- the same game-theoretic framing this project uses, but for a different
  decision (a sampling rate, not a choice among discrete response actions like ISOLATE/DECOY/
  THROTTLE) and evaluated analytically/in simulation, not against real captured Mininet traffic
  ([Stackelberg Game for Resilient Collaborative Cyber Threat Detection and Response in IoT
  Networks](https://www.researchgate.net/publication/398764870_Stackelberg_Game_for_Resilient_Collaborative_Cyber_Threat_Detection_and_Response_in_IoT_Networks)).
- **Closest single match for the PPO arm's cost framing**: a 2025 paper evaluates an RL-tuned
  moving-target-defense mutation strategy for edge IoT against DDoS specifically on attack success
  rate, defense latency, and CPU overhead -- the same *category* of cost-conscious framing this
  project's own cost/overhead analysis (below) uses, but for mutating network configuration rather
  than selecting among this project's own discrete response actions, and again not on shared,
  real, captured traffic ([An optimized reinforcement learning based MTD mutation strategy for
  securing edge IoT against DDoS
  attack](https://www.sciencedirect.com/science/article/pii/S2214212625001759)).

Neither paper, nor any other found, shares this project's dataset, environment, or exact decision
space -- which is precisely why this document's own numbers are reported as an internally-valid
comparison between the arms tested here (see the scope boundary above), not translated into a
claimed head-to-head standing against either of them.

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

## Disclosed defects found during a systematic review, and whether they affected reported results

A full, adversarial review of every subsystem (not just the code touched by any one
change) found and fixed 21 real issues, ranging from a firewall-rule leak to stale
comments. This section states plainly what each one was, whether it could have reached
any number reported in this document, and how that was actually checked -- not assumed.

**Reached no reported evaluation data (checked directly, not assumed):**

- **`quarantine()`/`bandwidth_cap()` multi-source leak.** Both required a *second*
  distinct-source call against an already-actioned target with no `restore()` in
  between. `harness.py`'s own design restores after every single trial before the
  next one begins -- the precondition for the leak literally cannot occur inside this
  evaluation's own trial loop.
- **`block_source()`/`reset_sessions()` unsanitized shell interpolation.** Required a
  malformed/attacker-controlled `source_ip` string; every value the harness ever
  passes is a real Mininet host IP or a registry-derived attacker address, never
  user- or attacker-supplied text.
- **The `dns_amplification`/`firmware_tampering` detector window overlap** (a real
  `[4.0, 5.0)` packets-per-second band where both detectors fired). Checked directly
  against the actual harness data, not inferred: all 5 `firmware_tampering` trials in
  the results classified correctly as `firmware_tampering`, 0 as `dns_amplification`.
  Real `firmware_tampering` traffic paces at ~3.33 pps, comfortably outside the
  overlapping band.
- **The fake "fallback to rule-based" in `demo/controller.py`.** That code path is
  the live-demo/dashboard state machine; `harness.py` calls
  `RuleBasedDefensePolicy`/`StackelbergDefensePolicy` directly and never goes through
  `controller.py` at all. Zero exposure to this evaluation's own numbers by
  construction, not by luck.
- **The PPO arm's authenticity.** Directly checked, not assumed, after a review
  raised the question of whether the harness's own long-running process could have
  silently hit the observation-shape mismatch that was separately found in a live
  demo run, with `PPODefensePolicy`'s internal fallback silently substituting
  rule-based decisions under the "ppo" label. It did not: all 80 `ppo` rows in the
  results are present (0 null/failed rows), none carry the `ppo_fallback` marker
  `PPODefensePolicy` sets when its model file is genuinely missing, and `PPO.load()`
  succeeded against the model deployed when the harness process started (which
  matched that process's own in-memory registry size for its entire run, since
  Python does not hot-reload an already-imported module even if the file on disk
  changes mid-run). The PPO numbers in this report are real model predictions.

**Coverage/documentation gaps, not runtime bugs — no data to have corrupted:**
the tautological Stackelberg-vs-registry test, the dead `capture_duration_seconds`
field, 12 previously-untested detectors, `harness.py`'s own previously-zero unit
test coverage, three now-consolidated sources of truth for host IPs, a dead helper
method, a dead import, and several stale comments. None of these executed different
logic at evaluation time than the logic whose output is reported here -- they were
gaps in what was *tested* or *documented*, not defects in what *ran*.

**A real, disclosed limitation on the deployed model, not a data-integrity issue:**
the PPO training recipe's own seed-robustness was found to be weaker than first
believed -- an earlier 6-seed sweep showed 4 of 6 seeds failing to converge every
scenario to its registered `preferred_action` at the recipe then in use. The recipe was
fixed (architecture and rollout-size changes; see `simulation/train_ppo.py`'s own
comment) and formally re-validated with error bars (see "PPO training seed-robustness"
below); the model deployed for this evaluation's own run was retrained with that
corrected recipe before this harness run started, and independently re-verified
(17/17 scenarios) immediately before launch.

This project treats a systematically-found-and-fixed defect as a methodology
strength worth stating plainly, not a finding to omit: the alternative -- an external
reviewer or replicator finding one of these independently -- would cost far more
credibility than disclosing them here does.

## PPO training seed-robustness

The recipe fix above was validated on a single seed at the time -- not itself a
resolved claim of robustness. `src/iot_defense/evaluation/ppo_seed_robustness.py`
formalizes that check: it trains 10 independent models at the exact corrected recipe
(`net_arch=[64,64]`, `ent_coef=0.01`, `n_steps=170`, `batch_size=170`, `lr=0.001`,
`timesteps=25500`), varying only the seed (`1, 2, 3, 7, 13, 17, 42, 55, 88, 99`), and
checks each one's convergence to every registered `preferred_action` the same way this
project's own PPO regression test does -- reporting the aggregate rate with a Wilson CI
rather than a single anecdote.

**Results (2026-09-24):**

| Seeds tested | Fully converged | Rate | 95% CI |
|---|---|---|---|
| 10 | 8 | 80.0% | (49.0%, 94.3%) |

**Both failures were the same kind of mistake, not two different ones**: seed 17 chose
`THROTTLE` instead of `ALLOW` on `normal` traffic, and seed 55 chose `DECOY` instead of
`ALLOW` on `normal` traffic -- both are false-positive-style errors on the *no-attack*
case, not a missed or misclassified attack. Every one of the 10 seeds converged
correctly on every real attack scenario; the recipe's residual instability, at this
sample size, is specifically in reliably learning restraint on `normal` traffic, not in
learning to respond to attacks. The wide CI (49-94%) is itself an honest, disclosed
result of testing at n=10 -- it does not support a claim tighter than "most seeds
converge fully; this specific instability mode recurs in roughly a fifth of runs," and
this document does not claim more than that. The model actually deployed for this
evaluation's own harness run was independently re-verified (17/17) immediately before
that run started, so the deployed checkpoint itself is not in the two failing seeds --
but a paper citing this system's PPO arm should cite this 80% (49-94% CI) figure, not
the single deployed checkpoint's own clean verification, as the honest statement of
training-recipe reliability.

## Evaluating decision divergence directly (not just on real captured traffic)

The comparison above shows rule-based, Stackelberg, and PPO choosing identical
actions on every one of the real trials -- a real result, not an error, but on its
own it cannot support any claim that these are three meaningfully different decision
mechanisms, because real captured traffic in this lab classifies far from any
threshold boundary every time: confidently classified, all three policies were each
independently designed (via rule-based's own thresholds, Stackelberg's payoff
tables, and PPO's training reward) to reach the same registry-declared
`preferred_action` for exactly that case. Agreement there is closer to a consistency
check than a comparison.

`src/iot_defense/evaluation/policy_disagreement.py` tests the three real policy
classes directly against synthetic `SecurityContext`s built two ways: (1)
threat_score/confidence perturbed around each attack's own registered
`action_score_min`/`action_confidence_min` boundary (`±0.03` to `±0.15`, 784
contexts across the full registry), where a real detector's honest uncertainty would
actually place a reading; and (2) entirely unregistered "novel" attack types no
policy was ever tuned for (12 contexts), probing generalization rather than
in-distribution ambiguity. No Mininet is needed -- these evaluate the real
`RuleBasedDefensePolicy`, `StackelbergDefensePolicy`, and `PPODefensePolicy` classes
directly, the same pattern this project's own PPO-convergence checks already use.

**Results (2026-09-24, `models/ppo_defense.zip` -- the recipe re-validated above):**

| | Rule vs. Stackelberg | Rule vs. PPO | Stackelberg vs. PPO | All three |
|---|---|---|---|---|
| Near decision boundaries (n=784) | 32.5% agree | 32.5% agree | **100% agree** | 32.5% agree |
| Novel/unseen attack types (n=12) | -- | -- | -- | 0% agree |

**Near decision boundaries, rule-based diverges from both Stackelberg and PPO on
roughly two-thirds of ambiguous contexts** -- exactly where a real, honest detector
reading would land under genuine uncertainty, not a corner case. Stackelberg and PPO
track each other closely (100% agreement in this run) even off the exact training
distribution: a real, positive finding that the learned policy generalizes toward
the same strategic reasoning the game-theoretic solver encodes explicitly, rather
than only memorizing the clean, high-confidence cases the harness's own real traffic
happens to produce.

**On entirely unregistered attack types, the three policies fail in different, worth-
disclosing ways.** Rule-based and Stackelberg both degrade to `ALERT` every time --
a real, deliberately-tested safe default for a `threat_type` neither recognizes (see
`RuleBasedDefensePolicy`'s own no-match branch and the pre-check added to
`StackelbergDefensePolicy.decide()` after this project's own system review). **PPO
instead selects `ISOLATE` regardless of the actual threat_score or confidence
supplied.** This is disclosed here as a genuine limitation, not smoothed over: unlike
the other two policies, PPO has no mechanism for recognizing "I have never seen
anything like this" and responding cautiously or by falling back -- its behavior
outside the training distribution is a fixed action, an artifact of how a trained
network extrapolates rather than a reasoned response to novelty. Whether a fixed
`ISOLATE` is an acceptable fail-safe default or a real generalization failure is left
as an open question this project does not claim to resolve -- it is reported because
a paper claiming PPO "learns adaptive defense" needs to state this boundary
explicitly, not discover it via a reviewer's own testing.

## Detector calibration: robustness beyond the exact tuned point

Every attack's own detection window was hand-placed to be clear of every other
registered detector's window for *this* system's own generated traffic -- including,
for `c2_beacon`, via an explicit 432-combination sweep. That is calibrating the
evaluation to the system under test, and it is a real, unresolved threat to external
validity this document does not claim to have fixed: only an independent, standard
dataset (e.g. IoT-23, Bot-IoT, CIC-IoT2023, N-BaIoT, TON_IoT) that this project's own
detectors were never tuned against could close it, and that has not been done.

What `src/iot_defense/evaluation/detector_robustness.py` *does* answer is a narrower,
adjacent question: is each detector's calibration a brittle single point, or does it
have real margin? Every numeric feature in each attack's own real signature was
perturbed by `-30%` to `+30%` (matching the scale of measurement variance this
project has already documented directly, e.g. a 570-byte payload measuring
`average_packet_size=612`), and re-classified through the full `UnifiedRuleBasedDetector`
(so an earlier-registered detector stealing a perturbed signature would also show up
as a failure, not just the target detector's own window).

**Results are real and uneven, not uniformly reassuring:** robust classification
rates under perturbation range from **28.6%** (`dns_amplification`, `firmware_tampering`,
`buffer_overflow` -- the same crowded region of the numeric space already flagged by
this project's own detector-overlap fix) to **100%** (`dos`, `brute_force`,
`exfiltration`). Every attack's exact calibrated point still classifies correctly
(the tautological floor this measurement is built on), but several attacks have
genuinely tight real-world margins, not wide ones. This is reported as a finding, not
smoothed into a single reassuring aggregate number.

## Adversarial robustness: an evasion-margin reading, and what it does not cover

The detector-robustness measurement above (`-30%` to `+30%` perturbation of each attack's own
numeric features) can be read two ways, and this document is explicit about which one it
supports. Read as **measurement-noise tolerance** -- does the calibration survive the kind of
variance this project has already documented in its own real traffic generation -- it is a fair,
direct answer, and the one this document primarily makes.

Read as **adversarial evasion resistance** -- could an attacker who knows this system's exact
detection windows deliberately shape traffic to sit just outside them -- it is a much weaker
answer, for a specific reason worth stating plainly: the perturbation is **symmetric, random, and
non-adaptive**. It does not search for the nearest evasive point the way a real adversary
(knowing, or inferring via probing, this project's own thresholds) would. A rate-limited attacker
willing to trade attack speed/volume for stealth has a direct, obvious evasion strategy this
measurement does not model at all: pace traffic to sit *just below* a detector's rate threshold
rather than at a randomly perturbed point around the attack's own calibrated signature. The
28.6%-robust conditions (`dns_amplification`, `firmware_tampering`, `buffer_overflow`) are exactly
where that gap matters most -- their narrow real margin is already known; whether a deliberate,
threshold-aware attacker could reliably exploit it is a distinct, harder question this measurement
does not answer.

**What this project's results do say about adaptive attacker behavior** comes from a different
experiment, already reported above: the Adaptive-attacker evaluation's `rotate` mode shows a real,
demonstrated evasion of the *response* layer (a fresh source IP bypasses `BLOCK_SOURCE`'s
per-identity containment) -- a genuine adversarial result, but at the response layer, not the
detection layer, and on identity rotation, not traffic shaping. **Detection-layer evasion via
deliberate, threshold-aware traffic shaping has not been tested here** and is named explicitly as
an open gap rather than left implicit: closing it would mean an adaptive search (e.g. a
gradient-free optimizer or a red-team script) that iteratively adjusts traffic shape against this
system's own detector responses, which this evaluation pass did not build.

## Ethics and responsible disclosure

Every attack technique implemented in this project (port scanning, flooding, brute-force,
exfiltration, beaconing, and the rest of the registry) targets **only hosts this project itself
creates inside an isolated Mininet virtual network**, on a single VM under this project's own
control, with no path to any real external host, device, or network. No traffic this project
generates leaves the VM's virtual namespace; no credential, exploit, or payload used against the
project's own simulated hosts is novel, withheld, or targeted at a real deployed system.

This project discloses its own defects as part of its own methodology, not only where convenient:
the "Disclosed defects" section above lists 21 issues found during a systematic self-review,
including two (`quarantine()`/`bandwidth_cap()`'s multi-source leak and `block_source()`/
`reset_sessions()`'s unsanitized shell interpolation) that would be real security weaknesses in a
production deployment of this code, stated plainly along with why neither reached this
evaluation's own reported numbers. Nothing in this project is deployed against real infrastructure,
so there is no real party to notify under a responsible-disclosure process; if any component of
this codebase (the executor's shell-interpolation pattern in particular) were adapted for use
against real infrastructure, the fixes already identified in that section (parameterize or
strictly validate any value interpolated into a shell command; add idempotency guards before
`quarantine()`/`bandwidth_cap()`) would need to be applied first, not treated as already resolved.

## Ablations: does the specific tuning matter, or would anything reasonable work?

Two structural questions neither the harness above nor the divergence/robustness sections
answer: does the *specific*, hand-tuned Stackelberg payoff table matter, or would any
reasonable table converge to the same registry answer? And does PPO's reward *shaping*
(distance-based partial credit) matter, or would a flat correct/incorrect signal train
just as well? Both are real ablations run against this project's own real code, not a
simulated or hypothetical version of it.

### Stackelberg payoff-table sensitivity

`src/iot_defense/evaluation/stackelberg_ablation.py` perturbs every value in the real
payoff table (`config/policies.yaml`) by random noise proportional to its own magnitude
(`±5%` to `±50%`, 30 trials per level, re-solving all 17 conditions per trial -- 2,550
solves total) and measures what fraction of (trial, condition) pairs still land on the
registry's declared `preferred_action`.

| Noise level | Match rate | 95% CI |
|---|---|---|
| ±5% | 96.1% | (94.0%, 97.4%) |
| ±10% | 88.0% | (85.1%, 90.5%) |
| ±20% | 78.8% | (75.3%, 82.0%) |
| ±35% | 64.5% | (60.5%, 68.4%) |
| ±50% | 61.0% | (56.8%, 65.0%) |

**The degradation is monotonic and the table is not a brittle single point**: small,
realistic tuning error (±5-10%) barely moves the outcome, meaning the *qualitative
structure* of the payoffs (which responses are relatively better for which threats) is
doing most of the real work, not the exact decimal values. At the same time, this is not
a claim of total insensitivity -- by ±50% noise, over a third of solves land somewhere
other than the registered answer, confirming the specific values still carry real
information and were not an arbitrary, interchangeable placeholder.

### PPO reward-shaping ablation

`src/iot_defense/evaluation/reward_shaping_ablation.py` trains the real `DefenseDecisionEnv`
under two reward configurations, holding the recipe (`net_arch=[64,64]`, `ent_coef=0.01`,
`n_steps=170`, `batch_size=170`, `lr=0.001`, `timesteps=25500`) and a 5-seed sweep
(`1, 2, 3, 7, 42`) fixed for both: the project's real **shaped** reward (`RewardConfig`,
via `config/policies.yaml` -- different magnitudes for different outcomes, e.g. an attack
let through unopposed is penalized twice as hard, `-6`, as merely choosing a
wrong-but-still-defensive response, `-3`) against a **flat** reward that collapses every
correct outcome to the same `+1`-scale reward and every incorrect outcome to the same
`-1`-scale penalty, removing that differentiation while keeping the same overall scale.

| Reward config | Seeds tested | Fully-converged rate | 95% CI |
|---|---|---|---|
| Shaped (deployed) | 5 | REWARD_SHAPED_RATE | REWARD_SHAPED_CI |
| Flat (ablated) | 5 | REWARD_FLAT_RATE | REWARD_FLAT_CI |

REWARD_SHAPING_DISCUSSION

### Cost/overhead: what does running three policies instead of one actually cost?

`src/iot_defense/evaluation/cost_overhead.py` times 300 real, direct calls per policy
(`RuleBasedDefensePolicy.decide`, `StackelbergDefensePolicy.decide`,
`PPODefensePolicy.decide`, 50 repeats across 6 representative attack scenarios each) with
`time.perf_counter()`, isolated from Mininet and packet capture entirely -- pure
decision-making cost.

| Policy | Mean | Median | p95 | Max |
|---|---|---|---|---|
| Rule-based | 0.054 ms | 0.047 ms | 0.126 ms | 0.570 ms |
| Stackelberg | 0.464 ms | 0.463 ms | 0.717 ms | 2.116 ms |
| PPO | 1.136 ms | 1.102 ms | 1.638 ms | 4.156 ms |

Running **all three** sequentially (as the harness and the live demo's comparison view
both do) costs **1.654 ms** total. The *marginal* overhead of running all three instead of
deploying only the slowest one is **0.518 ms**. For scale: this project's own harness
measured mean real detection latency (dominated by packet capture, not decision-making) at
**~26,026 ms** per trial (see Results) -- so the entire three-policy comparison this
project's architecture is built around costs roughly **0.002%** of one trial's real
end-to-end latency. Comparing three policies is not the bottleneck of this system, by a
wide margin; capture and network I/O are.

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
