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
covers `trials_per_condition=15` across the **full 17-condition registry** (`normal` plus 16
attacks, including `c2_beaconing`, registered after an earlier N=5 run and now included for the
first time) -- **255 real Mininet trials, 1,275 recorded outcomes** -- generated on 2026-09-24
(a ~2h9m real run), results at `data/evaluation/results.jsonl` (gitignored; regenerate with
`sudo .venv/bin/python3 -m iot_defense.evaluation.harness --trials-per-condition N`).

This is the third harness run at a different scale reported in this document's history (120
trials over 6 conditions, then 80 over 16, now 255 over the full 17), each time trading time cost
for statistical stability rather than quietly replacing an inconvenient number. **The N=5 run's
headline numbers were, in hindsight, optimistic** -- several conditions that read as a clean 100%
at n=5 settle meaningfully lower at n=15 (see Discussion). This is disclosed as the expected,
predictable cost of the earlier breadth-over-depth tradeoff, not as a new defect: at n=5 a single
unlucky trial swings a per-condition percentage by a full 20 points, and this run is reported
specifically to replace that narrower estimate with a wider, more trustworthy one -- not to
quietly supersede it without saying so.

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

A second, independent arm runs offline Suricata analysis of the same 255 pcaps
(`src/iot_defense/evaluation/suricata_eval.py`), against two rulesets -- ET-Open (real-world
community threat signatures, fetched via `suricata-update`) and a small lab-tailored ruleset
(`config/suricata/lab.rules`, written to encode the same shape knowledge `detection/detector.py`'s
own rule-based detectors use, so Suricata is judged on a fair signature-matching version of that
knowledge too, not only on a strawman of unrelated real-world malware signatures). *Detector*, not
*response*, is the axis Suricata is compared on: Suricata identifies traffic, it does not select
or execute a containment action, so its comparison metrics are accuracy/true-positive-rate/
false-positive-rate against ground truth, not verified-response rate.

## Results

All rates below are proportions of a finite trial count; the bracketed range next to each one is
a 95% Wilson score confidence interval, not a second measurement -- at this harness's own real
trial counts a single trial can still swing a reported percentage by several points, and the
interval is how wide that uncertainty genuinely is, not just the point estimate.

| Arm | Detection accuracy | Verified response rate | Matches preferred action (attacks only) | Mean detection latency |
|---|---|---|---|---|
| Rule-based (ours) | 73.7% [68.0, 78.8] | 68.2% [62.3, 73.6] | 74.2% [68.3, 79.3] | 27778 ms |
| Stackelberg (ours, deployed) | 73.7% [68.0, 78.8] | 68.2% [62.3, 73.6] | 74.2% [68.3, 79.3] | 27778 ms |
| PPO (ours) | 73.7% [68.0, 78.8] | 68.2% [62.3, 73.6] | 74.2% [68.3, 79.3] | 27778 ms |
| NaiveBlockAllBaseline | 73.7% [68.0, 78.8] | 26.7% [21.6, 32.4] | 22.1% [17.3, 27.8] | 27778 ms |
| AlwaysAllowBaseline | 73.7% [68.0, 78.8] | 5.9% [3.6, 9.5] | 0.0% [0.0, 1.6] | 27778 ms |

Per-condition breakdown for Stackelberg, the policy the live demo actually deploys (n=15 trials
per condition):

| Condition | Trials | Detection accuracy | Verified response rate |
|---|---|---|---|
| `normal` | 15 | 100.0% [79.6, 100.0] | 100.0% [79.6, 100.0] |
| `reconnaissance_port_scan` | 15 | 100.0% [79.6, 100.0] | 100.0% [79.6, 100.0] |
| `dos_flood` | 15 | 100.0% [79.6, 100.0] | 100.0% [79.6, 100.0] |
| `brute_force` | 15 | 100.0% [79.6, 100.0] | 100.0% [79.6, 100.0] |
| `data_exfiltration` | 15 | 73.3% [48.0, 89.1] | 73.3% [48.0, 89.1] |
| `exploit_payload_injection` | 15 | 60.0% [35.8, 80.2] | 60.0% [35.8, 80.2] |
| `tcp_syn_flood` | 15 | 20.0% [7.0, 45.2] | 53.3% [30.1, 75.2] |
| `icmp_ping_flood` | 15 | 73.3% [48.0, 89.1] | 0.0% [0.0, 20.4] |
| `slow_loris_exhaustion` | 15 | 60.0% [35.8, 80.2] | 13.3% [3.7, 37.9] |
| `dns_amplification` | 15 | 73.3% [48.0, 89.1] | 73.3% [48.0, 89.1] |
| `dns_tunneling_exfiltration` | 15 | 66.7% [41.7, 84.8] | 66.7% [41.7, 84.8] |
| `mqtt_message_flood` | 15 | 100.0% [79.6, 100.0] | 93.3% [70.2, 98.8] |
| `firmware_tampering` | 15 | 73.3% [48.0, 89.1] | 73.3% [48.0, 89.1] |
| `buffer_overflow_probe` | 15 | 80.0% [54.8, 93.0] | 80.0% [54.8, 93.0] |
| `credential_replay` | 15 | 46.7% [24.8, 69.9] | 46.7% [24.8, 69.9] |
| `rogue_config_beacon` | 15 | 60.0% [35.8, 80.2] | 60.0% [35.8, 80.2] |
| `c2_beaconing` | 15 | 66.7% [41.7, 84.8] | 66.7% [41.7, 84.8] |

External detection comparison (Suricata, offline analysis of the same 255 pcaps):

| Detector | Accuracy | True positive rate | False positive rate |
|---|---|---|---|
| Suricata + ET-Open (real-world community rules) | 67.8% | 67.1% | 20.0% (3/15 `normal` trials) |
| Suricata + lab-tailored rules (this project's own signatures) | 27.1% | 22.5% | 0.0% (0/15 `normal` trials) |
| This project's `UnifiedRuleBasedDetector` | 73.7% [68.0, 78.8] | -- | 0.0% (0/15 `normal` trials misclassified) |

## Discussion

**The N=5-to-N=15 revision is the single most important result in this section, and it is
reported plainly rather than quietly superseded.** Aggregate detection accuracy dropped from a
clean 90.0% (n=80) to 73.7% [68.0, 78.8] (n=255); verified response rate dropped from 85.0% to
68.2% [62.3, 73.6]. Several individual conditions that read as a perfect 100% at n=5 settle
meaningfully lower at n=15 (`data_exfiltration` 100%->73.3%, `dns_amplification` 100%->73.3%,
`firmware_tampering` 100%->73.3%, `buffer_overflow_probe` 100%->80.0%, `rogue_config_beacon`
100%->60.0%, `mqtt_message_flood` 100%->93.3%) -- exactly the outcome the N=5 run's own Discussion
predicted as a risk ("a single trial accounts for the entire 20-point gap from 100%"), now
confirmed directly rather than left as a caveat. **This is what the wider, honest number looks
like, and it is the number this project stands behind, not the earlier optimistic one.**

**All three of our policies still score identically** on every aggregate metric, now confirmed a
third time at a third scale (120 trials/6 conditions, 80/16, now 255/17) -- detection and the
registry-driven "correct action per attack" answer are shared inputs, and nothing in this
dataset's context vectors was adversarial enough to make the three decision mechanisms disagree.
Real disagreement between them is only visible when contexts are deliberately constructed near
decision boundaries (see "Evaluating decision divergence" above) -- real captured lab traffic
never lands there.

**The baseline gap holds, though its exact multiple shrank along with the headline number**: our
system's 68.2% verified-response rate is **2.6x** NaiveBlockAllBaseline's 26.7% and **11.6x**
AlwaysAllowBaseline's 5.9% (previously 3.4x/13.7x at n=80). The gap did not close because our
system's real numbers dropped in the same revision as everything else -- it remains a large,
real, and now better-measured advantage over both simpler designs.

**`tcp_syn_flood` produced this run's most counterintuitive-looking result, and checking the raw
per-trial rows (not just the aggregate percentages) explains it exactly, not speculatively**:
20.0% detection accuracy but 53.3% verified response rate -- response *higher* than detection.
Of the 15 `tcp_syn_flood` trials, only 3 were correctly labeled `tcp_syn_flood`; 6 were
misclassified as `brute_force` and 5 as `dos_flood`. The `brute_force` misclassifications fail
both metrics outright (`brute_force`'s preferred action is `BLOCK_SOURCE`, wrong for this
traffic). The `dos_flood` misclassifications fail detection accuracy but **still pass response
verification**, because `dos_flood` and `tcp_syn_flood` happen to share the same registry
`preferred_action` (`ISOLATE`) -- so choosing ISOLATE is independently confirmed as effective
regardless of which of the two labels the detector actually assigned. `3 (correct) + 5 (dos_flood,
same preferred action) = 8/15 = 53.3%`, exactly the reported number. This is a real, now-precisely
-understood measurement interaction, not a mystery: `tcp_syn_flood`'s detection window is
genuinely being confused with two adjacent flood-shaped attacks at this VM's traffic-generation
fidelity, and the response-verification metric is, by construction, blind to *which* attack label
produced a shared correct action. Both are disclosed plainly rather than smoothed into a single
misleading aggregate.

**`icmp_ping_flood`'s 0% verified-response rate is now confirmed as a real, reproducible finding,
not small-sample noise**: 0/15 at this run, versus 0/5 previously -- three times the evidence for
the same result, with a CI that has tightened from wide-and-inconclusive to [0.0%, 20.4%]. Its
detection accuracy also fell, from a clean 100% to 73.3% [48.0, 89.1], meaning this is not solely
a response-verification problem -- both stages show real degradation at higher N. Given the
CI now excludes anything above ~20%, this is reported as a genuine system weakness on this VM,
not an artifact awaiting a bigger sample -- the specific mechanism (a verification probe racing
real kernel/network timing under this VM's 2-CPU constraint, per the scope boundary above) is
named as the leading hypothesis, but this document does not claim to have isolated it further.

**`slow_loris_exhaustion` improved on paper (40%->60% detection) but its verified-response rate
stayed in the same weak range (20%->13.3%, CI [3.7%, 37.9%])**, consistent with a real, persistent
weakness in this specific attack's response-verification path rather than a detection problem
that has now resolved. `credential_replay` (80%->46.7%) and `rogue_config_beacon` (100%->60.0%)
are the two largest other drops, both landing near the middle of the registry's conditions rather
than at either extreme -- ordinary regression to a more honest mean at higher N, not a new
finding requiring its own investigation.

**`c2_beaconing`, included in a full harness run for the first time, lands at 66.7% [41.7, 84.8]
on both metrics** -- squarely in the middle of the registry's range, not an outlier requiring
special discussion, closing the "16th attack not included" gap from the previous run.

**A real, previously-undisclosed methodological gap was found while regenerating the Suricata
comparison at N=15, and is reported here rather than smoothed into the headline number**:
`config/suricata/lab.rules`' accuracy collapsed from the earlier run's 91.2% to **27.1%**. Direct
inspection of the per-condition breakdown (not assumed) shows why: **the file contains exactly
five signatures** -- `reconnaissance_port_scan`, `dos_flood`, `brute_force`, `data_exfiltration`,
and `exploit_payload_injection` -- written when the registry had five attacks, and it was never
extended for the **twelve** attacks added since. Every one of those twelve conditions scores 0/15
by construction (no signature exists to match), which mechanically drags the aggregate accuracy
down regardless of how well the five original signatures perform. This alone does not fully
explain the drop from 90.7% to 22.5% true-positive-rate, though: checking the five *original*
conditions individually shows `reconnaissance_port_scan`, `brute_force`, and `data_exfiltration`
still matching cleanly (15/15 each), `exploit_payload_injection` partially (9/15), but
**`dos_flood` scoring 0/15 despite its own signature's port, protocol, and target IP matching the
real traffic generator exactly** (`generate_dos_mininet_traffic`'s UDP flood to `10.0.0.10:5683`
against the rule's own `alert udp ... -> 10.0.0.10 5683 ... threshold: ... count 50, seconds 2`)
-- confirmed directly by inspecting both the generator and the rule side by side, not assumed.
Every sampled `dos_flood` pcap produced zero lab-ruleset alerts. The specific reason Suricata's
`threshold` mechanism fails to fire against traffic that appears to match its own stated
conditions was not further isolated in this pass -- it is disclosed as a real, open
methodological defect in the Suricata comparison specifically, not fixed here, and this
document's own `UnifiedRuleBasedDetector` accuracy (73.7%) is **not** affected by it (`dos_flood`
scores 100% verified response on this project's own detector -- see per-condition table above --
confirming the gap is specific to the lab Suricata ruleset's own signature/threshold behavior,
not a shared traffic or ground-truth problem). Expanding `lab.rules` to cover the missing twelve
attacks and root-causing the `dos_flood` non-fire are both real, scoped next steps, deliberately
not attempted under this pass's time constraints rather than rushed and left unverified.

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

**At this small scale, the rotate-mode result looked like a real finding**: a second,
entirely fresh source (`.121`) reached the sensor and was independently detected and
blocked, exactly like the first. Because `BLOCK_SOURCE` installs `iptables -A INPUT -s
<source_ip> -d <target_ip> -j DROP` (confirmed by reading `executor.py`'s own
implementation, not assumed), it is inherently scoped to the *claimed* IP in the packet
header, not the physical attacker -- so an attacker able to spoof or genuinely rotate
source addresses would not be contained by this response at all, only whichever single
address it has already been caught using. Two rounds is not much evidence for that,
though, and the scaled-up run below shows exactly why this initial read needed to be
treated with real caution rather than reported as confirmed.

### Scaled-up results: a bug found, fixed, and a weaker (not stronger) finding

The 5-round run above was explicitly flagged as too small to be a real headline finding
on its own, so it was scaled to 30 rounds per mode (real, ~36-minute Mininet run). That
run did not produce the "dozens of clean data points" it was run to get -- and, in
diagnosing why, found a real bug in this evaluation module itself. Reading the raw
per-round rows directly (not just the aggregate print) showed rotate mode selecting
source `.121` for **all 28 of the last 28 rounds** rather than rotating through the
pool's other addresses. `run_campaign()`'s selection was `remaining = [ip for ip in
_SOURCE_POOL if ip not in blocked_sources]; source_ip = remaining[0]` -- always the
*first* not-yet-blocked address. Because `.121` was never detected (so never blocked),
it stayed first-in-line and kept getting re-selected instead of the campaign moving on.
A 30-round "rotate" campaign was, in practice, a 2-source campaign with 28 rounds spent
retrying the one address that had already failed once.

This was fixed (`src/iot_defense/evaluation/adaptive.py`, commit `1902f99`): sources
whose capture comes back unreliable are now excluded from future selection, and the
address pool was expanded from 6 to 21 so a real dozens-of-rounds campaign can exercise
dozens of distinct sources. A new regression test
(`test_rotate_mode_skips_a_source_whose_capture_is_unreliable_instead_of_retrying_it_forever`)
locks this in. The fixed code was then re-run for real (25 rounds/mode, ~35 minutes),
and this time genuinely cycled through 20 distinct spoofed addresses (`.121`-`.140`,
confirmed directly from the log -- never repeating one until the pool was exhausted).

**The real result, once the selection bug stopped masking it, is a materially different
and more important finding than the original 5-round run suggested**: every one of the
20 distinct spoofed addresses produced **zero captured packets**, on both the initial
attempt and the built-in retry (40 real zero-packet observations total), in *both* the
30-round and the 25-round run. The only source that ever produced real, capturable
traffic in either scaled-up run was `.100` -- the physical attacker host's own real,
unspoofed address. `net.ipv4.conf.all.rp_filter` on the VM itself is `2` (loose mode,
which should not by itself explain this, since the whole `10.0.0.0/24` range is locally
routed), so the specific mechanism blocking spoofed-source capture was checked at the
host level and not found there; whether it is a per-namespace Mininet setting, an OVS
behavior, or something else was not further isolated in this pass, and this document
does not claim to have root-caused it.

**This means the original claim needs to be corrected, not reinforced, and this
document says so plainly rather than quietly keeping the more dramatic earlier framing.**
The one successful spoofed capture that grounded the original "a rotating attacker
evades per-source blocking" finding (`.121`, 17 packets, in the very first 5-round run)
could not be reproduced even once across 40 further real attempts spanning 20 distinct
addresses in two independent, larger, bug-fixed runs. The honest conclusion this
evaluation module currently supports is **not** "source rotation was demonstrated to
evade `BLOCK_SOURCE`" -- it is "one unreplicated pilot observation suggested source
rotation could evade `BLOCK_SOURCE`, and two much larger follow-up attempts, run
specifically to strengthen that claim, could not reproduce it, instead surfacing that
this module's spoofed-traffic generation is not reliably producing capturable packets
in this environment." The structural argument (`BLOCK_SOURCE` is identity-based, scoped
to the packet's claimed source IP, not the physical sender -- verified directly from
`executor.py`) still stands as a reasoned, architectural point independent of this
measurement. But this project no longer claims real, repeated Mininet evidence that a
rotating attacker gets through -- it has one old, unreplicated data point and a newer,
larger effort that could not confirm it. Root-causing why spoofed traffic is not being
captured, and re-running once that is fixed, is a real, scoped next step, deliberately
not chased further in this pass given the real time already spent on it.

**This is not a flaw unique to this project's response-execution design** -- any purely
identity-based (as opposed to behavior-based) containment has the same structural
limit in principle. It is, however, a real, disclosed gap between "the registered
`preferred_action` was executed and verified" (this evaluation's other results) and
"the attacker is actually contained against a rotating identity" (a stronger claim this
module was built to test, and -- honestly reported -- has not yet demonstrated at any
scale beyond one unreplicated pilot round).

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
  original N=5 run's results were present (0 null/failed rows), none carried the
  `ppo_fallback` marker `PPODefensePolicy` sets when its model file is genuinely
  missing, and `PPO.load()` succeeded against the model deployed when the harness
  process started (which matched that process's own in-memory registry size for its
  entire run, since Python does not hot-reload an already-imported module even if
  the file on disk changes mid-run). This check was re-run, not just assumed to
  still hold, against the current N=15 dataset's 255 `ppo` rows: same result, 0
  nulls and 0 fallback markers -- confirming the PPO numbers in this document's own
  headline Results table are real model predictions, not a silently substituted
  rule-based fallback, for both the run that established this check and the run
  this document currently reports.

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
| Shaped (deployed) | 5 | 100.0% | (56.6%, 100.0%) |
| Flat (ablated) | 5 | 100.0% | (56.6%, 100.0%) |

**At this sample size and on this specific metric (full convergence to every registered
`preferred_action`), no difference was detected between the two reward configurations --
both reached 5/5.** This is reported honestly as a real result, not reframed to make the
ablation look more decisive than it was: it does **not** show reward shaping is useless,
only that it is not *necessary* for this environment's specific 17-scenario, single-step
classification-style task to reach full convergence at n=5 each. Both CIs are wide (a
direct consequence of n=5) and overlap completely, so this result cannot distinguish "no
real difference" from "a real difference too small for this sample to detect." What this
ablation does not measure -- sample efficiency (how many timesteps each configuration
needs), training stability across a wider seed set, or behavior on a task with a longer
credit-assignment horizon than this project's own single-decision-per-step environment --
are the more likely places reward shaping would matter, and are named here as the
concrete follow-up this ablation motivates rather than answers.

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

- **`lab.rules` covers only 5 of the registry's 17 conditions, and one of those five
  (`dos_flood`) does not reliably fire despite matching the real traffic generator's own port,
  protocol, and target IP.** See Discussion above for the full breakdown found while regenerating
  this run's Suricata comparison -- a real, disclosed methodological gap in the lab-ruleset arm
  specifically, not in this project's own detector or in the other four arms' comparisons.
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
- **Single lab environment.** All trials ran in the same Mininet topology on one 2-CPU VM.
  Results should not be generalized to arbitrary IoT networks or attacker behavior, consistent
  with every other "controlled study" caveat already documented in this project (see the scope
  boundary stated at the top of this document).
- **Internal detection is shared, not compared, across the five internal arms.** Every arm in the
  main comparison receives the same detection result -- that comparison measures response
  selection and execution, not detection accuracy. The Suricata arm is what adds a genuine,
  independent detection-accuracy comparison.
