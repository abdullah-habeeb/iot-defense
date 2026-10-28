# IoT Defense: To-Do Lists

Written 2026-10-26. Nothing below has been started except where marked. Effort figures are estimates; add ~50% to anything that touches live Mininet, which has produced surprises before (7 bugs found and fixed in earlier runs).

How the lists are split:

- **To-Do List #1** is what to finish before the final demo. Each item is half a day to two days.
- **To-Do List #2** is heavy work: it strengthens the research claim ("works on other networks") but takes days to weeks. It is not needed for a valid demo.

Legend: **sudo** = needs the user's `sudo` password on the VM (the user starts the run, it runs unattended). **VM** = work happens on the VM over the SSH tunnel.

---

## To-Do List #1: before the demo

### A. Core additions

| # | Task | Effort | Needs | Why |
|---|---|---|---|---|
| 1.1 | **Fix the arbiter so it considers every response the device can apply**, not only the three policies' proposals. | ~0.5 day | VM | Today, for exfiltration, C2 beaconing, DNS tunneling and firmware tampering, the policies propose QUARANTINE or ISOLATE, which the live defender cannot apply (it applies only ALLOW, ALERT, FORENSIC_CAPTURE, BLOCK_SOURCE, THROTTLE). The arbiter falls back to ALERT. FORENSIC_CAPTURE scores about 4.70 on those four attacks, so the fix removes a regret of about 1.8. It is the weakest visible result in the live demo. Needs a test and a re-run of the arbiter evaluation. |
| 1.2 | **Add two new attacks and test Stackelberg on them (Option A).** | ~1-2 days (about 1.5 h of measuring, 6 blocks of 11 rows) | VM, sudo | Tests whether the Stackelberg priors were tuned to the 20 known attacks. **It does not test other networks (that is List #2, item 2.1).** |

**1.2 rules, so the test counts:**

1. Choose two attacks that are genuinely different from the existing 20 (candidates to decide: an ARP-spoofing man-in-the-middle, an application-layer HTTP flood, a UPnP/SSDP abuse). Each needs a traffic generator, a detector rule that does not clash with the existing 20, and a mechanism class assignment.
2. **Write and commit the Stackelberg priors for each new attack BEFORE any measurement is run**, ideally written by a teammate who has not seen the record book. Record the commit hash in the write-up.
3. Measure (3 blocks per attack, 11 rows each = 33 rows per attack).
4. Report Stackelberg's regret on the new attacks against the playbook's, whichever way it lands. A miss is also a finding.
5. If anyone changes the priors after seeing the results, the test no longer counts.

**1.2 evidence package (how to prove it on the day).** "It came 95% close" is not evidence on its own; the evidence is that the prediction existed before the measurement.

- **Prediction file:** the new attacks' mechanism-class assignments, their priors, and the response Stackelberg picks for each, committed before measuring; record the commit hash and date.
- **Sealed prediction:** compute the file's SHA-256 and send the hash to the guide or a teammate by email before measuring. On the day, show the email date and that the file matches the hash. This is stronger than git dates alone because an independent party holds the timestamp.
- **Raw evidence:** keep the Mininet logs, the pcap captures and the raw JSONL rows (each row carries a `measured_at` time).
- **Reproducible script:** one command that reads the prediction file and the raw rows and prints, per attack: chosen response, its measured mean, the best response's measured mean, and the gap. Run it live on the day.
- **Comparison:** show what the playbook does on the same unseen attacks (it falls back to its default).
- **Report per attack, never a percentage:** two attacks are two data points. Show a miss too if there is one.
- **Witness note (optional):** the guide or a teammate signs a short note that the prediction was committed before measurement began.
- **Screen recording (backup, not proof):** one continuous recording with a visible clock, covering writing the prediction, hashing it and starting the measurement.

| # | Task | Effort | Needs | Why |
|---|---|---|---|---|
| 1.2a | **Live challenge attack launcher.** An examiner or classmate picks an attack variation on the spot (any open port, a rate from low to high, from a pre-agreed safe range); the defender detects it and proposes a response; the proposed response, the playbook's choice and "do nothing" are then run live and their outcomes shown. | ~1-2 days | VM, sudo | Strongest evidence for an audience: the attack did not exist beforehand, so it cannot have been pre-fitted. Shows relative outcomes of 3 probes, not the best of all 10 responses. Rehearse it, agree the allowed variations in advance, and have the recording ready as a fallback. If the detector cannot name the attack, say so; it is a known limit. |

### B. Protecting the work

| # | Task | Effort | Needs | Why |
|---|---|---|---|---|
| 1.3 | **Back up and commit the uncommitted batch on the VM** (model-trained PPO, detector evaluation, label re-decision, public-data evaluation, docs, tests), and update PR #1. | ~0.5 h | VM; **the user must ask for the commit** | All of it exists only as uncommitted changes on the VM. Never add a Claude co-author line (see memory). Copy to the Desktop as well. |
| 1.4 | **Record an offline fallback:** a screen recording of the live demo plus saved replay captures. | ~2 h | VM, laptop, phone | Live Mininet can fail on the day. |
| 1.5 | **Run the full test suite** and record the result. | ~0.5 h | VM | Last known full run was 847 passing before the latest changes. Run it when nothing else is using the VM's 2 vCPUs. |

### C. Evidence and documents

| # | Task | Effort | Needs | Status |
|---|---|---|---|---|
| 1.6 | **Corrected IoT-23 evaluation** (like-for-like before/after, named recall, firewall actions). | done | VM | **DONE 2026-10-26.** Results in `data/evaluation/public_final.md` on the VM and folded into the paper (Table III, Echo text, abstract, discussion and conclusion now say 17-21 firewall actions per hour on the benign Echo). |
| 1.7 | **Update the repo's stale documents:** `README.md` (still leads with the preferred-action framing) and the repo's `paper/paper.tex` (still has the old circular numbers). Replace the repo paper with the compiled v2. | ~2 h | VM | A grader who opens the repo must not see contradicting numbers. |
| 1.8 | **Paper finishing:** fill the red placeholders (co-authors, guide, emails, availability URL and licence); verify every reference against the publisher page; confirm the AI-use statement is true; check the venue's page limit. Optionally get the references onto page 6 (drop 4-5 references or cut ~20 lines). | ~3 h | the user | v2 is compiled: 6 pages of content, references run onto page 7. |
| 1.9 | **Run the Mininet harness for the four distributed attacks' captures:** `sudo .venv/bin/python3 -m iot_defense.evaluation.harness --trials-per-condition 8 --output data/evaluation/results_v2.jsonl --pcap-dir data/evaluation/pcaps_v2 --restart` | ~2 h | VM, sudo | The four distributed attacks currently have no saved captures, so the naming result covers only the 16 single-source attacks. |

### D. Demo preparation

| # | Task | Effort | Notes |
|---|---|---|---|
| 1.10 | **Write the demo script** (about 12-15 minutes): problem, record-book heatmap, live attack with the three policy cards and arbiter verdict, results with statistics, limits, future work. | ~2 h | The dashboard already shows the three policy cards side by side and an Arbiter Verdict panel. |
| 1.11 | **Prepare the Q&A cheat sheet:** what the weights (5, 3, 2) are and the objective-shift result; why a lookup table does not make the strategies redundant; the honest weak spots (priors not blind, unseen-attack test, lab-only, detector does not transfer); what "measuring" means. | ~1.5 h | The honest limits are a strength if stated up front. |
| 1.12 | **Rehearse the live demo end to end at least twice**, including the physical setup (laptop attacker, phone client, defender VM on a bridged adapter), and run `calibrate` if the phone's page is used with a long window. | ~3 h | Keep the original 5 s configuration for live use; the 60 s window flags the phone's polling as brute force. |
| 1.13 | **Optional showpiece: execute each policy's proposal in turn** on the same attack and show the live outcome of each (attack stopped, phone still working, score). | ~0.5-1 day | VM, sudo. Not essential: the dashboard already lists all three proposals with measured scores, but only the winner is executed. |

### Do not add before the demo

- More attack types without measurements.
- New headline claims.
- Anything described as "Stackelberg is best"; the supported claim is that it is near the table ceiling without measuring and ties PPO when PPO has measurements.

---

## To-Do List #2: heavy work

| # | Task | Effort | Needs | What it proves |
|---|---|---|---|---|
| 2.1 | **Build a different second network and re-measure (Option B).** New topology with different device roles, link speeds and delays, and different legitimate client behaviour. Re-measure about 8 attacks x 3 blocks (about 24 blocks, ~5-6 h). | ~3-5 days | VM, sudo | That the Stackelberg priors hold when the environment changes. **This is the test that matches the "works in other networks" claim.** |
| 2.2 | **Full second benchmark** on the new network (all 21 situations x 3 blocks, ~14 h of measuring). | ~1-2 weeks | VM, sudo | A complete, comparable second record book. |
| 2.3 | **Raise repetitions from 3 to 5** (`--reps 5` resumes and adds only reps 3 and 4). | ~9-10 h of measuring (24 h from scratch) | VM, sudo | Shrinks error bars by about 20%. Does not fix the single-lab limit. |
| 2.4 | **Independently written priors:** a person who has not seen the record book writes the mechanism priors; compare against the current ones. | ~1-2 days | a teammate | Removes the "priors written knowing the lab" limitation. |
| 2.5 | **Real-hardware replication slice:** repeat a subset of the benchmark on physical IoT devices and a real router. | ~1-2 weeks | hardware | Moves the claim from simulation to hardware. |
| 2.6 | **Per-device behavioural baselines for the detector** instead of fixed thresholds. | ~1-2 weeks | VM | Targets the false-alarm rate (26-28 sustained alarms/hour on a benign Echo) and the long-window phone problem. |
| 2.7 | **Evaluate the detector on more public data** (CICIoT2023, N-BaIoT, Bot-IoT) and on more benign devices, not only one Echo. | ~1 week | VM | Replaces the single-device, size-selected IoT-23 transfer test. |
| 2.8 | **Attacker-aware PPO training environment** (a PPO trained against a reacting attacker model). | ~3-5 days | VM | Tests whether learning can recover what Stackelberg gets from structure. |
| 2.9 | **Online learning from deployed outcomes**, so policies adapt after deployment. | ~2-4 weeks | VM | Future-work item from the paper. |
| 2.10 | **A held-out detector evaluation:** tune thresholds on one set of captures and report on a separate set. | ~3-5 days | VM | The 16/16 naming result is currently a development-set result. |

---

## Ordering suggestion

1. 1.3 (backup) and 1.1 (arbiter fix) first: they protect the work and fix the weakest visible result.
2. 1.6 and 1.7 as soon as the IoT-23 run finishes.
3. 1.2 if at least two spare days exist; otherwise skip it and state the limits.
4. 1.10-1.12 in the last two days before the demo.
5. List #2 only after the demo, or in parallel if a teammate has capacity. Item 2.1 is the most valuable single addition.
