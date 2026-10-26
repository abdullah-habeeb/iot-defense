# Future work and how to build on this project

Written 2026-10-22. Plain-language companion to `EVALUATION.md` (the numbers) and `docs/LIVE_DEMO.md` (the physical demo).

## 1. What this research is about

**When a home IoT defender has to pick an automated response to an attack, how much does it need to measure first, and does modeling the attacker's reaction let it skip that measurement?**

How it is tested:

- **Record book (outcome table).** In live Mininet, every one of the 10 responses was applied to each of 21 situations (normal + 20 attacks), 3 repetitions each: 693 measurements. Each is scored with one shared objective: `5 x containment + 3 x service kept + 2 x intelligence - action cost`. It is the answer key. No strategy reads it while deciding.
- **Rule-based playbook.** A printed checklist written by a person: "port scan -> decoy, flood -> isolate". It knows nothing about the network, so it runs unchanged anywhere, but nobody has checked it works there.
- **Stackelberg.** A game model that includes the attacker's reaction: a contained attacker retreats, so a decoy's "intelligence bonus" is never earned. It uses hand-written mechanism priors (`config/policies.yaml`, `policy.game_model`) and never reads measurements.
- **PPO.** A learned policy. Trained on the record book it is circular (the book is both its study material and the answer key), so the main comparison uses a PPO trained only on the mechanism model.
- **Arbiter.** Looks up each proposal's measured evidence and executes the best-evidenced one.

## 2. Where we stand (honest summary)

| Finding | Number | Caveat |
|---|---|---|
| Playbook vs measured best | mean regret 3.0; picks the best in 4/21 | one lab |
| Stackelberg | regret 0.042; best in 20/21 | priors written by authors who knew the lab; not blind |
| Same priors, no attacker modeled | regret 0.549 (model argmax); PPO trained on that model 0.577 | the attacker-aware gap is the cleanest result |
| Live paired trials, Stackelberg vs PPO(table) | 7.226 vs 7.254, p = 0.69 | a tie, not a win |
| Leave-one-attack-out | Stackelberg 0.04, PPO 1.61 | Stackelberg never trains, so this shows PPO cannot generalize |
| Noisy detector (20-30% wrong) | noise-aware PPO beats Stackelberg by 0.3-0.56 | simulated errors |
| Reactive source-rotating attacker | deployed Stackelberg 2.17; adaptive-trained PPO 0.07 | in-sample; attacker is scripted |
| Table lookup of the best row | 7.322 (ceiling on known attacks) | strategies do not beat it on known attacks |

Limits to state wherever results are quoted: 5 virtual devices, 3 repetitions per cell, scripted attacker, one lab, priors not blind, PPO-on-table is circular.

## 3. Immediate to-do for this project

1. Train PPO on the model only and drop PPO-on-table from the main comparison. First attempt (no attacker in the practice world): regret 0.577. Also run an attacker-aware version and report both. Code: `src/iot_defense/defense/model_outcomes.py`, `src/iot_defense/evaluation/model_trained_ppo.py`, `tests/test_model_outcomes.py` (uncommitted).
2. Re-run the noisy-detector and reactive-attacker experiments with model-trained PPO so every PPO result is consistent.
3. Add bootstrap confidence intervals to the headline numbers; gaps like 0.017 vs 0.042 are within noise at 3 repetitions.
4. Grade on fresh data: build the key from repetitions 1-2 and grade on repetition 3, or re-measure.
5. Perturb Stackelberg's priors by +/-0.2 and show its regret barely moves (answers "written knowing the lab").
6. Add a table-lookup baseline as a named fourth strategy.
7. Use the 168 live paired trials as the headline (fresh measurements), table regret as secondary.

## 4. What the physical demo does and does not show

The demo used a laptop attacker, this laptop's VM as the defender, and a phone as the legitimate user. It **does** show that the system works end to end outside Mininet: real packets are sniffed, a real nmap scan is detected, a real firewall rule is installed, and the phone's page stays reachable.

It **does not** show that the lab results hold on real devices:

- one attack (a scan) and one response, run once, not scored with the objective;
- no repetitions and no measured containment or service-loss numbers;
- the "devices" were a phone and laptops, not IoT devices;
- the attacker was ordinary nmap, not the 20 scripted attacks.

So it is a working demonstration of the pipeline, not validation of the record book.

To show the lab results hold, re-measure a **small slice** of the record book on real hardware: for example 4 attacks x 3-4 responses (ALLOW, BLOCK_SOURCE, THROTTLE, QUARANTINE) x 3 repetitions, with the same counters. Then check whether the best response per attack is the same as in the lab. A Raspberry Pi, an ESP32 board, or a smart plug as the victim device is enough; a full home is not needed.

## 5. Future work

### Near-term: make the evidence stronger
1. **Measure more.** 10 repetitions per cell, confidence intervals, more device types.
2. **Replicate a slice on real hardware** (section 4).
3. **Test the detector on public data** (IoT-23, CICIoT2023) to check attack recognition beyond this lab. No public table of attack -> response -> measured outcome exists, so the record book itself is new.

### Mid-term: make the system smarter
4. **Let the record book build itself.** A home cannot try all 10 responses on every attack. A defender could start from the priors, learn from what happens after each response, and try new responses only where being wrong is cheap. This is the step from "lab benchmark" to "learns in your home".
5. **Combine the two ideas.** Attacker-aware modeling is what carries generalization; learning adds robustness. Options: update Stackelberg's priors from measurements, or train PPO inside an attacker-aware simulator.
6. **Real adaptive attackers.** Use a human red team or a learning attacker instead of a scripted one. Blocks currently expire after 60 seconds, so escalating blocks for repeat offenders is a natural extension.
7. **Use the detector's doubt.** Treat a 70%-sure detection differently from a 99%-sure one, and choose more cautious responses when unsure (the posterior arbiter is a first step).

### Long-term: make it deployable
8. **Personalize the goals.** A household with a medical device weights uptime far higher than one with a research honeypot; set the objective per home.
9. **Handle many things at once:** several attackers, several devices, sequences of responses.
10. **Run on a real router** (for example OpenWrt) and measure CPU, memory and delay on cheap hardware.
11. **Explain decisions to homeowners** in plain language and let them approve risky actions like ISOLATE.

## 6. How others can reuse this work

- **The benchmark.** The record book is a template: add rows for other networks, devices, or attacks, the way people extend a shared dataset.
- **The evaluation method.** Grade strategies on measured outcomes and held-out attacks, not against a playbook they were built to match.
- **The finding.** If you design an automated defense, model the attacker's reaction: the same priors without it scored 0.549 regret versus 0.042.

## 7. One paragraph for the report

> Future work includes replicating a slice of the outcome table on physical home hardware, learning the table online from deployed responses, hybridizing attacker-aware modeling with learned adaptation, testing against adaptive attackers, using detector confidence in the decision, and personalizing the objective to each household.

## 8. What the detector evaluation found (2026-10-22)

Tools: `evaluation/detection_report.py` (lab captures), `evaluation/defender_replay.py` (the whole live defender),
`evaluation/pcap_replay.py` and `evaluation/public_eval.py` (any recording, and the IoT-23 public dataset).

**Naming the attack (lab, 5 saved captures of each of the 16 single-source attacks):** the live defender as first built
(last 5 s, inbound traffic only) ended on the right attack name for 7 of 16. With `--window 60 --directions both` and
re-deciding when the name changes, it ends on the right name for all 16. The first name is often wrong because the
opening packets of an attack resemble another attack; the right name arrives after 1-3 s for the floods, scans and
brute force, 3-10 s for DNS amplification, data exfiltration, rogue beacon, firmware tampering and DNS tunneling, and 17-32 s for
credential replay, C2 beaconing, buffer overflow, MQTT flood and slow loris. Normal lab traffic: no false alarms.

**Real traffic (IoT-23, never used to tune anything):**

| | Result |
|---|---|
| One Amazon Echo, 5.5 hours, benign | 95 firewall actions (original setting) and 116 (60 s, both directions) in 5.5 h, i.e. about 17 and 21 per hour with a 60 s block counted as one action; 28 and 26 sustained alarms per hour. The rules tuned on lab traffic read ordinary device behaviour as exploit, flood and brute force. |
| Port scanning malware (3-1, first 30 min) | alarms were 100% precise in both settings; 9% (original) / 28% (60 s) of its connections were followed by an alarm with a plausible name (scan or brute force); 30% / 43% were noticed |
| Mirai and Torii C&C traffic (34-1, 20-1, 21-1) | noticed more often with the 60 s / both-directions setting (73% -> 98%, 50% -> 81%, 50% -> 71%, one 60 s scoring window for both), but never named as a beacon (0 of 314 connections, either setting): alarms were called brute force, credential replay or MQTT flood. The price: false-alarm seconds rose (Mirai: 38 -> 154 per hour) and firewall actions on the two Torii captures rose from 1 to 34 and from 3 to 60. |
| Quiet C&C traffic (8-1) | not noticed at all (0 of 8,222 connections) |
| Trojan file download (42-1) | its 6 malicious connections were all noticed, but 96-99% of the alarms were raised while nothing malicious was open (precision 4% original, 1% at 60 s) |

**What this means.** The detector reads the lab's attacks reliably and real scanning reasonably, but its thresholds
do not transfer to real device traffic: they false-alarm often and mis-name command-and-control. The lab accuracy
figures (98-100%) are in-sample and should not be quoted as general performance.

**Next steps for detection, in order:**
1. Learn each device's own normal behaviour (a camera talks to the same server at a steady rate) and flag departures,
   instead of fixed thresholds. This targets the false-alarm rate directly.
2. Re-tune or retrain on a mix of lab and public traffic, then test on captures that were held out.
3. Let the response step choose among every action the device can apply, by measured evidence, when the three
   strategies' own proposals are unavailable. The replay shows the remaining regret for exfiltration, C2, DNS tunneling
   and firmware tampering (1.8 each) is the arbiter falling back to ALERT where FORENSIC_CAPTURE scores 4.7.
4. Collect fresh Mininet captures of all 21 situations, including the four distributed attacks that have no saved
   captures yet: `sudo .venv/bin/python3 -m iot_defense.evaluation.harness --trials-per-condition 8 --output data/evaluation/results_v2.jsonl --pcap-dir data/evaluation/pcaps_v2 --restart`
   (about two hours; resumable).
