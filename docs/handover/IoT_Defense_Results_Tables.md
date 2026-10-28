# IoT-Defense: results tables for the paper

Source: all numbers are read from the VM (`~/iot-defense`, branch `outcome-based-policy-eval`, commit 44d8850): `data/outcomes/outcome_table.jsonl` (693 live Mininet measurements), `data/evaluation/results_measured.jsonl` (168 live paired trials), and the saved reports in `data/evaluation/`. Nothing here is estimated by hand.

## 0. How to read these tables

- **Utility** of one response to one attack = `5 x containment + 3 x service kept + 2 x intelligence gained - action cost`. Best possible for an attack is 8 (stop everything, lose no service) minus the response cost; for normal traffic it is 3.00 (do nothing).
- **Action costs:** ALLOW 0, ALERT 0.1, FORENSIC_CAPTURE 0.3, BANDWIDTH_CAP 0.3, BLOCK_SOURCE 0.3, THROTTLE 0.4, RESET_SESSIONS 0.4, DECOY 0.5, QUARANTINE 0.7, ISOLATE 1.0.
- **Containment** = share of the un-responded attack's packets that never reached the target (iptables counter vs the no-response baseline). **Service loss** = share of legitimate camera-to-sensor pings that failed. **Intel** = share of runs that gave verified evidence.
- **Record book / outcome table:** each of the 10 responses was applied to each of the 21 situations (normal + 20 attacks), 3 repetitions each, in live Mininet: 693 rows, 0 invalid.
- **Regret** of a strategy on an attack = (utility of the table's best response) - (table utility of the response the strategy chose). 0 means it chose the measured-best response.
- **Strategy choices** are what each strategy actually chose in 8 live trials per situation (168 trials). The detector was shared by all strategies (97.6% accurate, 4 misses in 168), so differences are due to the strategies only.

## 1. Headline scores

### 1a. Live paired trials (168 trials, each strategy's chosen response applied live)

| Strategy | Mean utility | 95% CI | Containment (attacks) | Service loss | Intel (attacks) | Exec failures |
|---|---|---|---|---|---|---|
| Rule-based | 4.272 | [4.00, 4.56] | 53.9% | 30.4% | 8.8% | 0% |
| Stackelberg | 7.226 | [7.04, 7.38] | 98.3% | 1.7% | 0.0% | 0% |
| PPO | 7.254 | [7.08, 7.40] | 98.8% | 0.0% | 0.0% | 0% |
| Arbiter (picks best-evidenced proposal) | 7.271 | [7.09, 7.42] | - | - | - | - |
| Naive: block everything | 3.940 | [3.90, 3.97] | 98.8% | 94.0% | 0.0% | 0% |
| Naive: always allow | 3.000 | [3.00, 3.00] | 0.0% | 0.0% | 0.0% | 0% |

Paired differences (Wilcoxon, Holm-corrected for the three main comparisons):

| Comparison | Mean diff | 95% CI | p (Wilcoxon; Holm-corrected for the first three) | Trials that differ |
|---|---|---|---|---|
| Rule-based - Stackelberg | -2.954 | [-3.26, -2.64] | 3.8e-22 | 126/168 |
| Rule-based - PPO | -2.981 | [-3.27, -2.68] | 2.4e-23 | 134/168 |
| **Stackelberg - PPO** | -0.027 | [-0.06, 0.00] | 0.69 (not significant) | 24/168 |
| Arbiter - Stackelberg | +0.044 | [+0.016, +0.081] | 0.0078 | 8/168 |
| Arbiter - PPO | +0.017 | [+0.009, +0.026] | 0.0004 | 16/168 |

### 1b. Scored against the record book (one canonical choice per situation, 21 situations)

| Strategy | Mean table utility | Mean regret | Worst-case regret | Picks the measured-best | Within 0.1 of best |
|---|---|---|---|---|---|
| Rule-based | 4.326 | 2.996 | 5.20 | 4/21 | 4/21 |
| Stackelberg | 7.280 | 0.042 | 0.88 | 20/21 | 20/21 |
| PPO | 7.305 | 0.017 | 0.24 | 19/21 | 19/21 |
| Lookup: best row of the table (upper bound) | 7.322 | 0.000 | 0.00 | 21/21 | 21/21 |

Note: the table-lookup row is the ceiling for known attacks. Stackelberg reaches 99.4% of it and PPO 99.8%.

### 1c. One fixed response for every situation (mean table utility over the 21 situations)

| Response | Mean utility |
|---|---|
| QUARANTINE | 6.919 |
| BLOCK_SOURCE | 5.312 |
| FORENSIC_CAPTURE | 4.550 |
| THROTTLE | 4.097 |
| ISOLATE | 3.762 |
| BANDWIDTH_CAP | 3.219 |
| ALLOW | 2.995 |
| ALERT | 2.924 |
| DECOY | 2.710 |
| RESET_SESSIONS | 2.639 |

QUARANTINE everywhere (6.92) is the strongest single fixed response. It is only 0.39 below the best strategy, which is a fair point to concede in the paper.

## 2. Per-attack scores: all 21 situations

Utility is the table mean for the response each strategy chose. Bold = the table-best response.

| # | Situation | Table-best response (utility) | Rule-based | Stackelberg | PPO | Lowest regret |
|---|---|---|---|---|---|---|
| 1 | normal | ALLOW 3.00 | **ALLOW** 3.00 (regret 0.00) | **ALLOW** 3.00 (regret 0.00) | **ALLOW** 3.00 (regret 0.00) | all three tie |
| 2 | reconnaissance_port_scan | BLOCK_SOURCE 7.70 | DECOY 7.49 (regret 0.21) | **BLOCK_SOURCE** 7.70 (regret 0.00) | **BLOCK_SOURCE** 7.70 (regret 0.00) | Stackelberg = PPO tie |
| 3 | dos_flood | BLOCK_SOURCE 7.70 | ISOLATE 4.00 (regret 3.70) | **BLOCK_SOURCE** 7.70 (regret 0.00) | **BLOCK_SOURCE** 7.70 (regret 0.00) | Stackelberg = PPO tie |
| 4 | brute_force | BLOCK_SOURCE 7.70 | **BLOCK_SOURCE** 7.70 (regret 0.00) | **BLOCK_SOURCE** 7.70 (regret 0.00) | **BLOCK_SOURCE** 7.70 (regret 0.00) | all three tie |
| 5 | data_exfiltration | QUARANTINE 7.30 | ISOLATE 4.00 (regret 3.30) | **QUARANTINE** 7.30 (regret 0.00) | **QUARANTINE** 7.30 (regret 0.00) | Stackelberg = PPO tie |
| 6 | exploit_payload_injection | BLOCK_SOURCE 7.70 | DECOY 2.50 (regret 5.20) | **BLOCK_SOURCE** 7.70 (regret 0.00) | **BLOCK_SOURCE** 7.70 (regret 0.00) | Stackelberg = PPO tie |
| 7 | tcp_syn_flood | BLOCK_SOURCE 7.70 | ISOLATE 4.00 (regret 3.70) | **BLOCK_SOURCE** 7.70 (regret 0.00) | **BLOCK_SOURCE** 7.70 (regret 0.00) | Stackelberg = PPO tie |
| 8 | icmp_ping_flood | BLOCK_SOURCE 7.70 | THROTTLE 4.43 (regret 3.27) | **BLOCK_SOURCE** 7.70 (regret 0.00) | **BLOCK_SOURCE** 7.70 (regret 0.00) | Stackelberg = PPO tie |
| 9 | slow_loris_exhaustion | BLOCK_SOURCE 7.70 | THROTTLE 2.58 (regret 5.12) | **BLOCK_SOURCE** 7.70 (regret 0.00) | **BLOCK_SOURCE** 7.70 (regret 0.00) | Stackelberg = PPO tie |
| 10 | dns_amplification | BLOCK_SOURCE 7.70 | BANDWIDTH_CAP 2.70 (regret 5.00) | **BLOCK_SOURCE** 7.70 (regret 0.00) | **BLOCK_SOURCE** 7.70 (regret 0.00) | Stackelberg = PPO tie |
| 11 | dns_tunneling_exfiltration | QUARANTINE 7.30 | DECOY 2.40 (regret 4.90) | **QUARANTINE** 7.30 (regret 0.00) | **QUARANTINE** 7.30 (regret 0.00) | Stackelberg = PPO tie |
| 12 | mqtt_message_flood | BLOCK_SOURCE 7.70 | THROTTLE 2.56 (regret 5.14) | **BLOCK_SOURCE** 7.70 (regret 0.00) | **BLOCK_SOURCE** 7.70 (regret 0.00) | Stackelberg = PPO tie |
| 13 | firmware_tampering | QUARANTINE 7.30 | **QUARANTINE** 7.30 (regret 0.00) | **QUARANTINE** 7.30 (regret 0.00) | **QUARANTINE** 7.30 (regret 0.00) | all three tie |
| 14 | buffer_overflow_probe | BLOCK_SOURCE 7.70 | RESET_SESSIONS 2.75 (regret 4.95) | **BLOCK_SOURCE** 7.70 (regret 0.00) | **BLOCK_SOURCE** 7.70 (regret 0.00) | Stackelberg = PPO tie |
| 15 | credential_replay | BLOCK_SOURCE 7.70 | **BLOCK_SOURCE** 7.70 (regret 0.00) | **BLOCK_SOURCE** 7.70 (regret 0.00) | **BLOCK_SOURCE** 7.70 (regret 0.00) | all three tie |
| 16 | rogue_config_beacon | QUARANTINE 7.30 | FORENSIC_CAPTURE 4.53 (regret 2.77) *(FORENSIC_CAPTURE x6, DECOY x2)* | **QUARANTINE** 7.30 (regret 0.00) | **QUARANTINE** 7.30 (regret 0.00) | Stackelberg = PPO tie |
| 17 | c2_beaconing | QUARANTINE 7.30 | ISOLATE 4.00 (regret 3.30) *(ISOLATE x6, ALLOW x2)* | **QUARANTINE** 7.30 (regret 0.00) *(QUARANTINE x6, ALLOW x2)* | **QUARANTINE** 7.30 (regret 0.00) *(QUARANTINE x6, ALLOW x2)* | Stackelberg = PPO tie |
| 18 | dos_flood_distributed | THROTTLE 7.54 | ISOLATE 4.00 (regret 3.54) | **THROTTLE** 7.54 (regret 0.00) | QUARANTINE 7.30 (regret 0.24) | Stackelberg (only) |
| 19 | tcp_syn_flood_distributed | THROTTLE 7.42 | ISOLATE 4.00 (regret 3.42) | **THROTTLE** 7.42 (regret 0.00) | QUARANTINE 7.30 (regret 0.12) | Stackelberg (only) |
| 20 | icmp_ping_flood_distributed | QUARANTINE 7.30 | THROTTLE 6.42 (regret 0.88) | THROTTLE 6.42 (regret 0.88) | **QUARANTINE** 7.30 (regret 0.00) | PPO (only) |
| 21 | credential_replay_distributed | QUARANTINE 7.30 | THROTTLE 2.80 (regret 4.50) | **QUARANTINE** 7.30 (regret 0.00) | **QUARANTINE** 7.30 (regret 0.00) | Stackelberg = PPO tie |

Where a cell lists two responses, the detector mislabelled 2 of the 8 trials: c2_beaconing was read as normal (so every strategy chose ALLOW for those 2), and rogue_config_beacon was read as dns_tunneling_exfiltration (which changed only the rule-based choice, to DECOY; Stackelberg and PPO still chose QUARANTINE). That is detector error, not strategy error.

Ties inside the table: dos_flood has BLOCK_SOURCE and BANDWIDTH_CAP both at 7.70, so either is measured-best.

### Who wins how often

| Result | Situations |
|---|---|
| Stackelberg = PPO tie | 14 |
| all three tie | 4 |
| Stackelberg (only) | 2 |
| PPO (only) | 1 |

## 3. Why each best response is best

Grouped by what the measurements show. Every row of the table behind these explanations is in section 4.

| Situation | Table-best | Utility | Containment | Service loss | Why |
|---|---|---|---|---|---|
| normal | ALLOW | 3.00 | n/a | 0% | No attack: any response only costs something. Quarantine/block/isolate also cut off the legitimate device (service loss 100%). |
| reconnaissance_port_scan | BLOCK_SOURCE | 7.70 | 100% | 0% | Blocking the attacker's address stops 100% of the attack, with 0% service loss, at the cheapest cost that achieves it (0.3). QUARANTINE also contains 100% but costs 0.7; ISOLATE contains 100% but breaks the protected service (4.0). |
| dos_flood | BLOCK_SOURCE | 7.70 | 100% | 0% | Blocking the attacker's address stops 100% of the attack, with 0% service loss, at the cheapest cost that achieves it (0.3). QUARANTINE also contains 100% but costs 0.7; ISOLATE contains 100% but breaks the protected service (4.0). |
| brute_force | BLOCK_SOURCE | 7.70 | 100% | 0% | Blocking the attacker's address stops 100% of the attack, with 0% service loss, at the cheapest cost that achieves it (0.3). QUARANTINE also contains 100% but costs 0.7; ISOLATE contains 100% but breaks the protected service (4.0). |
| data_exfiltration | QUARANTINE | 7.30 | 100% | 0% | BLOCK_SOURCE contained ~0% in the measurements (the traffic is not stopped by blocking the source address). Only QUARANTINE and ISOLATE contain it; QUARANTINE keeps the service up, ISOLATE does not. |
| exploit_payload_injection | BLOCK_SOURCE | 7.70 | 100% | 0% | Blocking the attacker's address stops 100% of the attack, with 0% service loss, at the cheapest cost that achieves it (0.3). QUARANTINE also contains 100% but costs 0.7; ISOLATE contains 100% but breaks the protected service (4.0). |
| tcp_syn_flood | BLOCK_SOURCE | 7.70 | 100% | 0% | Blocking the attacker's address stops 100% of the attack, with 0% service loss, at the cheapest cost that achieves it (0.3). QUARANTINE also contains 100% but costs 0.7; ISOLATE contains 100% but breaks the protected service (4.0). |
| icmp_ping_flood | BLOCK_SOURCE | 7.70 | 100% | 0% | Blocking the attacker's address stops 100% of the attack, with 0% service loss, at the cheapest cost that achieves it (0.3). QUARANTINE also contains 100% but costs 0.7; ISOLATE contains 100% but breaks the protected service (4.0). |
| slow_loris_exhaustion | BLOCK_SOURCE | 7.70 | 100% | 0% | Blocking the attacker's address stops 100% of the attack, with 0% service loss, at the cheapest cost that achieves it (0.3). QUARANTINE also contains 100% but costs 0.7; ISOLATE contains 100% but breaks the protected service (4.0). |
| dns_amplification | BLOCK_SOURCE | 7.70 | 100% | 0% | Blocking the attacker's address stops 100% of the attack, with 0% service loss, at the cheapest cost that achieves it (0.3). QUARANTINE also contains 100% but costs 0.7; ISOLATE contains 100% but breaks the protected service (4.0). |
| dns_tunneling_exfiltration | QUARANTINE | 7.30 | 100% | 0% | BLOCK_SOURCE contained ~0% in the measurements (the traffic is not stopped by blocking the source address). Only QUARANTINE and ISOLATE contain it; QUARANTINE keeps the service up, ISOLATE does not. |
| mqtt_message_flood | BLOCK_SOURCE | 7.70 | 100% | 0% | Blocking the attacker's address stops 100% of the attack, with 0% service loss, at the cheapest cost that achieves it (0.3). QUARANTINE also contains 100% but costs 0.7; ISOLATE contains 100% but breaks the protected service (4.0). |
| firmware_tampering | QUARANTINE | 7.30 | 100% | 0% | BLOCK_SOURCE contained ~0% in the measurements (the traffic is not stopped by blocking the source address). Only QUARANTINE and ISOLATE contain it; QUARANTINE keeps the service up, ISOLATE does not. |
| buffer_overflow_probe | BLOCK_SOURCE | 7.70 | 100% | 0% | Blocking the attacker's address stops 100% of the attack, with 0% service loss, at the cheapest cost that achieves it (0.3). QUARANTINE also contains 100% but costs 0.7; ISOLATE contains 100% but breaks the protected service (4.0). |
| credential_replay | BLOCK_SOURCE | 7.70 | 100% | 0% | Blocking the attacker's address stops 100% of the attack, with 0% service loss, at the cheapest cost that achieves it (0.3). QUARANTINE also contains 100% but costs 0.7; ISOLATE contains 100% but breaks the protected service (4.0). |
| rogue_config_beacon | QUARANTINE | 7.30 | 100% | 0% | BLOCK_SOURCE contained ~0% in the measurements (the traffic is not stopped by blocking the source address). Only QUARANTINE and ISOLATE contain it; QUARANTINE keeps the service up, ISOLATE does not. |
| c2_beaconing | QUARANTINE | 7.30 | 100% | 0% | BLOCK_SOURCE contained ~0% in the measurements (the traffic is not stopped by blocking the source address). Only QUARANTINE and ISOLATE contain it; QUARANTINE keeps the service up, ISOLATE does not. |
| dos_flood_distributed | THROTTLE | 7.54 | 99% | 0% | Blocking one address does not help: the sources are spoofed/rotated (BLOCK_SOURCE contains only 17-20%). Rate-limiting works whatever the source (THROTTLE 96-99%), and is cheaper (0.4) than QUARANTINE (0.7). |
| tcp_syn_flood_distributed | THROTTLE | 7.42 | 96% | 0% | Blocking one address does not help: the sources are spoofed/rotated (BLOCK_SOURCE contains only 17-20%). Rate-limiting works whatever the source (THROTTLE 96-99%), and is cheaper (0.4) than QUARANTINE (0.7). |
| icmp_ping_flood_distributed | QUARANTINE | 7.30 | 100% | 0% | THROTTLE contains 96% but also drops the legitimate ping probe (33% service loss), which costs more than QUARANTINE's extra action cost. |
| credential_replay_distributed | QUARANTINE | 7.30 | 100% | 0% | Distributed credential replay: BLOCK_SOURCE 20%, THROTTLE 4%; only QUARANTINE/ISOLATE contain it, and QUARANTINE keeps the service up. |

Check on the arithmetic: BLOCK_SOURCE 5 x 1.00 + 3 x 1.00 - 0.3 = 7.70; QUARANTINE 5 + 3 - 0.7 = 7.30; THROTTLE (dos_flood_distributed) 5 x 0.988 + 3 - 0.4 = 7.54; ALLOW on normal traffic 3 x 1.00 = 3.00.

The mechanism behind the 'inside' group (why BLOCK_SOURCE contains ~0%) is my reading of the measurements, not something I verified in this session. The measurement itself (containment about 0%) is what the table records.

## 4. The full record book: mean utility of every response for every situation

Bold = the best response for that situation. Rows are situations, columns are the 10 responses.

| Situation | ALLOW | ALERT | FORENSIC | BW_CAP | BLOCK | THROTTLE | RESET | DECOY | QUARANTINE | ISOLATE |
|---|---|---|---|---|---|---|---|---|---|---|
| normal | **3.00** | 2.90 | 2.70 | 2.70 | -0.30 | 2.60 | 2.60 | 2.50 | -0.70 | -1.00 |
| reconnaissance_port_scan | 3.00 | 2.87 | 4.67 | 3.06 | **7.70** | 7.07 | 3.19 | 7.47 | 7.30 | 4.00 |
| dos_flood | 3.00 | 4.00 | 4.72 | 7.70 | **7.70** | 7.60 | 3.49 | 3.00 | 7.30 | 4.00 |
| brute_force | 3.00 | 3.16 | 4.44 | 3.36 | **7.70** | 2.78 | 2.38 | 2.41 | 7.30 | 4.00 |
| data_exfiltration | 3.00 | 2.90 | 4.70 | 3.03 | 2.70 | 2.60 | 2.93 | 2.50 | **7.30** | 4.00 |
| exploit_payload_injection | 3.00 | 2.90 | 5.12 | 2.70 | **7.70** | 2.60 | 2.60 | 2.50 | 7.30 | 4.00 |
| tcp_syn_flood | 3.00 | 2.90 | 4.70 | 2.70 | **7.70** | 6.69 | 2.60 | 2.50 | 7.30 | 4.00 |
| icmp_ping_flood | 3.00 | 2.90 | 4.70 | 2.70 | **7.70** | 4.43 | 2.60 | 2.50 | 7.30 | 4.00 |
| slow_loris_exhaustion | 3.00 | 2.90 | 4.70 | 2.70 | **7.70** | 2.58 | 2.60 | 2.50 | 7.30 | 4.00 |
| dns_amplification | 3.00 | 3.12 | 4.76 | 2.70 | **7.70** | 5.43 | 2.71 | 2.50 | 7.30 | 4.00 |
| dns_tunneling_exfiltration | 3.00 | 2.90 | 4.70 | 2.85 | 2.70 | 2.65 | 2.70 | 2.50 | **7.30** | 4.00 |
| mqtt_message_flood | 3.00 | 2.92 | 4.72 | 2.70 | **7.70** | 2.60 | 2.77 | 2.83 | 7.30 | 4.00 |
| firmware_tampering | 3.00 | 2.73 | 4.49 | 2.49 | 2.49 | 2.57 | 2.39 | 2.29 | **7.30** | 4.00 |
| buffer_overflow_probe | 3.00 | 2.90 | 4.75 | 2.75 | **7.70** | 2.70 | 2.80 | 2.50 | 7.30 | 4.00 |
| credential_replay | 3.00 | 3.11 | 4.49 | 2.49 | **7.70** | 2.39 | 2.29 | 2.19 | 7.30 | 4.00 |
| rogue_config_beacon | 3.00 | 2.71 | 4.51 | 3.22 | 2.76 | 2.84 | 2.73 | 2.28 | **7.30** | 4.00 |
| c2_beaconing | 3.00 | 2.90 | 4.70 | 2.70 | 2.70 | 2.60 | 2.60 | 2.50 | **7.30** | 4.00 |
| dos_flood_distributed | 3.00 | 2.90 | 4.70 | 6.51 | 3.53 | **7.54** | 2.60 | 2.50 | 7.30 | 4.00 |
| tcp_syn_flood_distributed | 3.00 | 2.90 | 4.70 | 2.70 | 3.54 | **7.42** | 2.60 | 2.78 | 7.30 | 4.00 |
| icmp_ping_flood_distributed | 2.90 | 2.90 | 4.70 | 3.83 | 3.54 | 6.42 | 2.60 | 2.50 | **7.30** | 4.00 |
| credential_replay_distributed | 3.00 | 3.00 | 4.90 | 2.80 | 3.68 | 2.80 | 2.70 | 2.60 | **7.30** | 4.00 |

### 4b. Containment (share of the attack stopped)

| Situation | ALLOW | ALERT | FORENSIC | BW_CAP | BLOCK | THROTTLE | RESET | DECOY | QUARANTINE | ISOLATE |
|---|---|---|---|---|---|---|---|---|---|---|
| reconnaissance_port_scan | 0% | -1% | -1% | 7% | 100% | 89% | 12% | 59% | 100% | 100% |
| dos_flood | 0% | 22% | 0% | 100% | 100% | 100% | 18% | 10% | 100% | 100% |
| brute_force | 0% | 5% | -5% | 13% | 100% | 4% | -4% | -2% | 100% | 100% |
| data_exfiltration | 0% | 0% | 0% | 7% | 0% | 0% | 7% | 0% | 100% | 100% |
| exploit_payload_injection | 0% | 0% | 8% | 0% | 100% | 0% | 0% | 0% | 100% | 100% |
| tcp_syn_flood | 0% | 0% | 0% | 0% | 100% | 82% | 0% | 0% | 100% | 100% |
| icmp_ping_flood | 0% | 0% | 0% | 0% | 100% | 57% | 0% | 0% | 100% | 100% |
| slow_loris_exhaustion | 0% | 0% | 0% | 0% | 100% | -0% | 0% | 0% | 100% | 100% |
| dns_amplification | 0% | 4% | 1% | 0% | 100% | 57% | 2% | 0% | 100% | 100% |
| dns_tunneling_exfiltration | 0% | 0% | 0% | 3% | 0% | 1% | 2% | 0% | 100% | 100% |
| mqtt_message_flood | 0% | 0% | 0% | 0% | 100% | 0% | 3% | 7% | 100% | 100% |
| firmware_tampering | 0% | -3% | -4% | -4% | -4% | -1% | -4% | -4% | 100% | 100% |
| buffer_overflow_probe | 0% | 0% | 1% | 1% | 100% | 2% | 4% | 0% | 100% | 100% |
| credential_replay | 0% | 4% | -4% | -4% | 100% | -4% | -6% | -6% | 100% | 100% |
| rogue_config_beacon | 0% | -4% | -4% | 10% | 1% | 5% | 3% | -4% | 100% | 100% |
| c2_beaconing | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 100% | 100% |
| dos_flood_distributed | 0% | 0% | 0% | 76% | 17% | 99% | 0% | 0% | 100% | 100% |
| tcp_syn_flood_distributed | 0% | 0% | 0% | 0% | 17% | 96% | 0% | 6% | 100% | 100% |
| icmp_ping_flood_distributed | 0% | 0% | 0% | 23% | 17% | 96% | 0% | 0% | 100% | 100% |
| credential_replay_distributed | 0% | 2% | 4% | 2% | 20% | 4% | 2% | 2% | 100% | 100% |

Negative or tiny values (such as -4%) are measurement noise around zero for responses that did nothing.

### 4c. Baseline attack size (packets reaching the target with no response)

| Situation | Baseline packets |
|---|---|
| reconnaissance_port_scan | 171 |
| dos_flood | 417439 |
| brute_force | 38 |
| data_exfiltration | 5 |
| exploit_payload_injection | 4 |
| tcp_syn_flood | 245 |
| icmp_ping_flood | 40 |
| slow_loris_exhaustion | 140 |
| dns_amplification | 60 |
| dns_tunneling_exfiltration | 34 |
| mqtt_message_flood | 90 |
| firmware_tampering | 48 |
| buffer_overflow_probe | 34 |
| credential_replay | 16 |
| rogue_config_beacon | 77 |
| c2_beaconing | 20 |
| dos_flood_distributed | 1200 |
| tcp_syn_flood_distributed | 400 |
| icmp_ping_flood_distributed | 400 |
| credential_replay_distributed | 17 |

Several baselines are very small (data_exfiltration 5, exploit_payload_injection 4, credential_replay 16, c2_beaconing 20). Containment for those is a ratio of a few packets, so it is coarser than for the floods.

## 5. Where the strategies actually differ

| Situation | Table-best | Stackelberg | PPO | Why they differ |
|---|---|---|---|---|
| dos_flood_distributed | THROTTLE 7.54 | THROTTLE 7.54 (regret 0) | QUARANTINE 7.30 (regret 0.24) | PPO prefers the safe response with 100% containment; the table says THROTTLE contains 99% for less cost |
| tcp_syn_flood_distributed | THROTTLE 7.42 | THROTTLE 7.42 (regret 0) | QUARANTINE 7.30 (regret 0.12) | Same pattern |
| icmp_ping_flood_distributed | QUARANTINE 7.30 | THROTTLE 6.42 (regret 0.88) | QUARANTINE 7.30 (regret 0) | Stackelberg's prior says THROTTLE suits ICMP; measured, it drops the legitimate ping probe (33% service loss) |

The other 18 situations: Stackelberg and PPO choose the same response, so any difference in utility comes only from the 3 above. Over all 21: Stackelberg mean regret 0.042, PPO 0.017.

## 6. Further numbers for the paper

### 6a. Arbiter

| Item | Value |
|---|---|
| Mean utility, live trials | 7.271 [7.09, 7.42] |
| Equals the best of the three proposals in every trial | yes (difference 0.000, 168/168) |
| Proposal the arbiter chose | Stackelberg 160, PPO 8, rule-based 0 |
| Trials with no evidence (fell back to Stackelberg) | 0 |
| Situation where it overrides Stackelberg | icmp_ping_flood_distributed (7.30 vs 6.37 live) |

### 6b. Generalisation: attacks the strategy was not built on (regret vs table, lower = better)

Leave-one-attack-out (20 held-out attacks):

| Arm | Mean regret [95% CI] | Picks measured-best |
|---|---|---|
| Rule-based | 3.15 [2.31, 3.91] | 3/20 |
| Stackelberg | 0.04 [0.00, 0.13] | 19/20 |
| PPO (never saw it) | 1.61 [0.85, 2.47] | 3/20 |
| Arbiter | 0.04 [0.00, 0.13] | 19/20 |
| One fixed action | 0.24 [0.15, 0.32] | 7/20 |

Stackelberg better than PPO in 17 of 20, equal in 3, worse in 0 (mean difference +1.57 regret). Leave-one-class-out (17 held-out): Stackelberg 0.05, PPO 2.19.

### 6c. Changing the goal (objective shift), mean regret over 21 situations

| Shift | Optimum changes in | Rule-based | Stackelberg rebuilt | Stackelberg stale | PPO stale | PPO retrained | Arbiter + stale PPO |
|---|---|---|---|---|---|---|---|
| service_critical | 0/21 | 4.90 | 1.44 | 0.14 | 0.02 | 0.02 | 0.00 |
| intelligence_priority | 20/21 | 5.52 | 2.82 | 3.13 | 3.11 | 0.01 | 0.96 |
| cost_averse | 1/21 | 3.40 | 0.00 | 0.00 | 0.10 | 0.00 | 0.00 |
| security_first | 0/21 | 3.62 | 0.02 | 0.02 | 0.01 | 0.14 | 0.00 |

### 6d. Unreliable detector (mean regret at 90% benign traffic)

| Detector error | Stackelberg | PPO deployed | PPO noise-aware + prior | Arbiter | Posterior arbiter |
|---|---|---|---|---|---|
| 0% (clean) | 0.00 | 0.00 | 0.22 | 0.00 | 0.13 |
| 2.2% (measured) | 0.01 | 0.01 | 0.22 | 0.00 | 0.11 |
| ~10% uniform | 0.33 | 0.36 | 0.27 | 0.34 | 0.32 |
| ~20% uniform | 0.59 | 0.65 | 0.29 | 0.62 | 0.59 |
| ~30% uniform | 0.89 | 0.99 | 0.36 | 0.93 | 0.68 |
| ~20% missed attacks | 0.71 | 0.79 | 0.35 | 0.74 | 0.59 |
| ~30% missed attacks | 0.95 | 1.08 | 0.39 | 1.00 | 0.70 |

Noise-aware PPO beats Stackelberg by 0.29-0.56 regret when the detector is 20-30% wrong, and costs about 0.21 when the detector is accurate. A PPO trained for 5% benign traffic looks best at 5% benign and worst at realistic mixes (training-prior artefact).

### 6e. Reactive attacker (4 spoofable attacks)

| Arm | Regret vs reactive attacker | Regret vs ordinary attacker |
|---|---|---|
| Rule-based | 2.75 | 2.67 |
| Stackelberg (deployed) | 2.17 | 0.00 |
| PPO (standard) | 2.17 | 0.00 |
| Stackelberg anticipating the switch | 0.56 | 1.19 |
| PPO trained on adaptive outcomes (in-sample) | 0.07 | 0.40 |
| Arbiter, adaptive evidence + anticipating proposer | 0.58 | 0.38 |

The model predicted which responses the attacker dodges by switching address in 16 of 16 (response, attack) pairs. The attacker is scripted, so this is a threat model, not evidence about real attackers.

### 6f. Robustness and cost

| Item | Value |
|---|---|
| PPO seeds tested | 10; mean regret 0.017, worst seed 0.022; all 10 near-optimal |
| Stackelberg containment prior vs measured | mean absolute error 0.116 over 90 (action, class) cells |
| Decision time (mean) | rule-based 0.05 ms, Stackelberg 0.46 ms, PPO 1.14 ms (all three 1.65 ms) |
| Disagreement, live trials | rule vs Stackelberg 75.0%, rule vs PPO 79.8%, Stackelberg vs PPO 14.3%, all identical 20.2% |
| Disagreement over 796 synthetic contexts | Stackelberg vs PPO agree 100% in-distribution (784); on 12 out-of-distribution contexts PPO chose ISOLATE where the others chose ALERT |
| Objective weighting sensitivity (live data) | PPO > Stackelberg > others under service-heavy, containment-heavy and no-action-cost weightings |
| Detector accuracy in live harness | 97.6% (shared by all strategies) |

## 7. Limits to state in the paper

1. The record book is a lab measurement: 5 virtual devices in Mininet, 3 repetitions per cell, one attacker behaviour. It is not data from a real home network.
2. PPO was trained on this table, so its scores on the 21 known situations are in-sample. The generalisation tests (6b) are the fair comparison.
3. On the 21 known situations, a table lookup is the upper bound and Stackelberg and PPO are within 0.6% of it; they do not beat it. The strategies matter only when the table does not apply (new attack, unreliable detector, reactive attacker).
4. The detector-noise and reactive-attacker results come from simulation on top of the table (scripted attacker, made-up error rates), apart from the 2.2% measured detector error.
5. Some baselines are only a few packets (section 4c), so those containment values are coarse.
6. Live trials: 8 per situation. The 2 missed detections each in c2_beaconing and rogue_config_beacon are detector errors, shared by all three strategies.

