# Detector evaluation

Offline scoring of the deployed rule-based detector (and a cross-validated Random Forest) on lab traffic. Intervals are 95% Wilson intervals; with few samples they are wide, and that width is the honest result.

## 1. Saved captures (Mininet pcaps, batch pipeline)

279 captures scored (6 empty or unreadable captures skipped). Accuracy 100% [98-100%].
False alarms on normal traffic: 0 of 16 benign captures flagged (0%, 95% interval [0-19%]). A rate cannot be pinned down from this few benign samples; see `pcap_replay` for hours of benign traffic.

| Class | n | Recall | 95% CI | Precision | 95% CI | Missed (FN) | Wrongly flagged (FP) |
|---|---|---|---|---|---|---|---|
| brute_force | 20 | 100% | [84-100%] | 100% | [84-100%] | 0 | 0 |
| buffer_overflow_probe | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| c2_beaconing | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| credential_replay | 15 | 93% | [70-99%] | 100% | [78-100%] | 1 | 0 |
| data_exfiltration | 20 | 100% | [84-100%] | 100% | [84-100%] | 0 | 0 |
| dns_amplification | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| dns_tunneling_exfiltration | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| dos_flood | 20 | 100% | [84-100%] | 100% | [84-100%] | 0 | 0 |
| exploit_payload_injection | 18 | 100% | [82-100%] | 100% | [82-100%] | 0 | 0 |
| firmware_tampering | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| icmp_ping_flood | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| mqtt_message_flood | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| normal | 16 | 100% | [81-100%] | 94% | [73-99%] | 0 | 1 |
| reconnaissance_port_scan | 20 | 100% | [84-100%] | 100% | [84-100%] | 0 | 0 |
| rogue_config_beacon | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| slow_loris_exhaustion | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| tcp_syn_flood | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |

Mistakes (truth -> predicted): credential_replay -> normal x1

### Time to detect (live defender's rolling window, replayed on the saved attack captures)

Seconds from the first packet to the defender acting (5 s window, 2 consecutive flagged checks). A capture the window never acted on counts as missed. Captures are truncated at a packet limit, so slow attacks can look worse than they are.

| Attack | Captures | Acted on | Median s | Max s |
|---|---|---|---|---|
| brute_force | 20 | 20 | 3.0 | 4.0 |
| buffer_overflow_probe | 15 | 15 | 2.0 | 2.0 |
| c2_beaconing | 15 | 15 | 3.0 | 4.0 |
| credential_replay | 15 | 0 | n/a | n/a |
| data_exfiltration | 20 | 0 | n/a | n/a |
| dns_amplification | 15 | 15 | 2.0 | 2.0 |
| dns_tunneling_exfiltration | 15 | 15 | 2.0 | 2.0 |
| dos_flood | 20 | 20 | 2.0 | 2.0 |
| exploit_payload_injection | 18 | 18 | 2.0 | 2.0 |
| firmware_tampering | 15 | 0 | n/a | n/a |
| icmp_ping_flood | 15 | 15 | 3.0 | 4.0 |
| mqtt_message_flood | 15 | 0 | n/a | n/a |
| reconnaissance_port_scan | 20 | 20 | 2.0 | 2.0 |
| rogue_config_beacon | 15 | 15 | 2.0 | 2.0 |
| slow_loris_exhaustion | 15 | 15 | 27.0 | 27.0 |
| tcp_syn_flood | 15 | 15 | 2.0 | 2.0 |

Windowed false alarms on the normal captures: 0.

## 2. Labelled flow table (260 single flows, by run)

Rule-based accuracy 87% [82-90%]; Random Forest, 5-fold cross-validated by run, 99% [97-100%]. This table has no inter-arrival column, so the rule-based beacon detector cannot fire on it; read its C2 row accordingly.

### Rule-based

| Class | n | Recall | 95% CI | Precision | 95% CI | Missed (FN) | Wrongly flagged (FP) |
|---|---|---|---|---|---|---|---|
| brute_force | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| buffer_overflow_probe | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| c2_beaconing | 15 | 0% | [0-20%] | n/a | n/a | 15 | 0 |
| credential_replay | 15 | 80% | [55-93%] | 100% | [76-100%] | 3 | 0 |
| data_exfiltration | 15 | 100% | [80-100%] | 94% | [72-99%] | 0 | 1 |
| dns_amplification | 15 | 87% | [62-96%] | 100% | [77-100%] | 2 | 0 |
| dns_tunneling_exfiltration | 15 | 87% | [62-96%] | 93% | [69-99%] | 2 | 1 |
| dos_flood | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| exploit_payload_injection | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| firmware_tampering | 15 | 100% | [80-100%] | 94% | [72-99%] | 0 | 1 |
| icmp_ping_flood | 15 | 87% | [62-96%] | 100% | [77-100%] | 2 | 0 |
| mqtt_message_flood | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| normal | 20 | 100% | [84-100%] | 38% | [26-52%] | 0 | 32 |
| reconnaissance_port_scan | 15 | 40% | [20-64%] | 100% | [61-100%] | 9 | 0 |
| rogue_config_beacon | 15 | 87% | [62-96%] | 100% | [77-100%] | 2 | 0 |
| slow_loris_exhaustion | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| tcp_syn_flood | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |

### Random Forest (cross-validated)

| Class | n | Recall | 95% CI | Precision | 95% CI | Missed (FN) | Wrongly flagged (FP) |
|---|---|---|---|---|---|---|---|
| brute_force | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| buffer_overflow_probe | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| c2_beaconing | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| credential_replay | 15 | 100% | [80-100%] | 94% | [72-99%] | 0 | 1 |
| data_exfiltration | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| dns_amplification | 15 | 100% | [80-100%] | 94% | [72-99%] | 0 | 1 |
| dns_tunneling_exfiltration | 15 | 100% | [80-100%] | 94% | [72-99%] | 0 | 1 |
| dos_flood | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| exploit_payload_injection | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| firmware_tampering | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| icmp_ping_flood | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| mqtt_message_flood | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| normal | 20 | 100% | [84-100%] | 100% | [84-100%] | 0 | 0 |
| reconnaissance_port_scan | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| rogue_config_beacon | 15 | 80% | [55-93%] | 100% | [76-100%] | 3 | 0 |
| slow_loris_exhaustion | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |
| tcp_syn_flood | 15 | 100% | [80-100%] | 100% | [80-100%] | 0 | 0 |

## 3. Live harness trials (includes distributed attacks)

168 trials. Accuracy 98% [94-99%]. Normal trials flagged: 0 of 8.

| Class | n | Recall | 95% CI | Precision | 95% CI | Missed (FN) | Wrongly flagged (FP) |
|---|---|---|---|---|---|---|---|
| brute_force | 8 | 100% | [68-100%] | 100% | [68-100%] | 0 | 0 |
| buffer_overflow_probe | 8 | 100% | [68-100%] | 100% | [68-100%] | 0 | 0 |
| c2_beaconing | 8 | 75% | [41-93%] | 100% | [61-100%] | 2 | 0 |
| credential_replay | 8 | 100% | [68-100%] | 100% | [68-100%] | 0 | 0 |
| credential_replay_distributed | 8 | 100% | [68-100%] | 100% | [68-100%] | 0 | 0 |
| data_exfiltration | 8 | 100% | [68-100%] | 100% | [68-100%] | 0 | 0 |
| dns_amplification | 8 | 100% | [68-100%] | 100% | [68-100%] | 0 | 0 |
| dns_tunneling_exfiltration | 8 | 100% | [68-100%] | 80% | [49-94%] | 0 | 2 |
| dos_flood | 8 | 100% | [68-100%] | 100% | [68-100%] | 0 | 0 |
| dos_flood_distributed | 8 | 100% | [68-100%] | 100% | [68-100%] | 0 | 0 |
| exploit_payload_injection | 8 | 100% | [68-100%] | 100% | [68-100%] | 0 | 0 |
| firmware_tampering | 8 | 100% | [68-100%] | 100% | [68-100%] | 0 | 0 |
| icmp_ping_flood | 8 | 100% | [68-100%] | 100% | [68-100%] | 0 | 0 |
| icmp_ping_flood_distributed | 8 | 100% | [68-100%] | 100% | [68-100%] | 0 | 0 |
| mqtt_message_flood | 8 | 100% | [68-100%] | 100% | [68-100%] | 0 | 0 |
| normal | 8 | 100% | [68-100%] | 80% | [49-94%] | 0 | 2 |
| reconnaissance_port_scan | 8 | 100% | [68-100%] | 100% | [68-100%] | 0 | 0 |
| rogue_config_beacon | 8 | 75% | [41-93%] | 100% | [61-100%] | 2 | 0 |
| slow_loris_exhaustion | 8 | 100% | [68-100%] | 100% | [68-100%] | 0 | 0 |
| tcp_syn_flood | 8 | 100% | [68-100%] | 100% | [68-100%] | 0 | 0 |
| tcp_syn_flood_distributed | 8 | 100% | [68-100%] | 100% | [68-100%] | 0 | 0 |

Mistakes: rogue_config_beacon -> dns_tunneling_exfiltration x2; c2_beaconing -> normal x2

The harness's `detection_latency_ms` (median 14581 ms) times the whole observation, including generating and capturing the traffic. It is not a time-to-detect.

## 4. Is the attack named correctly, and how soon?

The defender acts at its second consecutive flagged check, using the label current at that moment. Early evidence often looks like a different attack, so the table also gives how long until the label is right. **before**: inbound traffic, last 5 s. **after**: both traffic, last 60 s.

Each cell: captures acted on / label right when it acted / label right at some point, then median seconds to act and to the right label.

| Class | Captures | before | after |
|---|---|---|---|
| brute_force | 20 | 20 / 20 / 20 of 20 (act 3s, right 2s) | 20 / 20 / 20 of 20 (act 3s, right 2s) |
| buffer_overflow_probe | 15 | 15 / 0 / 0 of 15 (act 2s, right -) | 15 / 0 / 15 of 15 (act 2s, right 31s) |
| c2_beaconing | 15 | 15 / 0 / 0 of 15 (act 3s, right -) | 15 / 0 / 15 of 15 (act 3s, right 22s) |
| credential_replay | 15 | 0 / 0 / 0 of 15 (act -, right -) | 14 / 14 / 14 of 15 (act 18s, right 17s) |
| data_exfiltration | 20 | 0 / 0 / 0 of 20 (act -, right -) | 20 / 20 / 20 of 20 (act 4s, right 3s) |
| dns_amplification | 15 | 15 / 0 / 15 of 15 (act 2s, right 3s) | 15 / 0 / 15 of 15 (act 2s, right 3s) |
| dns_tunneling_exfiltration | 15 | 15 / 0 / 0 of 15 (act 2s, right -) | 15 / 0 / 15 of 15 (act 2s, right 9s) |
| dos_flood | 20 | 20 / 20 / 20 of 20 (act 2s, right 1s) | 20 / 20 / 20 of 20 (act 2s, right 1s) |
| exploit_payload_injection | 18 | 18 / 18 / 18 of 18 (act 2s, right 1s) | 18 / 18 / 18 of 18 (act 2s, right 1s) |
| firmware_tampering | 15 | 0 / 0 / 0 of 15 (act -, right -) | 15 / 0 / 15 of 15 (act 2s, right 8s) |
| icmp_ping_flood | 15 | 15 / 15 / 15 of 15 (act 3s, right 2s) | 15 / 15 / 15 of 15 (act 3s, right 2s) |
| mqtt_message_flood | 15 | 0 / 0 / 0 of 15 (act -, right -) | 15 / 0 / 15 of 15 (act 14s, right 31s) |
| normal | 16 | false alarms: 0/16 | false alarms: 0/16 |
| reconnaissance_port_scan | 20 | 20 / 20 / 20 of 20 (act 2s, right 1s) | 20 / 20 / 20 of 20 (act 2s, right 1s) |
| rogue_config_beacon | 15 | 15 / 0 / 0 of 15 (act 2s, right -) | 15 / 0 / 15 of 15 (act 2s, right 5s) |
| slow_loris_exhaustion | 15 | 15 / 0 / 0 of 15 (act 27s, right -) | 15 / 0 / 15 of 15 (act 3s, right 26s) |
| tcp_syn_flood | 15 | 15 / 15 / 15 of 15 (act 2s, right 1s) | 15 / 15 / 15 of 15 (act 2s, right 1s) |

## 5. Margin around the calibrated thresholds

Share of perturbed copies of each attack's own signature (each feature moved by up to +/-30%) that the detector still classifies correctly. Low values mean the rule sits close to a boundary.

| Attack | Perturbed copies | Still correct |
|---|---|---|
| reconnaissance | 343 | 71% |
| dos | 343 | 100% |
| brute_force | 343 | 100% |
| exfiltration | 2401 | 100% |
| exploit | 2401 | 86% |
| syn_flood | 343 | 43% |
| icmp_flood | 2401 | 57% |
| slow_loris | 2401 | 57% |
| dns_amplification | 2401 | 29% |
| dns_tunneling | 2401 | 43% |
| mqtt_flood | 2401 | 71% |
| firmware_tampering | 2401 | 29% |
| buffer_overflow | 2401 | 29% |
| replay_attack | 2401 | 71% |
| rogue_beacon | 2401 | 37% |
| c2_beacon | 2401 | 86% |
