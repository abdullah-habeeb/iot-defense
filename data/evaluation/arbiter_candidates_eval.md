# The arbiter with and without the supported actions as candidates

Held-out grading: for each of the measurement blocks the arbiter is built from the other blocks and graded on the held-out one (blocks [0, 1, 2], 168 harness trials, risk aversion 1.0). *Held-out utility* is the primary number. *Regret* grades the choice against the best action in the full table, which includes the held-out block, so it is an in-sample reference. Intervals are bootstrap intervals over trials that share one testbed: lower bounds on the real uncertainty.

## live: candidates are ALERT, ALLOW, BLOCK_SOURCE, FORENSIC_CAPTURE, THROTTLE

- **before**: held-out utility 6.045 per situation (trial mean 6.045, 95% CI [5.705, 6.368]); mean in-sample regret 0.462.
- **after**: held-out utility 6.486 per situation (trial mean 6.486, 95% CI [6.241, 6.720]); mean in-sample regret 0.020.
- **after minus before**: +0.442 per trial, 95% CI [+0.326, +0.563]; 40 of 168 trials differ (Wilcoxon p = 2.6e-08).
- Situations whose most frequent choice changed: 5 of 21 (c2_beaconing, credential_replay_distributed, data_exfiltration, dns_tunneling_exfiltration, firmware_tampering); trials where any fold chose differently: 40 of 168; trials where every proposal was unsupported: 32.

| Situation | Trials | Proposals (rule / Stackelberg / PPO) | Before | After | Held-out utility before -> after | Regret before -> after |
|---|---|---|---|---|---|---|
| brute_force | 8 | BLOCK_SOURCE / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| buffer_overflow_probe | 8 | RESET_SESSIONS / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| c2_beaconing **(focus)** | 8 | ISOLATE / QUARANTINE / QUARANTINE | ALERT | FORENSIC_CAPTURE * | 2.92 -> 4.28 | 1.78 -> 0.43 |
| credential_replay | 8 | BLOCK_SOURCE / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| credential_replay_distributed | 8 | THROTTLE / QUARANTINE / QUARANTINE | THROTTLE | FORENSIC_CAPTURE * | 2.80 -> 4.90 | 2.10 -> 0.00 |
| data_exfiltration **(focus)** | 8 | ISOLATE / QUARANTINE / QUARANTINE | ALERT | FORENSIC_CAPTURE * | 2.48 -> 4.28 | 1.80 -> 0.00 |
| dns_amplification | 8 | BANDWIDTH_CAP / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| dns_tunneling_exfiltration **(focus)** | 8 | DECOY / QUARANTINE / QUARANTINE | ALERT | FORENSIC_CAPTURE * | 2.80 -> 4.60 | 1.80 -> 0.00 |
| dos_flood | 8 | ISOLATE / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| dos_flood_distributed | 8 | ISOLATE / THROTTLE / QUARANTINE | THROTTLE | THROTTLE | 7.54 -> 7.54 | 0.00 -> 0.00 |
| exploit_payload_injection | 8 | DECOY / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| firmware_tampering **(focus)** | 8 | QUARANTINE / QUARANTINE / QUARANTINE | ALERT | FORENSIC_CAPTURE * | 2.79 -> 4.56 | 1.77 -> 0.00 |
| icmp_ping_flood | 8 | THROTTLE / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| icmp_ping_flood_distributed | 8 | THROTTLE / THROTTLE / QUARANTINE | THROTTLE | THROTTLE | 6.42 -> 6.42 | 0.00 -> 0.00 |
| mqtt_message_flood | 8 | THROTTLE / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| normal | 8 | ALLOW / ALLOW / ALLOW | ALLOW | ALLOW | 3.00 -> 3.00 | 0.00 -> 0.00 |
| reconnaissance_port_scan | 8 | DECOY / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| rogue_config_beacon | 8 | FORENSIC_CAPTURE / QUARANTINE / QUARANTINE | FORENSIC_CAPTURE | FORENSIC_CAPTURE | 4.07 -> 4.53 | 0.46 -> 0.00 |
| slow_loris_exhaustion | 8 | THROTTLE / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| tcp_syn_flood | 8 | ISOLATE / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| tcp_syn_flood_distributed | 8 | ISOLATE / THROTTLE / QUARANTINE | THROTTLE | THROTTLE | 7.42 -> 7.42 | 0.00 -> 0.00 |

\* the most frequent choice changed.

## lab: candidates are ALERT, ALLOW, BANDWIDTH_CAP, BLOCK_SOURCE, DECOY, FORENSIC_CAPTURE, ISOLATE, QUARANTINE, RESET_SESSIONS, THROTTLE

- **before**: held-out utility 7.271 per situation (trial mean 7.271, 95% CI [7.095, 7.423]); mean in-sample regret 0.051.
- **after**: held-out utility 7.271 per situation (trial mean 7.271, 95% CI [7.095, 7.423]); mean in-sample regret 0.051.
- **after minus before**: +0.000 per trial, 95% CI [+0.000, +0.000]; 0 of 168 trials differ (Wilcoxon p = 1).
- Situations whose most frequent choice changed: 0 of 21 (none); trials where any fold chose differently: 0 of 168; trials where every proposal was unsupported: 0.

| Situation | Trials | Proposals (rule / Stackelberg / PPO) | Before | After | Held-out utility before -> after | Regret before -> after |
|---|---|---|---|---|---|---|
| brute_force | 8 | BLOCK_SOURCE / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| buffer_overflow_probe | 8 | RESET_SESSIONS / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| c2_beaconing **(focus)** | 8 | ISOLATE / QUARANTINE / QUARANTINE | QUARANTINE | QUARANTINE | 6.22 -> 6.22 | 1.07 -> 1.07 |
| credential_replay | 8 | BLOCK_SOURCE / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| credential_replay_distributed | 8 | THROTTLE / QUARANTINE / QUARANTINE | QUARANTINE | QUARANTINE | 7.30 -> 7.30 | 0.00 -> 0.00 |
| data_exfiltration **(focus)** | 8 | ISOLATE / QUARANTINE / QUARANTINE | QUARANTINE | QUARANTINE | 7.30 -> 7.30 | 0.00 -> 0.00 |
| dns_amplification | 8 | BANDWIDTH_CAP / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| dns_tunneling_exfiltration **(focus)** | 8 | DECOY / QUARANTINE / QUARANTINE | QUARANTINE | QUARANTINE | 7.30 -> 7.30 | 0.00 -> 0.00 |
| dos_flood | 8 | ISOLATE / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| dos_flood_distributed | 8 | ISOLATE / THROTTLE / QUARANTINE | THROTTLE | THROTTLE | 7.54 -> 7.54 | 0.00 -> 0.00 |
| exploit_payload_injection | 8 | DECOY / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| firmware_tampering **(focus)** | 8 | QUARANTINE / QUARANTINE / QUARANTINE | QUARANTINE | QUARANTINE | 7.30 -> 7.30 | 0.00 -> 0.00 |
| icmp_ping_flood | 8 | THROTTLE / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| icmp_ping_flood_distributed | 8 | THROTTLE / THROTTLE / QUARANTINE | QUARANTINE | QUARANTINE | 7.30 -> 7.30 | 0.00 -> 0.00 |
| mqtt_message_flood | 8 | THROTTLE / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| normal | 8 | ALLOW / ALLOW / ALLOW | ALLOW | ALLOW | 3.00 -> 3.00 | 0.00 -> 0.00 |
| reconnaissance_port_scan | 8 | DECOY / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| rogue_config_beacon | 8 | FORENSIC_CAPTURE / QUARANTINE / QUARANTINE | QUARANTINE | QUARANTINE | 7.30 -> 7.30 | 0.00 -> 0.00 |
| slow_loris_exhaustion | 8 | THROTTLE / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| tcp_syn_flood | 8 | ISOLATE / BLOCK_SOURCE / BLOCK_SOURCE | BLOCK_SOURCE | BLOCK_SOURCE | 7.70 -> 7.70 | 0.00 -> 0.00 |
| tcp_syn_flood_distributed | 8 | ISOLATE / THROTTLE / QUARANTINE | THROTTLE | THROTTLE | 7.42 -> 7.42 | 0.00 -> 0.00 |

\* the most frequent choice changed.
