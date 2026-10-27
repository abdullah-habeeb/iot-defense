# Fresh live trials: the arbiter on the live defender, proposals only vs every supported action

168 paired trials. Each arm's action was applied and measured live; the arbiter's evidence (the outcome table) does not contain these trials.

- **arbiter_live_before**: mean utility 6.074, 95% CI [5.740, 6.396]
- **arbiter_live_after**: mean utility 6.517, 95% CI [6.272, 6.747]
- **after minus before**: +0.443, 95% CI [+0.326, +0.565]; 40 of 168 trials differ (Wilcoxon p = 2.2e-08).

| Situation | Trials | Before: actions (mean utility) | After: actions (mean utility) | Trials that changed |
|---|---|---|---|---|
| brute_force | 8 | BLOCK_SOURCE x8 (7.70) | BLOCK_SOURCE x8 (7.70) | 0 |
| buffer_overflow_probe | 8 | BLOCK_SOURCE x8 (7.70) | BLOCK_SOURCE x8 (7.70) | 0 |
| c2_beaconing **(focus)** | 8 | ALERT x7, ALLOW x1 (2.94) | ALLOW x1, FORENSIC_CAPTURE x7 (4.49) | 7 |
| credential_replay | 8 | BLOCK_SOURCE x8 (7.70) | BLOCK_SOURCE x8 (7.70) | 0 |
| credential_replay_distributed | 8 | THROTTLE x8 (2.44) | FORENSIC_CAPTURE x8 (4.58) | 8 |
| data_exfiltration **(focus)** | 8 | ALERT x8 (2.90) | FORENSIC_CAPTURE x8 (4.70) | 8 |
| dns_amplification | 8 | BLOCK_SOURCE x8 (7.70) | BLOCK_SOURCE x8 (7.70) | 0 |
| dns_tunneling_exfiltration **(focus)** | 8 | ALERT x8 (2.95) | FORENSIC_CAPTURE x8 (4.71) | 8 |
| dos_flood | 8 | BLOCK_SOURCE x8 (7.70) | BLOCK_SOURCE x8 (7.70) | 0 |
| dos_flood_distributed | 8 | THROTTLE x8 (7.54) | THROTTLE x8 (7.54) | 0 |
| exploit_payload_injection | 8 | BLOCK_SOURCE x8 (7.70) | BLOCK_SOURCE x8 (7.70) | 0 |
| firmware_tampering **(focus)** | 8 | ALERT x8 (2.74) | FORENSIC_CAPTURE x8 (4.64) | 8 |
| icmp_ping_flood | 8 | BLOCK_SOURCE x8 (7.70) | BLOCK_SOURCE x8 (7.70) | 0 |
| icmp_ping_flood_distributed | 8 | THROTTLE x8 (6.45) | THROTTLE x8 (6.45) | 0 |
| mqtt_message_flood | 8 | BLOCK_SOURCE x8 (7.70) | BLOCK_SOURCE x8 (7.70) | 0 |
| normal | 8 | ALLOW x8 (3.00) | ALLOW x8 (3.00) | 0 |
| reconnaissance_port_scan | 8 | BLOCK_SOURCE x8 (7.70) | BLOCK_SOURCE x8 (7.70) | 0 |
| rogue_config_beacon | 8 | ALERT x1, FORENSIC_CAPTURE x7 (4.47) | FORENSIC_CAPTURE x8 (4.63) | 1 |
| slow_loris_exhaustion | 8 | BLOCK_SOURCE x8 (7.70) | BLOCK_SOURCE x8 (7.70) | 0 |
| tcp_syn_flood | 8 | BLOCK_SOURCE x8 (7.70) | BLOCK_SOURCE x8 (7.70) | 0 |
| tcp_syn_flood_distributed | 8 | THROTTLE x8 (7.42) | THROTTLE x8 (7.42) | 0 |
