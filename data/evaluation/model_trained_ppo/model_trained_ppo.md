# PPO trained on the mechanism model (no measurements), graded on the measured table

3 seeds, 120000 timesteps each; model noise sigma 0.0. Regret is against the measured table's best response (0 = best).

| Arm | Models | Mean regret | Worst-case regret | Picks the measured-best (of 21) | Mean utility |
|---|---|---|---|---|---|
| rule_based | 1 | 2.996 | 5.20 | 4.0 | 4.326 |
| stackelberg | 1 | 0.042 | 0.88 | 20.0 | 7.280 |
| model_argmax | 1 | 0.549 | 5.25 | 17.0 | 6.773 |
| ppo_trained_on_model | 3 | 0.577 | 5.25 | 15.7 | 6.745 |
| ppo_trained_on_measured_table | 1 | 0.017 | 0.24 | 19.0 | 7.305 |

PPO reproduces the model's own best response in 84.1% of the 21 conditions (per seed: 86%, 86%, 81%), and agrees with Stackelberg in 69.8%.

## Per-condition regret

| Condition | model best | measured best | Stackelberg | PPO (model) | PPO (measured table) |
|---|---|---|---|---|---|
| normal | ALLOW | ALLOW | 0.00 | 1.10 | 0.00 |
| reconnaissance_port_scan | DECOY | BLOCK_SOURCE | 0.00 | 0.21 | 0.00 |
| dos_flood | BLOCK_SOURCE | BLOCK_SOURCE | 0.00 | 0.00 | 0.00 |
| brute_force | BLOCK_SOURCE | BLOCK_SOURCE | 0.00 | 0.00 | 0.00 |
| data_exfiltration | QUARANTINE | QUARANTINE | 0.00 | 0.00 | 0.00 |
| exploit_payload_injection | DECOY | BLOCK_SOURCE | 0.00 | 5.20 | 0.00 |
| tcp_syn_flood | BLOCK_SOURCE | BLOCK_SOURCE | 0.00 | 0.00 | 0.00 |
| icmp_ping_flood | BLOCK_SOURCE | BLOCK_SOURCE | 0.00 | 0.00 | 0.00 |
| slow_loris_exhaustion | BLOCK_SOURCE | BLOCK_SOURCE | 0.00 | 0.00 | 0.00 |
| dns_amplification | BLOCK_SOURCE | BLOCK_SOURCE | 0.00 | 0.00 | 0.00 |
| dns_tunneling_exfiltration | QUARANTINE | QUARANTINE | 0.00 | 0.00 | 0.00 |
| mqtt_message_flood | BLOCK_SOURCE | BLOCK_SOURCE | 0.00 | 0.00 | 0.00 |
| firmware_tampering | QUARANTINE | QUARANTINE | 0.00 | 0.00 | 0.00 |
| buffer_overflow_probe | DECOY | BLOCK_SOURCE | 0.00 | 5.25 | 0.00 |
| credential_replay | BLOCK_SOURCE | BLOCK_SOURCE | 0.00 | 0.00 | 0.00 |
| rogue_config_beacon | QUARANTINE | QUARANTINE | 0.00 | 0.00 | 0.00 |
| c2_beaconing | QUARANTINE | QUARANTINE | 0.00 | 0.00 | 0.00 |
| dos_flood_distributed | THROTTLE | THROTTLE | 0.00 | 0.24 | 0.24 |
| tcp_syn_flood_distributed | THROTTLE | THROTTLE | 0.00 | 0.12 | 0.12 |
| icmp_ping_flood_distributed | THROTTLE | QUARANTINE | 0.88 | 0.00 | 0.00 |
| credential_replay_distributed | QUARANTINE | QUARANTINE | 0.00 | 0.00 | 0.00 |
