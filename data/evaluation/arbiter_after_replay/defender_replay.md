# The whole live defender, replayed on saved lab attacks

Policy: arbiter (arbiter candidates: the proposals plus every supported response). Each capture drives the real defender (detection, policy pipeline, response executor) against a recording firewall. Regret is how far the response chosen falls below the best response *the live defender can apply* for the true attack, by the measured outcome table (0 = the best available). 'First' is the response decided at the first confirmed alarm; 'final' is the last one decided within one block lifetime (60 s) of it.

- **before**: inbound traffic, last 5 s, decides once per source.
- **after**: both traffic, last 60 s, decides again when the name changes.

| Attack | Captures | before: acted / name right at first / name right at last / regret first -> final / seconds to final | after: acted / name right at first / name right at last / regret first -> final / seconds to final |
|---|---|---|---|
| brute_force | 5 | 5 / 5 / 5 / 0.00 -> 0.00 / 3 | 5 / 5 / 5 / 0.00 -> 0.00 / 3 |
| buffer_overflow_probe | 5 | 5 / 0 / 0 / 0.00 -> 0.00 / 2 | 5 / 0 / 5 / 0.00 -> 0.00 / 32 |
| c2_beaconing | 5 | 5 / 0 / 0 / 2.00 -> 2.00 / 3 | 5 / 0 / 5 / 2.00 -> 0.00 / 23 |
| credential_replay | 5 | 0 / 0 / 0 / - -> - / - | 5 / 5 / 5 / 0.00 -> 0.00 / 18 |
| data_exfiltration | 5 | 0 / 0 / 0 / - -> - / - | 5 / 5 / 5 / 0.00 -> 0.00 / 4 |
| dns_amplification | 5 | 5 / 0 / 5 / 2.94 -> 0.00 / 4 | 5 / 0 / 5 / 2.94 -> 0.00 / 4 |
| dns_tunneling_exfiltration | 5 | 5 / 0 / 0 / 2.00 -> 2.00 / 2 | 5 / 0 / 5 / 2.00 -> 0.00 / 10 |
| dos_flood | 5 | 5 / 5 / 5 / 0.00 -> 0.00 / 2 | 5 / 5 / 5 / 0.00 -> 0.00 / 2 |
| exploit_payload_injection | 5 | 5 / 5 / 5 / 0.00 -> 0.00 / 2 | 5 / 5 / 5 / 0.00 -> 0.00 / 2 |
| firmware_tampering | 5 | 0 / 0 / 0 / - -> - / - | 5 / 0 / 5 / 0.00 -> 0.00 / 9 |
| icmp_ping_flood | 5 | 5 / 5 / 5 / 0.00 -> 0.00 / 3 | 5 / 5 / 5 / 0.00 -> 0.00 / 3 |
| mqtt_message_flood | 5 | 0 / 0 / 0 / - -> - / - | 5 / 0 / 5 / 0.00 -> 0.00 / 32 |
| normal | 5 | false alarms 0/5 | false alarms 0/5 |
| reconnaissance_port_scan | 5 | 5 / 5 / 5 / 0.00 -> 0.00 / 2 | 5 / 5 / 5 / 0.00 -> 0.00 / 2 |
| rogue_config_beacon | 5 | 5 / 0 / 0 / 1.79 -> 1.79 / 2 | 5 / 0 / 5 / 1.79 -> 0.00 / 6 |
| slow_loris_exhaustion | 5 | 5 / 0 / 0 / 0.00 -> 0.00 / 27 | 5 / 0 / 5 / 0.00 -> 0.00 / 27 |
| tcp_syn_flood | 5 | 5 / 5 / 5 / 0.00 -> 0.00 / 2 | 5 / 5 / 5 / 0.00 -> 0.00 / 2 |
