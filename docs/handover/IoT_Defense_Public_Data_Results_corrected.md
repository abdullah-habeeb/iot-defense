# IoT-23 results, corrected (one 60 s scoring window for both configurations)

## Benign Amazon Echo (5.5 h)

| Setting | Flagged s/h | Sustained alarms/h | Firewall actions (60 s block) | Actions/h | Called |
|---|---|---|---|---|---|
| original (5 s, inbound) | 159.48 | 28.069 | 95 | 17.315 | exploit_payload_injection x58, dos_flood x23, brute_force x6, data_exfiltration x4, reconnaissance_port_scan x3, buffer_overflow_probe x1 |
| 60 s, both | 593.63 | 26.428 | 116 | 21.143 | exploit_payload_injection x61, buffer_overflow_probe x14, brute_force x14, dos_flood x11, reconnaissance_port_scan x8, data_exfiltration x6, mqtt_message_flood x2 |

## Malware captures

| Capture | Setting | Conn. | Noticed | Named | Alarms | Precision | Alarm-s/h with nothing malicious open | Actions |
|---|---|---|---|---|---|---|---|---|
| m03.pcap | original | 1635 | 30% | 9% (146/1635) | 97 | 100% | 0.0 | 2 |
| m03.pcap | 60 s, both | 1635 | 43% | 28% (452/1635) | 263 | 100% | 0.0 | 6 |
| m34.pcap | original | 284 | 73% | 0% (0/284) | 113 | 83% | 38.08 | 14 |
| m34.pcap | 60 s, both | 284 | 98% | 0% (0/284) | 1129 | 93% | 154.31 | 15 |
| m08.pcap | original | 8222 | 0% | 0% (0/8222) | 0 | n/a | 0.0 | 0 |
| m08.pcap | 60 s, both | 8222 | 0% | 0% (0/8222) | 0 | n/a | 0.0 | 0 |
| m20.pcap | original | 16 | 50% | 0% (0/16) | 5 | 100% | 0.0 | 1 |
| m20.pcap | 60 s, both | 16 | 81% | 0% (0/16) | 1071 | 84% | 7.17 | 34 |
| m21.pcap | original | 14 | 50% | 0% (0/14) | 13 | 100% | 0.0 | 3 |
| m21.pcap | 60 s, both | 14 | 71% | 0% (0/14) | 1806 | 98% | 1.54 | 60 |
| m42.pcap | original | 6 | 100% | 33% (2/6) | 758 | 4% | 86.66 | 82 |
| m42.pcap | 60 s, both | 6 | 100% | 0% (0/6) | 6815 | 1% | 803.88 | 134 |