# New-attack transfer experiment: results

Generated 2026-10-27T10:50:10+0000 from 66 measured rows (sha256 `c10785d79cbdbfd55c2e5793811145ff3e8a7860e040bb3e3e32d7bc46339f34`). Regret = best measured response minus the chosen response, in utility points, on blocks 0 to 2.

**Pre-registered verdict: PASS** (2 of 2 attacks pass: Stackelberg regret <= 1.0 and not worse than the playbook).

## ssdp_reflection
Class used by Stackelberg: `reflection`. Blocks: [0, 1, 2]. Best response: **BLOCK_SOURCE** (7.70). Practically tied with it (within 0.25): BLOCK_SOURCE. Verdict: **PASS**.

| Policy | Chose | Its utility | Regret | Rank of 10 | Regret per block |
|---|---|---|---|---|---|
| Stackelberg (frozen priors) | BLOCK_SOURCE | 7.70 | 0.00 | 1 | [0.0, 0.0, 0.0] |
| Rule-based playbook (frozen entry) | BLOCK_SOURCE | 7.70 | 0.00 | 1 | [0.0, 0.0, 0.0] |
| Same priors, attacker's reaction ignored | BLOCK_SOURCE | 7.70 | 0.00 | 1 | [0.0, 0.0, 0.0] |
| Best single response on the 20 known attacks | QUARANTINE | 7.30 | 0.40 | 2 | [0.4, 0.4, 0.4] |
| Borrow the nearest known attack's measured best | BLOCK_SOURCE | 7.70 | 0.00 | 1 | [0.0, 0.0, 0.0] |
| Always QUARANTINE | QUARANTINE | 7.30 | 0.40 | 2 | [0.4, 0.4, 0.4] |
| Do nothing (ALLOW) | ALLOW | 3.00 | 4.70 | 6 | [4.7, 4.7, 4.7] |

Measured mean utility per response: BLOCK_SOURCE 7.70, QUARANTINE 7.30, THROTTLE 5.60, FORENSIC_CAPTURE 4.70, ISOLATE 4.00, ALLOW 3.00, ALERT 2.90, BANDWIDTH_CAP 2.70, RESET_SESSIONS 2.60, DECOY 2.50

## telnet_scan_outbound
Class used by Stackelberg: `outbound`. Blocks: [0, 1, 2]. Best response: **QUARANTINE** (7.30). Practically tied with it (within 0.25): QUARANTINE. Verdict: **PASS**.

| Policy | Chose | Its utility | Regret | Rank of 10 | Regret per block |
|---|---|---|---|---|---|
| Stackelberg (frozen priors) | QUARANTINE | 7.30 | 0.00 | 1 | [0.0, 0.0, 0.0] |
| Rule-based playbook (frozen entry) | QUARANTINE | 7.30 | 0.00 | 1 | [0.0, 0.0, 0.0] |
| Same priors, attacker's reaction ignored | QUARANTINE | 7.30 | 0.00 | 1 | [0.0, 0.0, 0.0] |
| Best single response on the 20 known attacks | QUARANTINE | 7.30 | 0.00 | 1 | [0.0, 0.0, 0.0] |
| Borrow the nearest known attack's measured best | BLOCK_SOURCE | 6.67 | 0.63 | 2 | [0.6417, 0.6309, 0.6309] |
| Always QUARANTINE | QUARANTINE | 7.30 | 0.00 | 1 | [0.0, 0.0, 0.0] |
| Do nothing (ALLOW) | ALLOW | 3.00 | 4.30 | 5 | [4.3, 4.3, 4.3] |

Measured mean utility per response: QUARANTINE 7.30, BLOCK_SOURCE 6.67, FORENSIC_CAPTURE 4.75, ISOLATE 4.00, ALLOW 3.00, ALERT 2.90, BANDWIDTH_CAP 2.75, RESET_SESSIONS 2.65, THROTTLE 2.62, DECOY 2.55

## Sanity check on the 21 known situations

The same code on the benchmark: mean regret Stackelberg 0.0419, rule-based 2.9955 (EVALUATION.md reports 0.042 and 2.996).

PPO: Not applicable. PPO's observation encodes the attack label as one of the 21 known conditions, so an unseen attack cannot be presented to a trained model; using it would mean rebuilding and retraining it on the very measurements being predicted.
