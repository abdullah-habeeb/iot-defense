# Brief for the author of the priors and the playbook entries

You are writing, from what you know about how networks and firewalls work, what each defensive response should do against two
attacks nobody has measured. Your numbers are a hypothesis. A measurement will then show how good the hypothesis was, whatever the
answer, and that answer is the research result. A bad prior is not a failure; an unjustified or peeked-at one is.

**Do not open** `data/outcomes/`, `data/evaluation/`, `EVALUATION.md`, `docs/FUTURE_WORK.md`, the dashboard's Arbiter Verdict table or
any result of this project. This brief and the files it names are all you need. If you have already seen the results, say so in
`blind_declaration.saw_outcome_table`; if you have seen any measurement of the two new attacks, stop and tell the team.

## The lab, in one paragraph

Five virtual hosts on one switch: the protected **sensor** (10.0.0.10), a **camera** (the legitimate user, 10.0.0.20), a smart
**plug** (10.0.0.30), the **attacker** host (10.0.0.100) and a **decoy** (10.0.0.200). A response is applied on the protected device
(or, for one response, on the attacker's own link) while the attack runs.

## What is measured, and how it becomes a score

For one response against one attack:

- **Containment**: the fraction of the attack's packets, compared with the same attack with no response, that no longer reach the
  receiving host. (Inbound attacks are received by the sensor; outbound ones, which leave the sensor, by the attacker-controlled host.)
- **Service lost**: the fraction of the camera's pings to the sensor that fail while the response is active.
- **Intelligence**: 1 if the response verifiably gathered evidence about the attacker (a decoy interaction, or a non-empty packet
  capture); otherwise 0.
- **Utility** = 5 x containment + 3 x (1 - service lost) + 2 x intelligence - cost, with these fixed costs: ALLOW 0, ALERT 0.1,
  FORENSIC_CAPTURE 0.3, BANDWIDTH_CAP 0.3, BLOCK_SOURCE 0.3, THROTTLE 0.4, RESET_SESSIONS 0.4, DECOY 0.5, QUARANTINE 0.7, ISOLATE 1.0.

## The ten responses (what each does mechanically)

| Response | What it does |
|---|---|
| ALLOW | nothing |
| ALERT | writes a log line; no network change |
| ISOLATE | takes the protected device's network interface down: no traffic in either direction |
| DECOY | redirects the attacker's connections to a decoy service on another host (an iptables NAT redirect) |
| THROTTLE | rate-limits **new connection attempts to the protected device** (iptables hashlimit; aware of TCP SYN, UDP and ICMP echo) |
| BLOCK_SOURCE | drops, at the protected device, all traffic from one identified source address; every other address is untouched |
| QUARANTINE | default-deny firewall on the protected device, both incoming and outgoing, with an allowlist of the network's known-legitimate peers |
| RESET_SESSIONS | destroys the established TCP sockets between the device and the attacker; leaves no standing rule |
| FORENSIC_CAPTURE | preserves a packet capture and a snapshot of connection state; changes nothing on the network |
| BANDWIDTH_CAP | installs a token-bucket rate cap on the **attacker host's own network interface** |

## The two attacks

1. **`ssdp_reflection`** (inbound). About 340-byte UDP datagrams from source port 1900 to a high port on the sensor, from a single
   lab address, at about 7 packets per second, 60 packets in about 9 seconds: the unsolicited search responses a victim of an SSDP/UPnP
   reflection-amplification attack receives.
2. **`telnet_scan_outbound`** (outbound). The sensor, assumed compromised, opens many short TCP connections to ports 23 and 2323 of
   another host, about 15 per second for about 6 seconds, the way Mirai-style malware scans for devices to infect. The traffic
   leaves the device; the target refuses the connections.

## The model that turns your numbers into a decision

The Stackelberg policy treats the attacker as a follower who either continues or retreats. The only attack-specific input it needs
is the **mechanism class** of the attack and, for each response, the **prior probability that the response neutralises that class**
(containment prior, 0 to 1). Service loss and intelligence priors are per response, not per class, and are already fixed:

- Service lost while the response is active: ISOLATE 1.0, QUARANTINE 0.35, THROTTLE 0.25, RESET_SESSIONS 0.15, DECOY 0.05; all others 0.
- Intelligence yield: DECOY 0.8, FORENSIC_CAPTURE 0.9; all others 0.

Existing classes and their written containment priors (committed long before these attacks existed; you may reuse any class
unchanged, which adds no new number to defend):

| Response | probing | flood | exhaustion | credential | payload | outbound | reflection | distributed_flood | distributed_trickle |
|---|---|---|---|---|---|---|---|---|---|
| ISOLATE | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| QUARANTINE | 0.95 | 0.95 | 0.95 | 0.95 | 0.95 | 0.9 | 0.95 | 0.9 | 0.9 |
| BLOCK_SOURCE | 0.95 | 0.95 | 0.95 | 0.95 | 0.9 | 0.3 | 0.95 | 0.15 | 0.15 |
| THROTTLE | 0.5 | 0.8 | 0.7 | 0.6 | 0.15 | 0.1 | 0.3 | 0.8 | 0.0 |
| RESET_SESSIONS | 0.0 | 0.05 | 0.5 | 0.2 | 0.5 | 0.2 | 0.0 | 0.0 | 0.0 |
| DECOY | 0.9 | 0.3 | 0.5 | 0.6 | 0.8 | 0.2 | 0.2 | 0.1 | 0.1 |
| BANDWIDTH_CAP | 0.1 | 0.4 | 0.1 | 0.1 | 0.05 | 0.0 | 0.8 | 0.15 | 0.15 |

(ALLOW, ALERT and FORENSIC_CAPTURE contain nothing by construction.) The 20 known attacks and their classes are in
`config/policies.yaml` under `policy.game_model.attack_class`.

## What to fill in (`config/experiments/new_attacks/preregistration.yaml`)

For **each** attack:

1. `attack_class`: an existing class, or `NEW`. If you choose `NEW`, give the class a name and, for **each of the seven** responses in
   the table above, a containment prior between 0 and 1 **and a written reason of at least a sentence** that points at the
   mechanism (what the response physically does to this traffic), not at a feeling. A prior with no reason is rejected.
2. `class_rationale`: why that class.
3. `playbook_response` and `playbook_rationale`: the single response a hand-written playbook for a home gateway would list for this attack.
4. `nearest_known_attack`: which of the 20 known attack types it most resembles (a separate baseline borrows that attack's measured best).

Then fill in `blind_declaration` truthfully, set `status: READY`, and run
`python -m iot_defense.experiments.new_attacks.prereg validate`.

A good reason names a mechanism, what the response physically does to this kind of traffic. A neutral example, about neither attack: "a limit on new connection attempts cannot shorten a connection that is already open, so it does little against traffic carried on one long-lived connection". A weak reason names an outcome you remember or guess. If you are unsure between two values, pick the one the mechanism supports and say how unsure you are in the reason.
