"""Single-definition registry for attack scenarios.

Before this module existed, adding one attack type meant hand-editing six
different files (traffic generation, detection thresholds, the ML label
schema, the Stackelberg payoff lookup, the rule-based policy's decision
branches, and PPO's observation encoding) -- each edited by copying the
previous attack's pattern. That repetition is exactly what made adding the
second attack type (DoS) bug-prone: the same kind of mistake had to be
avoided independently in each of those places.

Adding a new attack now means adding one AttackScenario entry here. Every
dependent module (detection/detector.py, defense/stackelberg.py,
defense/policy.py, defense/ppo_env.py, ml/schema.py, ml/generate_dataset.py,
demo/controller.py) reads from ATTACK_SCENARIOS instead of hardcoding
per-attack logic.

UnifiedRuleBasedDetector checks scenarios in registry order and returns the
first one whose detector fires -- registration order is a real tiebreak,
not a formality, because these signatures are NOT all naturally disjoint.
Port diversity alone separates a scan (many ports) from everything else
(one port); rate alone separates a flood (very high, raw burst) from the
rest. But brute-force and exfiltration overlap on both axes they check --
same port-diversity bound, and their packet_count windows intersect
([12, inf) vs [3, 25]) -- so RuleBasedBruteForceDetector (checked first)
carries an explicit average_packet_size upper bound specifically to stay
out of exfiltration's territory (tens of bytes vs 1200+), not because the
two signatures happened to fall apart on their own. Adding a future attack
whose signature could overlap with an existing one needs the same kind of
explicit exclusion, not just a hopeful ordering choice.

Registration order here also fixes ml/schema.py's LABEL_NAMES integer
mapping (1=reconnaissance, 2=dos, ...) and defense/ppo_env.py's
TRAINING_SCENARIOS tuple, both of which enumerate ATTACK_SCENARIOS in
order. Reordering existing entries changes those numeric/positional
mappings and invalidates any already-trained RF/PPO model checkpoint --
append new attacks at the end rather than reordering existing ones.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable

# DefenseAction is imported lazily inside _build_registry(), not here at
# module level: iot_defense.defense.decision's own package (iot_defense.defense)
# eagerly imports policy.py/stackelberg.py/ppo_env.py as part of its
# __init__.py, and those modules read ATTACK_SCENARIOS back from this
# module -- a top-level import here would deadlock on the still-partially-
# built registry the moment any of those modules load DefenseAction through
# this file. TYPE_CHECKING-only imports below are never evaluated at
# runtime, so they don't participate in that cycle.
if TYPE_CHECKING:
    from iot_defense.defense.decision import DefenseAction
    from iot_defense.detection.detector import Detector


@dataclass(frozen=True)
class AttackScenario:
    """Everything one attack type needs to exist end-to-end, defined once."""

    key: str
    """CLI / attack_mode identifier, e.g. "reconnaissance", "dos"."""

    label: str
    """Human-readable name for the dashboard/CLI, e.g. "DDoS flood"."""

    attack_type: str
    """Canonical detection label used in ThreatEvent.attack_type and
    SecurityContext.beliefs.threat_type, e.g. "reconnaissance_port_scan"."""

    observed_threat_key: str
    """Stackelberg lookup key in config/policies.yaml, e.g. "DOS_FLOOD"."""

    build_detector: Callable[[], Detector]
    """Factory for this attack's rule-based detector (a fresh instance per
    call, so config-driven thresholds are re-read each time)."""

    generate_traffic: Callable[[Any], Any]
    """(net) -> raw traffic-generator result. Involves the sensor at
    10.0.0.10 in every attack, but not always as the traffic *target* --
    exfiltration reverses direction (the sensor is the compromised
    traffic *source*, the attacker-controlled host is the destination),
    matching how RuleBasedExfiltrationDetector swaps source_ip/
    destination_ip on the resulting ThreatEvent."""

    capture_packet_limit: int
    capture_duration_seconds: float
    capture_completion_timeout: float

    preferred_action: DefenseAction
    """What RuleBasedDefensePolicy favors once score/confidence clear this
    attack's own thresholds (checked after the normal/severe catch-alls)."""
    action_score_min: float
    action_confidence_min: float

    intention: str
    """BDI-style intention associated with this attack in build_security_context()."""

    ppo_example_features: dict[str, float]
    """Template observed_features for PPO's synthetic training scenario."""
    ppo_threat_score: float
    ppo_confidence: float


def _build_registry() -> dict[str, AttackScenario]:
    # Imported here, not at module level, to avoid a circular import: these
    # modules import iot_defense.attacks.registry themselves.
    from iot_defense.defense.decision import DefenseAction
    from iot_defense.detection.detector import (
        RuleBasedBruteForceDetector,
        RuleBasedBufferOverflowDetector,
        RuleBasedDnsAmplificationDetector,
        RuleBasedDnsTunnelingDetector,
        RuleBasedDosDetector,
        RuleBasedExfiltrationDetector,
        RuleBasedExploitDetector,
        RuleBasedFirmwareTamperingDetector,
        RuleBasedIcmpFloodDetector,
        RuleBasedMqttFloodDetector,
        RuleBasedReconDetector,
        RuleBasedReplayAttackDetector,
        RuleBasedRogueBeaconDetector,
        RuleBasedSlowLorisDetector,
        RuleBasedSynFloodDetector,
    )
    from iot_defense.simulation.traffic import TrafficGenerator

    traffic = TrafficGenerator()

    return {
        "reconnaissance": AttackScenario(
            key="reconnaissance",
            label="Reconnaissance (port scan)",
            attack_type="reconnaissance_port_scan",
            observed_threat_key="RECONNAISSANCE_PORT_SCAN",
            build_detector=RuleBasedReconDetector,
            generate_traffic=lambda net: traffic.generate_malicious_mininet_traffic(net, duration_seconds=5),
            capture_packet_limit=25,
            capture_duration_seconds=5.0,
            capture_completion_timeout=6.0,
            preferred_action=DefenseAction.DECOY,
            action_score_min=0.8,
            action_confidence_min=0.8,
            intention="gather_attacker_intelligence_when_appropriate",
            ppo_example_features={"packets_per_second": 20.0, "unique_destination_ports": 4},
            ppo_threat_score=0.9,
            ppo_confidence=0.88,
        ),
        "dos": AttackScenario(
            key="dos",
            label="DDoS flood",
            attack_type="dos_flood",
            observed_threat_key="DOS_FLOOD",
            build_detector=RuleBasedDosDetector,
            generate_traffic=lambda net: traffic.generate_dos_mininet_traffic(net, duration_seconds=4),
            capture_packet_limit=200,
            capture_duration_seconds=4.0,
            capture_completion_timeout=5.0,
            preferred_action=DefenseAction.ISOLATE,
            action_score_min=0.7,
            action_confidence_min=0.7,
            intention="contain_malicious_activity",
            ppo_example_features={"packets_per_second": 80.0, "unique_destination_ports": 1},
            ppo_threat_score=0.92,
            ppo_confidence=0.9,
        ),
        "brute_force": AttackScenario(
            key="brute_force",
            label="Brute-force / credential stuffing",
            attack_type="brute_force",
            observed_threat_key="BRUTE_FORCE",
            build_detector=RuleBasedBruteForceDetector,
            generate_traffic=lambda net: traffic.generate_brute_force_mininet_traffic(net, duration_seconds=6),
            capture_packet_limit=100,
            capture_duration_seconds=6.0,
            capture_completion_timeout=7.0,
            # Originally THROTTLE (rate-limiting the repeated attempts
            # defeats a brute-force attack's actual mechanism while
            # leaving the device reachable) -- still true, and still a
            # real, live-verified mitigation (7/56 attempts got through
            # under a 2/sec hashlimit). But this lab's brute_force traffic
            # always comes from one fixed, identifiable attacker host, so
            # BLOCK_SOURCE does strictly better with the same "legitimate
            # access preserved" property: 0/N attempts get through, not
            # 7/56, and every OTHER source stays completely unaffected,
            # not just rate-limited. This is not a general replacement for
            # THROTTLE -- a real distributed/botnet-driven brute force has
            # no single source to block, which is exactly the case
            # THROTTLE (still used elsewhere in this registry) covers. The
            # Stackelberg payoff table below independently agrees.
            preferred_action=DefenseAction.BLOCK_SOURCE,
            action_score_min=0.65,
            action_confidence_min=0.65,
            intention="contain_malicious_activity",
            ppo_example_features={"packets_per_second": 6.0, "unique_destination_ports": 1},
            ppo_threat_score=0.75,
            ppo_confidence=0.75,
        ),
        "exfiltration": AttackScenario(
            key="exfiltration",
            label="Data exfiltration",
            attack_type="data_exfiltration",
            observed_threat_key="DATA_EXFILTRATION",
            build_detector=RuleBasedExfiltrationDetector,
            generate_traffic=lambda net: traffic.generate_exfiltration_mininet_traffic(net, duration_seconds=5),
            capture_packet_limit=30,
            capture_duration_seconds=5.0,
            capture_completion_timeout=6.0,
            # Once data is actively leaving, deception offers nothing --
            # the real device is already compromised, so redirecting to a
            # decoy doesn't stop the leak. ISOLATE is the sensible default,
            # and the Stackelberg payoff table below independently agrees.
            preferred_action=DefenseAction.ISOLATE,
            action_score_min=0.7,
            action_confidence_min=0.7,
            intention="contain_malicious_activity",
            ppo_example_features={"packets_per_second": 1.0, "unique_destination_ports": 1},
            ppo_threat_score=0.85,
            ppo_confidence=0.8,
        ),
        "exploit": AttackScenario(
            key="exploit",
            label="Exploit payload injection",
            attack_type="exploit_payload_injection",
            observed_threat_key="EXPLOIT_PAYLOAD_INJECTION",
            build_detector=RuleBasedExploitDetector,
            generate_traffic=lambda net: traffic.generate_exploit_mininet_traffic(net, duration_seconds=4),
            capture_packet_limit=20,
            capture_duration_seconds=4.0,
            capture_completion_timeout=5.0,
            # DECOY's second scenario: unlike reconnaissance's decoy (which
            # only observes a scan in progress), redirecting this traffic
            # captures the actual oversized/malformed payload for analysis
            # while the real device never processes it -- and unlike
            # brute-force/exfiltration/dos, containing it outright (ISOLATE)
            # forfeits that intelligence for what is, at this point, still
            # an unconfirmed single-shot attempt rather than a sustained,
            # already-proven attack. The Stackelberg payoff table below
            # independently arrives at the same choice.
            preferred_action=DefenseAction.DECOY,
            action_score_min=0.7,
            action_confidence_min=0.7,
            intention="gather_attacker_intelligence_when_appropriate",
            ppo_example_features={"packets_per_second": 1.5, "unique_destination_ports": 1},
            ppo_threat_score=0.8,
            ppo_confidence=0.78,
        ),
        "syn_flood": AttackScenario(
            key="syn_flood",
            label="TCP SYN flood",
            attack_type="tcp_syn_flood",
            observed_threat_key="TCP_SYN_FLOOD",
            build_detector=RuleBasedSynFloodDetector,
            generate_traffic=lambda net: traffic.generate_syn_flood_mininet_traffic(net, duration_seconds=14),
            capture_packet_limit=400,
            capture_duration_seconds=14.0,
            capture_completion_timeout=16.0,
            # A resource-exhaustion flood, same reasoning as DOS_FLOOD:
            # full containment is the decisive response, and the
            # Stackelberg payoff table independently agrees.
            preferred_action=DefenseAction.ISOLATE,
            action_score_min=0.7,
            action_confidence_min=0.7,
            intention="contain_malicious_activity",
            ppo_example_features={"packets_per_second": 17.0, "unique_destination_ports": 1},
            ppo_threat_score=0.88,
            ppo_confidence=0.85,
        ),
        "icmp_flood": AttackScenario(
            key="icmp_flood",
            label="ICMP ping flood",
            attack_type="icmp_ping_flood",
            observed_threat_key="ICMP_PING_FLOOD",
            build_detector=RuleBasedIcmpFloodDetector,
            generate_traffic=lambda net: traffic.generate_icmp_flood_mininet_traffic(net, duration_seconds=4),
            # A real 40-count ping produces ~80 wire packets (echo +
            # reply, both captured); a live run at the old limit of 60
            # truncated the capture mid-flood.
            capture_packet_limit=110,
            capture_duration_seconds=4.0,
            capture_completion_timeout=6.0,
            # Rate-limiting directly defeats a ping flood's mechanism
            # while leaving the device reachable -- the same reasoning
            # BRUTE_FORCE's own original THROTTLE choice already
            # establishes, and the Stackelberg payoff table independently
            # agrees. (throttle()'s iptables rule was, until fixed this
            # pass, hardcoded to TCP SYNs -- meaning this attack's own
            # THROTTLE response reported "success" while never matching a
            # single one of its real ICMP packets. throttle() is now
            # protocol-aware; this is the one registered attack that fix
            # actually changes the live behavior of.)
            preferred_action=DefenseAction.THROTTLE,
            action_score_min=0.65,
            action_confidence_min=0.65,
            intention="minimize_unnecessary_disruption",
            ppo_example_features={"packets_per_second": 10.0, "unique_destination_ports": 0},
            ppo_threat_score=0.82,
            ppo_confidence=0.8,
        ),
        "slow_loris": AttackScenario(
            key="slow_loris",
            label="Slowloris connection exhaustion",
            attack_type="slow_loris_exhaustion",
            observed_threat_key="SLOW_LORIS_EXHAUSTION",
            build_detector=RuleBasedSlowLorisDetector,
            generate_traffic=lambda net: traffic.generate_slow_loris_mininet_traffic(net, duration_seconds=25),
            # 28 connections each producing a handshake, one data packet,
            # and a teardown (both directions) comfortably exceeds 100 --
            # a live run at that old limit truncated the capture well
            # before enough distinct source ports had connected.
            capture_packet_limit=400,
            capture_duration_seconds=25.0,
            capture_completion_timeout=27.0,
            # Rate-limiting new connection attempts directly defeats this
            # attack's mechanism (it needs to keep opening connections
            # faster than they're released) while legitimate traffic
            # still gets through -- the Stackelberg payoff table
            # independently agrees.
            preferred_action=DefenseAction.THROTTLE,
            action_score_min=0.65,
            action_confidence_min=0.65,
            intention="minimize_unnecessary_disruption",
            ppo_example_features={"packets_per_second": 2.0, "unique_destination_ports": 1},
            ppo_threat_score=0.78,
            ppo_confidence=0.75,
        ),
        "dns_amplification": AttackScenario(
            key="dns_amplification",
            label="DNS amplification / reflection",
            attack_type="dns_amplification",
            observed_threat_key="DNS_AMPLIFICATION",
            build_detector=RuleBasedDnsAmplificationDetector,
            generate_traffic=lambda net: traffic.generate_dns_amplification_mininet_traffic(net, duration_seconds=9),
            capture_packet_limit=200,
            capture_duration_seconds=9.0,
            capture_completion_timeout=11.0,
            # Originally ISOLATE, mirroring DOS_FLOOD's own full-
            # containment reasoning -- but this attack's real mechanism is
            # bulk *byte volume* from the reflector/attacker's own egress
            # (~570-byte UDP responses sent rapidly), not a raw packet-
            # count flood, and unlike a SYN flood a byte-rate cap actually
            # bites here. BANDWIDTH_CAP constrains the attack at its real
            # source instead of taking the target fully offline -- the
            # target stays reachable to legitimate traffic throughout,
            # something full ISOLATE can't offer. The Stackelberg payoff
            # table below independently agrees.
            preferred_action=DefenseAction.BANDWIDTH_CAP,
            action_score_min=0.7,
            action_confidence_min=0.7,
            intention="contain_malicious_activity",
            ppo_example_features={"packets_per_second": 6.5, "unique_destination_ports": 1},
            ppo_threat_score=0.87,
            ppo_confidence=0.82,
        ),
        "dns_tunneling": AttackScenario(
            key="dns_tunneling",
            label="DNS tunneling (covert-channel exfiltration)",
            attack_type="dns_tunneling_exfiltration",
            observed_threat_key="DNS_TUNNELING_EXFILTRATION",
            build_detector=RuleBasedDnsTunnelingDetector,
            generate_traffic=lambda net: traffic.generate_dns_tunneling_mininet_traffic(net, duration_seconds=15),
            capture_packet_limit=150,
            capture_duration_seconds=15.0,
            capture_completion_timeout=17.0,
            # A genuinely different exfiltration mechanism from
            # DATA_EXFILTRATION's bulk-transfer signature -- unconfirmed
            # until the encoded queries are actually inspected, so
            # redirecting to a decoy captures real intelligence on what's
            # being leaked while the covert channel never reaches its
            # real destination. The Stackelberg payoff table
            # independently agrees.
            preferred_action=DefenseAction.DECOY,
            action_score_min=0.65,
            action_confidence_min=0.6,
            intention="gather_attacker_intelligence_when_appropriate",
            ppo_example_features={"packets_per_second": 2.0, "unique_destination_ports": 1},
            ppo_threat_score=0.8,
            ppo_confidence=0.72,
        ),
        "mqtt_flood": AttackScenario(
            key="mqtt_flood",
            label="MQTT message flood",
            attack_type="mqtt_message_flood",
            observed_threat_key="MQTT_MESSAGE_FLOOD",
            build_detector=RuleBasedMqttFloodDetector,
            generate_traffic=lambda net: traffic.generate_mqtt_flood_mininet_traffic(net, duration_seconds=110),
            capture_packet_limit=120,
            capture_duration_seconds=110.0,
            capture_completion_timeout=112.0,
            # An IoT-protocol-specific flood of otherwise-legitimate
            # messages -- rate-limiting the publish rate defeats the
            # attack while the broker keeps serving real clients, the
            # same reasoning BRUTE_FORCE's own THROTTLE choice
            # establishes. The Stackelberg payoff table independently
            # agrees.
            preferred_action=DefenseAction.THROTTLE,
            action_score_min=0.6,
            action_confidence_min=0.6,
            intention="minimize_unnecessary_disruption",
            ppo_example_features={"packets_per_second": 0.85, "unique_destination_ports": 1},
            ppo_threat_score=0.75,
            ppo_confidence=0.72,
        ),
        "firmware_tampering": AttackScenario(
            key="firmware_tampering",
            label="Firmware / configuration tampering",
            attack_type="firmware_tampering",
            observed_threat_key="FIRMWARE_TAMPERING",
            build_detector=RuleBasedFirmwareTamperingDetector,
            generate_traffic=lambda net: traffic.generate_firmware_tampering_mininet_traffic(net, duration_seconds=18),
            capture_packet_limit=150,
            capture_duration_seconds=18.0,
            capture_completion_timeout=20.0,
            # Originally ISOLATE, mirroring DATA_EXFILTRATION's own
            # reasoning -- still true that deception offers nothing once
            # tampering is underway. But unlike a data leak (where full
            # severance has no downside once the data's gone), a tampered
            # device is one you actively want to *remediate*, and full
            # ISOLATE cuts off the very path a corrective push would need.
            # QUARANTINE keeps the device reachable to the network's other
            # known-legitimate peers under a default-deny policy while
            # cutting it off from the attacker specifically -- contained,
            # but not unreachable for recovery. The Stackelberg payoff
            # table below independently agrees.
            preferred_action=DefenseAction.QUARANTINE,
            action_score_min=0.7,
            action_confidence_min=0.7,
            intention="contain_malicious_activity",
            ppo_example_features={"packets_per_second": 2.5, "unique_destination_ports": 1},
            ppo_threat_score=0.83,
            ppo_confidence=0.78,
        ),
        "buffer_overflow": AttackScenario(
            key="buffer_overflow",
            label="Buffer-overflow / fuzzing probe",
            attack_type="buffer_overflow_probe",
            observed_threat_key="BUFFER_OVERFLOW_PROBE",
            build_detector=RuleBasedBufferOverflowDetector,
            generate_traffic=lambda net: traffic.generate_buffer_overflow_mininet_traffic(net, duration_seconds=40),
            capture_packet_limit=100,
            # 40s, not a shorter window: see generate_buffer_overflow_
            # mininet_traffic's own docstring for why this attack's real
            # rate must stay below 1.0/s on *both* the payload flow and
            # its paired TCP-ACK flow to avoid either being misclassified
            # by an earlier-registered detector.
            capture_duration_seconds=40.0,
            capture_completion_timeout=42.0,
            # Originally ISOLATE -- still true that this sustained,
            # unambiguous campaign warrants full containment over
            # deception. But unlike a flood or a scan, this attack's
            # entire campaign runs over ONE persistent TCP connection (see
            # generate_buffer_overflow_mininet_traffic's own docstring),
            # so it is this registry's one genuinely session-oriented
            # attack: RESET_SESSIONS kills exactly that connection outright
            # -- more surgical than taking the whole interface down, and
            # with no standing rule left behind afterward. The Stackelberg
            # payoff table below independently agrees.
            preferred_action=DefenseAction.RESET_SESSIONS,
            action_score_min=0.7,
            action_confidence_min=0.7,
            intention="contain_malicious_activity",
            ppo_example_features={"packets_per_second": 0.8, "unique_destination_ports": 1},
            ppo_threat_score=0.86,
            ppo_confidence=0.8,
        ),
        "replay_attack": AttackScenario(
            key="replay_attack",
            label="Credential / command replay",
            attack_type="credential_replay",
            observed_threat_key="CREDENTIAL_REPLAY",
            build_detector=RuleBasedReplayAttackDetector,
            generate_traffic=lambda net: traffic.generate_replay_attack_mininet_traffic(net, duration_seconds=20),
            capture_packet_limit=60,
            capture_duration_seconds=20.0,
            capture_completion_timeout=22.0,
            # Originally THROTTLE -- but this attack's traffic is UDP, and
            # THROTTLE's iptables rule was, until fixed this pass, TCP-only
            # (`-p tcp --syn`), meaning it never actually matched a single
            # packet of this attack's real traffic despite reporting
            # "success". Now that throttle() is protocol-aware this would
            # work, but BLOCK_SOURCE is still the better fit on its own
            # merits, the same reasoning BRUTE_FORCE's own reassignment
            # establishes: this lab's replay traffic comes from one fixed,
            # identifiable source, so blocking it outright beats merely
            # slowing it down, with the same "other sources unaffected"
            # property. The Stackelberg payoff table below independently
            # agrees.
            preferred_action=DefenseAction.BLOCK_SOURCE,
            action_score_min=0.6,
            action_confidence_min=0.55,
            intention="minimize_unnecessary_disruption",
            ppo_example_features={"packets_per_second": 0.85, "unique_destination_ports": 1},
            ppo_threat_score=0.72,
            ppo_confidence=0.68,
        ),
        "rogue_beacon": AttackScenario(
            key="rogue_beacon",
            label="Rogue configuration beacon",
            attack_type="rogue_config_beacon",
            observed_threat_key="ROGUE_CONFIG_BEACON",
            build_detector=RuleBasedRogueBeaconDetector,
            generate_traffic=lambda net: traffic.generate_rogue_beacon_mininet_traffic(net, duration_seconds=10),
            capture_packet_limit=200,
            capture_duration_seconds=10.0,
            capture_completion_timeout=12.0,
            # Originally ALERT -- still the lowest-confidence signature of
            # any registered attack (a frequent-but-small outbound pattern
            # that could still be legitimate), so still the least
            # disruptive category of response, unlike FIRMWARE_TAMPERING's
            # larger, less frequent, more clearly hostile pushes. But a
            # single log line is a weaker response to genuine uncertainty
            # than actually gathering evidence: FORENSIC_CAPTURE preserves
            # a real pcap plus connection/neighbor state for later review
            # -- still zero disruption to the device, strictly more useful
            # than ALERT if this ever needs a second look. The Stackelberg
            # payoff table below independently agrees.
            preferred_action=DefenseAction.FORENSIC_CAPTURE,
            action_score_min=0.5,
            action_confidence_min=0.5,
            intention="minimize_unnecessary_disruption",
            ppo_example_features={"packets_per_second": 7.0, "unique_destination_ports": 1},
            ppo_threat_score=0.6,
            ppo_confidence=0.55,
        ),
    }


ATTACK_SCENARIOS: dict[str, AttackScenario] = _build_registry()
