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
        RuleBasedDosDetector,
        RuleBasedExfiltrationDetector,
        RuleBasedExploitDetector,
        RuleBasedReconDetector,
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
            # Rate-limiting the repeated attempts defeats a brute-force
            # attack's actual mechanism (it needs a high guess rate to
            # succeed) while leaving the device reachable for a legitimate
            # user -- strictly better than fully isolating it, which
            # achieves the same containment at the cost of also blocking
            # legitimate access. The Stackelberg payoff table below
            # independently arrives at the same choice.
            preferred_action=DefenseAction.THROTTLE,
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
    }


ATTACK_SCENARIOS: dict[str, AttackScenario] = _build_registry()
