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
first one whose detector fires. Today's two attacks have mutually exclusive
rule signatures (a flood needs very few destination ports, a scan needs
many), so order doesn't change what gets detected -- but a future attack
whose signature could overlap with an existing one should still be
registered with that in mind, since registration order is the tiebreak.

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
    """(net) -> raw traffic-generator result. Always targets the sensor at
    10.0.0.10, matching every existing and planned attack's target."""

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
    from iot_defense.detection.detector import RuleBasedDosDetector, RuleBasedReconDetector
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
    }


ATTACK_SCENARIOS: dict[str, AttackScenario] = _build_registry()
