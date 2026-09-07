"""Generic tests that run once per registered attack, proving the Phase 0
registry refactor actually made the system generic over attack type --
not just correct for the two attacks that happen to be registered today.
"""

from __future__ import annotations

import pytest

from iot_defense.attacks.registry import ATTACK_SCENARIOS, AttackScenario
from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.policy import RuleBasedDefensePolicy
from iot_defense.defense.ppo_env import (
    INTENTIONS,
    OBSERVATION_SIZE,
    SecurityContextEncoder,
    TRAINING_SCENARIOS,
    context_for_scenario,
)
from iot_defense.defense.stackelberg import StackelbergGame, _observed_threat_types
from iot_defense.detection.detector import UnifiedRuleBasedDetector


@pytest.fixture(params=list(ATTACK_SCENARIOS.keys()))
def attack_key(request) -> str:
    return request.param


@pytest.fixture
def scenario(attack_key: str) -> AttackScenario:
    return ATTACK_SCENARIOS[attack_key]


def test_registry_has_at_least_one_attack():
    assert len(ATTACK_SCENARIOS) >= 1


def test_every_scenario_has_distinct_attack_type_and_observed_threat_key():
    scenarios = list(ATTACK_SCENARIOS.values())
    assert len({s.attack_type for s in scenarios}) == len(scenarios)
    assert len({s.observed_threat_key for s in scenarios}) == len(scenarios)


# Detector-triggering feature overrides for scenarios whose signature needs
# more than "packet_count=200 + ppo_example_features" to trip -- e.g.
# exfiltration's detector also requires a *bounded* packet_count and a
# large average_packet_size, neither of which ppo_example_features carries
# (that field is a template for PPO's simpler packet-rate/port-diversity
# encoding, not a full detector-triggering feature set). Add an entry here
# for any future attack whose detector inspects additional fields.
DETECTION_FEATURE_OVERRIDES: dict[str, dict[str, float]] = {
    "exfiltration": {"packet_count": 10, "average_packet_size": 1200.0},
}


class TestUnifiedDetectorIsRegistryDriven:
    def test_default_construction_uses_the_full_registry(self):
        detector = UnifiedRuleBasedDetector()
        assert set(detector.detectors.keys()) == set(ATTACK_SCENARIOS.keys())

    def test_each_scenarios_own_detector_flags_its_own_signature(self, scenario: AttackScenario):
        """Build a feature record designed to trip only this attack's rules,
        and confirm the unified detector (with the real, unmodified default
        registry) classifies it as this attack -- not "normal" and not a
        different registered attack."""
        detector = scenario.build_detector()
        features = {
            "source_ip": "10.0.0.100",
            "destination_ip": "10.0.0.10",
            "packet_count": 200,
            **scenario.ppo_example_features,
            **DETECTION_FEATURE_OVERRIDES.get(scenario.key, {}),
        }
        event = detector.detect(features)
        assert event.attack_type == scenario.attack_type


class TestPolicyIsRegistryDriven:
    def test_every_scenario_has_a_configured_action_threshold(self, attack_key: str):
        policy = RuleBasedDefensePolicy()
        assert attack_key in policy.action_thresholds
        score_min, confidence_min = policy.action_thresholds[attack_key]
        assert 0.0 <= score_min <= 1.0
        assert 0.0 <= confidence_min <= 1.0

    def test_preferred_action_is_reachable_through_decide(self, scenario: AttackScenario):
        from iot_defense.defense.context import Beliefs, Desires, SecurityContext

        policy = RuleBasedDefensePolicy()
        score_min, confidence_min = policy.action_thresholds[scenario.key]
        context = SecurityContext(
            beliefs=Beliefs(
                threat_type=scenario.attack_type,
                threat_score=min(score_min + 0.02, 0.94),
                confidence=min(confidence_min + 0.02, 0.94),
                source_device="10.0.0.100",
                destination_device="10.0.0.10",
                observed_features=dict(scenario.ppo_example_features),
            ),
            desires=Desires(),
            intention=scenario.intention,
        )
        decision = policy.decide(context)
        assert decision.action == scenario.preferred_action


class TestStackelbergIsRegistryDriven:
    def test_observed_threat_types_include_every_scenario(self):
        observed = _observed_threat_types()
        assert observed[0] == "NORMAL"
        for scenario_ in ATTACK_SCENARIOS.values():
            assert scenario_.observed_threat_key in observed

    def test_game_solves_for_every_registered_threat(self, scenario: AttackScenario):
        solution = StackelbergGame().solve(scenario.observed_threat_key)
        assert isinstance(solution.selected_action, DefenseAction)


class TestPPOEnvIsRegistryDriven:
    def test_training_scenarios_include_every_attack_type(self):
        training_scenarios = TRAINING_SCENARIOS()
        assert training_scenarios[0] == "normal"
        for scenario_ in ATTACK_SCENARIOS.values():
            assert scenario_.attack_type in training_scenarios

    def test_context_for_scenario_round_trips_every_attack_type(self, scenario: AttackScenario):
        context = context_for_scenario(scenario.attack_type)
        assert context.beliefs.threat_type == scenario.attack_type
        assert context.intention == scenario.intention
        assert context.intention in INTENTIONS

    def test_encoded_observation_matches_declared_size(self, scenario: AttackScenario):
        context = context_for_scenario(scenario.attack_type)
        encoded = SecurityContextEncoder().encode(context)
        assert encoded.shape == (OBSERVATION_SIZE(),)

    def test_every_scenarios_encoding_is_distinct(self):
        """Two different attacks must never collapse to the same one-hot
        encoding -- otherwise PPO cannot tell them apart."""
        encoder = SecurityContextEncoder()
        encodings = [
            encoder.encode(context_for_scenario(s.attack_type)).tobytes() for s in ATTACK_SCENARIOS.values()
        ]
        assert len(set(encodings)) == len(encodings)
