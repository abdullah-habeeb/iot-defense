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
    # 442.0 is the real, live-measured average_packet_size documented in
    # README.md's own known-limitations section (framing overhead means
    # this is NOT the same as the generator's raw payload byte count --
    # see that section for the full real-vs-window margin analysis). Was
    # 350.0, a value that still landed inside this detector's own
    # [250, 550) window but didn't match the real captured traffic --
    # found by a system review.
    "exploit": {"packet_count": 4, "average_packet_size": 442.0},
    "syn_flood": {"protocol": "TCP", "tcp_syn_count": 15, "tcp_ack_count": 0},
    "icmp_flood": {"protocol": "ICMP", "icmp_packet_count": 30, "average_packet_size": 220.0},
    "slow_loris": {"protocol": "TCP", "unique_source_ports": 20, "tcp_ack_count": 20, "average_packet_size": 225.0},
    "dns_amplification": {"protocol": "UDP", "average_packet_size": 570.0},
    "dns_tunneling": {"protocol": "UDP", "average_packet_size": 220.0},
    "mqtt_flood": {"protocol": "TCP", "tcp_ack_count": 20, "average_packet_size": 80.0},
    "firmware_tampering": {"protocol": "UDP", "average_packet_size": 570.0},
    # 675.6 is a real, live-measured average_packet_size from a direct
    # capture of generate_buffer_overflow_mininet_traffic (was 570.0, a
    # value that still landed inside this detector's own [550, 700)
    # window but didn't match real captured traffic -- found by a system
    # review). The real capture actually produces two flows -- one
    # ~675-byte (the oversized-payload data, what this detector keys on)
    # and one ~66-byte (handshake/ACK-only packets, below this
    # detector's own 550 floor and therefore never classified as
    # buffer_overflow) -- this override is the former.
    "buffer_overflow": {"protocol": "TCP", "average_packet_size": 675.6},
    "replay_attack": {"protocol": "UDP", "average_packet_size": 100.0},
    "rogue_beacon": {"protocol": "UDP", "average_packet_size": 220.0},
    # RuleBasedC2BeaconDetector's own primary signal, inter_arrival_cv,
    # isn't in ppo_example_features at all (a synthetic PPO training
    # template, not a real captured timing measurement) -- must be
    # overridden explicitly, or this scenario's own generic feature
    # record would default to inter_arrival_cv=999.0 (the "not enough
    # data" sentinel) and never trip its own detector.
    "c2_beacon": {"protocol": "UDP", "average_packet_size": 380.0, "inter_arrival_cv": 0.05},
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

    def test_each_scenarios_own_signature_survives_the_full_unified_sweep(self, scenario: AttackScenario):
        """The real regression this whole registry exists to prevent: it is
        not enough for an attack's *own* detector to recognize its own
        signature in isolation (test above) -- UnifiedRuleBasedDetector
        tries every registered detector in registry order and returns the
        *first* one that fires, so an earlier-registered detector whose
        window happens to also cover this signature would silently steal
        it, and this attack's own detector would never even be consulted.
        Every one of the 15 rule-based signatures registered as of this
        test was hand-designed to avoid every other one's numeric window
        (see each detector's own docstring for the specific gap it was
        placed in) -- this is what actually proves those gaps are real
        and disjoint, not just individually self-consistent."""
        detector = UnifiedRuleBasedDetector()
        features = {
            "source_ip": "10.0.0.100",
            "destination_ip": "10.0.0.10",
            "packet_count": 200,
            **scenario.ppo_example_features,
            **DETECTION_FEATURE_OVERRIDES.get(scenario.key, {}),
        }
        event = detector.detect(features)
        assert event.attack_type == scenario.attack_type, (
            f"expected {scenario.key!r}'s own signature to be classified as "
            f"{scenario.attack_type!r} by the full unified sweep, got "
            f"{event.attack_type!r} (detected by {event.detector_name!r}) -- "
            "an earlier-registered detector's window overlaps this one's."
        )


class TestCaptureDurationFieldsStayConsistent:
    """capture_duration_seconds is documentation, not an enforced runtime
    bound (see its own field docstring in registry.py) -- but
    monitoring/monitor.py's watchdog_seconds mechanism relies on
    capture_completion_timeout always being the *larger* of the two, or
    a naive future caller wiring capture_duration_seconds in directly as
    a hard timeout would kill every capture before stop_capture() gets a
    fair chance (confirmed during a system review: every single
    registered attack currently has capture_duration_seconds 1-2 seconds
    *smaller* than capture_completion_timeout). This is the regression
    guard for that relationship."""

    def test_capture_duration_seconds_stays_under_completion_timeout(self, scenario: AttackScenario):
        assert scenario.capture_duration_seconds < scenario.capture_completion_timeout, (
            f"{scenario.key!r}: capture_duration_seconds="
            f"{scenario.capture_duration_seconds} must stay below "
            f"capture_completion_timeout={scenario.capture_completion_timeout}"
        )


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
        # Found by a system review: this used to only assert *a* valid
        # DefenseAction came back, never that it was the *right* one --
        # a tautology that would pass even if a payoff-table edit picked
        # a completely different winner than the registry declares (the
        # exact class of bug the C2_BEACONING payoff fix earlier this
        # session was). This is the real assertion the test name promises.
        assert solution.selected_action == scenario.preferred_action, (
            f'{scenario.key!r}: Stackelberg solved to {solution.selected_action.name}, '
            f'but the registry declares preferred_action={scenario.preferred_action.name}'
        )


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
