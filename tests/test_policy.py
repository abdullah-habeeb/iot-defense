from iot_defense.agents.decision_agent import DecisionAgent
from iot_defense.defense.context import build_security_context
from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.policy import DefensePolicy, RuleBasedDefensePolicy, _load_decision_policy_config
from iot_defense.detection.threat_event import ThreatEvent


def test_load_decision_policy_config_actually_finds_the_yaml_file():
    """Regression test for a real bug: the config path was resolved one
    directory too shallow (parents[2], landing in src/ instead of the repo
    root), so config_path.exists() was always False and this function
    always silently returned {} -- editing config/policies.yaml's
    policy.decision section had no effect at all. Invisible in practice
    only because every caller's hardcoded fallback happened to be kept in
    sync with the YAML by hand; this asserts the file is genuinely found
    and its real, non-default values come through."""
    config = _load_decision_policy_config()
    assert config, "config/policies.yaml's policy.decision section must actually load, not silently return {}"
    assert config["recon_decoy_score_min"] == 0.8
    assert config["brute_force_score_min"] == 0.65


def _event(
    *,
    attack_type: str,
    threat_score: float,
    confidence: float,
    source_ip: str = "10.0.0.100",
    destination_ip: str = "10.0.0.10",
) -> ThreatEvent:
    return ThreatEvent.from_result(
        source_ip=source_ip,
        destination_ip=destination_ip,
        attack_type=attack_type,
        threat_score=threat_score,
        confidence=confidence,
        detection_reason="test",
        features={"protocol": "TCP", "packet_count": 3},
        detector_name="unit-test",
    )


def test_context_creation_builds_bdi_state():
    prior_event = _event(attack_type="normal", threat_score=0.05, confidence=0.9)
    current_event = _event(
        attack_type="reconnaissance_port_scan",
        threat_score=0.9,
        confidence=0.88,
    )

    context = build_security_context(
        current_event,
        previous_events=[prior_event],
        device_criticality="high",
    )

    assert context.beliefs.threat_type == "reconnaissance_port_scan"
    assert context.beliefs.source_device == "10.0.0.100"
    assert context.beliefs.destination_device == "10.0.0.10"
    assert context.beliefs.device_criticality == "high"
    assert len(context.beliefs.previous_relevant_events) == 1
    assert context.desires.protect_legitimate_iot_service is True
    assert context.intention == "gather_attacker_intelligence_when_appropriate"


def test_normal_event_maps_to_allow():
    agent = DecisionAgent(policy=RuleBasedDefensePolicy())
    decision = agent.decide(_event(attack_type="normal", threat_score=0.05, confidence=0.9))
    assert decision.action == DefenseAction.ALLOW


def test_reconnaissance_maps_to_decoy():
    agent = DecisionAgent(policy=RuleBasedDefensePolicy())
    decision = agent.decide(
        _event(
            attack_type="reconnaissance_port_scan",
            threat_score=0.9,
            confidence=0.88,
        )
    )
    assert decision.action == DefenseAction.DECOY


def test_severe_threat_maps_to_isolate():
    policy = RuleBasedDefensePolicy(
        severe_threat_score_min=0.95,
        severe_confidence_min=0.95,
    )
    agent = DecisionAgent(policy=policy)
    decision = agent.decide(
        _event(
            attack_type="reconnaissance_port_scan",
            threat_score=0.99,
            confidence=0.99,
        )
    )
    assert decision.action == DefenseAction.ISOLATE


def test_dos_flood_maps_to_isolate():
    """Unlike reconnaissance (decoy), a flood should trigger immediate
    containment -- there's no useful deception target for a flood."""
    agent = DecisionAgent(policy=RuleBasedDefensePolicy())
    decision = agent.decide(
        _event(
            attack_type="dos_flood",
            threat_score=0.92,
            confidence=0.9,
        )
    )
    assert decision.action == DefenseAction.ISOLATE


def test_low_risk_suspicious_maps_to_alert():
    policy = RuleBasedDefensePolicy(
        severe_threat_score_min=0.95,
        severe_confidence_min=0.95,
    )
    agent = DecisionAgent(policy=policy)
    decision = agent.decide(
        _event(
            attack_type="reconnaissance_port_scan",
            threat_score=0.45,
            confidence=0.6,
        )
    )
    assert decision.action == DefenseAction.ALERT


def test_decision_reason_is_explainable():
    agent = DecisionAgent(policy=RuleBasedDefensePolicy())
    decision = agent.decide(
        _event(
            attack_type="reconnaissance_port_scan",
            threat_score=0.9,
            confidence=0.88,
        )
    )
    assert "Reconnaissance" in decision.reason


class _TestAllowPolicy(DefensePolicy):
    def decide(self, context):
        return DefenseDecision.create(
            action=DefenseAction.ALLOW,
            target_ip=context.beliefs.destination_device,
            source_ip=context.beliefs.source_device,
            reason="test override policy",
            confidence=context.beliefs.confidence,
            threat_score=context.beliefs.threat_score,
            policy_name=self.name,
            context=context.to_dict(),
        )


def test_policy_replacement_via_interface():
    agent = DecisionAgent(policy=_TestAllowPolicy())
    decision = agent.decide(
        _event(
            attack_type="reconnaissance_port_scan",
            threat_score=0.9,
            confidence=0.88,
        )
    )
    assert decision.action == DefenseAction.ALLOW
    assert decision.policy_name == "_TestAllowPolicy"


def test_defense_decision_serialization():
    context = build_security_context(
        _event(attack_type="normal", threat_score=0.05, confidence=0.9)
    )
    decision = DefenseDecision.create(
        action=DefenseAction.ALERT,
        target_ip="10.0.0.10",
        source_ip="10.0.0.100",
        reason="unit test serialization",
        confidence=0.8,
        threat_score=0.3,
        policy_name="UnitPolicy",
        context=context.to_dict(),
    )

    serialized = decision.to_dict()
    assert serialized["action"] == "ALERT"
    assert serialized["target_ip"] == "10.0.0.10"
    assert serialized["context"]["beliefs"]["threat_type"] == "normal"


class TestStackelbergDefensePolicyUnknownThreatType:
    """Regression test for a real inconsistency found by a system review:
    RuleBasedDefensePolicy.decide() gracefully falls back to ALERT for an
    attack_type it doesn't recognize, but StackelbergDefensePolicy.decide()
    used to raise a bare ValueError from StackelbergGame.solve() for the
    same case -- unreachable through the real detection pipeline today,
    but a real asymmetry between the two policies' own resilience."""

    def test_unrecognized_threat_type_falls_back_to_alert_not_an_exception(self):
        from iot_defense.defense.policy import StackelbergDefensePolicy

        threat_event = ThreatEvent.from_result(
            source_ip="10.0.0.100", destination_ip="10.0.0.10",
            attack_type="totally_unregistered_attack_type",
            threat_score=0.5, confidence=0.5, detection_reason="test fixture",
            features={}, detector_name="test",
        )
        context = build_security_context(threat_event, device_criticality="high")

        decision = StackelbergDefensePolicy().decide(context)

        assert decision.action == DefenseAction.ALERT
        assert "TOTALLY_UNREGISTERED_ATTACK_TYPE" in decision.reason.upper()

    def test_recognized_threat_type_still_solves_normally(self):
        """Confirms the new pre-check doesn't accidentally short-circuit
        real, valid threat types."""
        from iot_defense.defense.policy import StackelbergDefensePolicy
        from iot_defense.attacks.registry import ATTACK_SCENARIOS

        dos_scenario = ATTACK_SCENARIOS["dos"]
        threat_event = ThreatEvent.from_result(
            source_ip="10.0.0.100", destination_ip="10.0.0.10",
            attack_type=dos_scenario.attack_type,
            threat_score=0.92, confidence=0.9, detection_reason="test fixture",
            features=dict(dos_scenario.ppo_example_features), detector_name="test",
        )
        context = build_security_context(threat_event, device_criticality="high")

        decision = StackelbergDefensePolicy().decide(context)

        assert decision.action == dos_scenario.preferred_action
