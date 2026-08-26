from iot_defense.agents.decision_agent import DecisionAgent
from iot_defense.defense.context import build_security_context
from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.policy import DefensePolicy, RuleBasedDefensePolicy
from iot_defense.detection.threat_event import ThreatEvent


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


def test_low_risk_suspicious_maps_to_alert():
    policy = RuleBasedDefensePolicy(
        recon_decoy_score_min=0.8,
        recon_decoy_confidence_min=0.8,
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
