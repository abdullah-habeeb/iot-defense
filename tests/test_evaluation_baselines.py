from iot_defense.defense.context import build_security_context
from iot_defense.defense.decision import DefenseAction
from iot_defense.detection.threat_event import ThreatEvent
from iot_defense.evaluation.baselines import AlwaysAllowBaseline, NaiveBlockAllBaseline


def _event(*, attack_type: str, threat_score: float, confidence: float) -> ThreatEvent:
    return ThreatEvent.from_result(
        source_ip="10.0.0.100",
        destination_ip="10.0.0.10",
        attack_type=attack_type,
        threat_score=threat_score,
        confidence=confidence,
        detection_reason="test",
        features={"protocol": "TCP", "packet_count": 3},
        detector_name="unit-test",
    )


def test_always_allow_never_intervenes():
    baseline = AlwaysAllowBaseline()
    normal = baseline.decide(build_security_context(_event(attack_type="normal", threat_score=0.05, confidence=0.9)))
    attack = baseline.decide(
        build_security_context(_event(attack_type="dos_flood", threat_score=0.92, confidence=0.9))
    )
    assert normal.action == DefenseAction.ALLOW
    assert attack.action == DefenseAction.ALLOW


def test_naive_block_all_allows_normal_and_isolates_every_attack():
    baseline = NaiveBlockAllBaseline()
    normal = baseline.decide(build_security_context(_event(attack_type="normal", threat_score=0.05, confidence=0.9)))
    assert normal.action == DefenseAction.ALLOW

    for attack_type in [
        "reconnaissance_port_scan",
        "dos_flood",
        "brute_force",
        "data_exfiltration",
        "exploit_payload_injection",
    ]:
        decision = baseline.decide(
            build_security_context(_event(attack_type=attack_type, threat_score=0.8, confidence=0.8))
        )
        assert decision.action == DefenseAction.ISOLATE, attack_type


def test_naive_block_all_does_not_differentiate_by_attack_type():
    """The whole point of this baseline: it gives the identical response
    to every attack type, unlike our own registry-driven preferred_action
    per attack -- this is the exact property the 3-policy comparison is
    meant to show adds value."""
    baseline = NaiveBlockAllBaseline()
    actions = {
        baseline.decide(
            build_security_context(_event(attack_type=attack_type, threat_score=0.8, confidence=0.8))
        ).action
        for attack_type in ["reconnaissance_port_scan", "brute_force", "exploit_payload_injection"]
    }
    assert actions == {DefenseAction.ISOLATE}
