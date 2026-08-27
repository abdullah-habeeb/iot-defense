from iot_defense.defense.context import build_security_context
from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.policy import StackelbergDefensePolicy, compare_policies
from iot_defense.defense.stackelberg import StackelbergGame
from iot_defense.detection.threat_event import ThreatEvent


def event(attack_type: str, score: float, confidence: float) -> ThreatEvent:
    return ThreatEvent.from_result(
        source_ip="10.0.0.100",
        destination_ip="10.0.0.10",
        attack_type=attack_type,
        threat_score=score,
        confidence=confidence,
        detection_reason="test event",
        features={"packet_count": 10},
    )


def test_attacker_best_response_uses_maximum_attacker_utility():
    game = StackelbergGame()
    strategy, utility = game.attacker_best_response("RECONNAISSANCE_PORT_SCAN", DefenseAction.ALLOW)
    assert strategy == "CONTINUE"
    assert utility == 8.0


def test_defender_utility_is_loaded_from_payoff_matrix():
    game = StackelbergGame()
    assert game.defender_utility("RECONNAISSANCE_PORT_SCAN", DefenseAction.DECOY, "RETREAT") == 8.0


def test_stackelberg_selection_for_normal_and_reconnaissance():
    policy = StackelbergDefensePolicy()
    normal = policy.decide(build_security_context(event("normal", 0.05, 0.9)))
    recon = policy.decide(build_security_context(event("reconnaissance_port_scan", 0.9, 0.88)))
    assert normal.action == DefenseAction.ALLOW
    assert recon.action == DefenseAction.DECOY
    assert recon.context["stackelberg_reasoning"]["observed_threat"] == "RECONNAISSANCE_PORT_SCAN"
    assert recon.context["stackelberg_reasoning"]["predicted_attacker_strategy"] == "RETREAT"


def test_stackelberg_exposes_all_candidate_evaluations():
    solution = StackelbergGame().solve("RECONNAISSANCE_PORT_SCAN")
    assert len(solution.candidates) == 4
    assert solution.selected_action == DefenseAction.DECOY
    assert solution.selected_defender_utility == 8.0


def test_custom_payoff_matrix_changes_selection():
    payoffs = {
        "NORMAL": {action.value: {"attacker": 0, "defender": 0} for action in DefenseAction},
        "RECONNAISSANCE_PORT_SCAN": {
            action.value: {
                "CONTINUE": {"attacker": 0, "defender": 10 if action == DefenseAction.ISOLATE else 0},
                "RETREAT": {"attacker": 0, "defender": 0},
            }
            for action in DefenseAction
        },
    }
    game = StackelbergGame(payoffs=payoffs)
    assert game.solve("RECONNAISSANCE_PORT_SCAN").selected_action == DefenseAction.ISOLATE


def test_policy_comparison_uses_same_context():
    context = build_security_context(event("reconnaissance_port_scan", 0.9, 0.88))
    comparison = compare_policies(context)
    assert comparison["same_context"] is True
    assert comparison["rule_based_action"] == "DECOY"
    assert comparison["stackelberg_action"] == "DECOY"
    assert comparison["observed_threat"] == "RECONNAISSANCE_PORT_SCAN"
    assert comparison["predicted_attacker_response"] == "RETREAT"
    assert comparison["defender_utility"] == 8.0


def test_defender_utility_uses_the_actual_best_response():
    payoffs = {
        "NORMAL": {
            action.value: {
                "CONTINUE": {"attacker": 0, "defender": 0},
                "RETREAT": {"attacker": 0, "defender": 0},
            }
            for action in DefenseAction
        },
        "RECONNAISSANCE_PORT_SCAN": {
            "ALLOW": {
                "CONTINUE": {"attacker": 9, "defender": -9},
                "RETREAT": {"attacker": 1, "defender": 1},
            },
            "ALERT": {
                "CONTINUE": {"attacker": 2, "defender": 2},
                "RETREAT": {"attacker": 8, "defender": 99},
            },
            "DECOY": {
                "CONTINUE": {"attacker": 1, "defender": 3},
                "RETREAT": {"attacker": -1, "defender": 4},
            },
            "ISOLATE": {
                "CONTINUE": {"attacker": 0, "defender": 2},
                "RETREAT": {"attacker": -1, "defender": 3},
            },
        },
    }
    solution = StackelbergGame(payoffs).solve("RECONNAISSANCE_PORT_SCAN")
    alert = next(candidate for candidate in solution.candidates if candidate.defender_action == DefenseAction.ALERT)
    assert alert.predicted_attacker_strategy == "RETREAT"
    assert alert.attacker_utility == 8
    assert alert.defender_utility == 99
    assert solution.selected_action == DefenseAction.ALERT


def test_observed_threat_is_separate_from_attacker_response():
    decision = StackelbergDefensePolicy().decide(
        build_security_context(event("reconnaissance_port_scan", 0.9, 0.88))
    )
    reasoning = decision.context["stackelberg_reasoning"]
    assert reasoning["observed_threat"] == "RECONNAISSANCE_PORT_SCAN"
    assert reasoning["predicted_attacker_strategy"] in {"CONTINUE", "RETREAT"}
    assert reasoning["observed_threat"] != reasoning["predicted_attacker_strategy"]
