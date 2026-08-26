from iot_defense.agents.decision_agent import DecisionAgent
from iot_defense.defense.policy import DefensePolicy


def test_decision_agent_returns_isolate_for_suspicious_activity():
    agent = DecisionAgent(default_action="allow")
    decision = agent.decide({"suspicious": True})
    assert decision == "isolate"


def test_defense_policy_accepts_known_actions():
    policy = DefensePolicy(default_action="allow")
    assert policy.is_allowed("allow") is True
    assert policy.is_allowed("decoy") is True
    assert policy.is_allowed("unknown") is False
