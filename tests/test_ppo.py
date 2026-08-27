import numpy as np

from iot_defense.defense.context import build_security_context
from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.policy import RuleBasedDefensePolicy
from iot_defense.defense.ppo_env import (
    ACTION_TO_INDEX,
    DefenseDecisionEnv,
    SecurityContextEncoder,
    context_for_scenario,
)
from iot_defense.defense.ppo_policy import PPODefensePolicy
from iot_defense.detection.threat_event import ThreatEvent


def test_context_encoding_is_normalized_and_deterministic():
    context = context_for_scenario("reconnaissance_port_scan")
    encoder = SecurityContextEncoder()
    first = encoder.encode(context)
    second = encoder.encode(context)
    assert first.shape == (16,)
    assert first.dtype == np.float32
    assert np.array_equal(first, second)
    assert np.all(first >= 0.0)
    assert np.all(first <= 1.0)


def test_action_mapping_matches_defense_actions():
    assert ACTION_TO_INDEX == {
        DefenseAction.ALLOW: 0,
        DefenseAction.ALERT: 1,
        DefenseAction.ISOLATE: 2,
        DefenseAction.DECOY: 3,
    }


def test_environment_reset_step_reward_and_termination():
    environment = DefenseDecisionEnv(episode_length=2)
    observation, info = environment.reset(seed=7)
    assert observation.shape == (16,)
    assert info["scenario"] == "normal"

    next_observation, reward, terminated, truncated, step_info = environment.step(ACTION_TO_INDEX[DefenseAction.ALLOW])
    assert next_observation.shape == (16,)
    assert reward == 2.5
    assert terminated is False
    assert truncated is False
    assert step_info["scenario"] == "normal"

    _, _, terminated, _, _ = environment.step(ACTION_TO_INDEX[DefenseAction.DECOY])
    assert terminated is True


def test_reward_model_rewards_containment_and_penalizes_false_positive():
    environment = DefenseDecisionEnv()
    normal = context_for_scenario("normal")
    recon = context_for_scenario("reconnaissance_port_scan")
    allow_reward, _ = environment.calculate_reward(normal, DefenseAction.ALLOW)
    isolate_reward, _ = environment.calculate_reward(recon, DefenseAction.ISOLATE)
    false_positive_reward, _ = environment.calculate_reward(normal, DefenseAction.ISOLATE)
    assert allow_reward > false_positive_reward
    assert isolate_reward > false_positive_reward


def test_ppo_policy_fallback_is_explicit_when_model_is_absent(tmp_path):
    fallback = RuleBasedDefensePolicy()
    policy = PPODefensePolicy(tmp_path / "missing-model", fallback=fallback)
    event = ThreatEvent.from_result(
        source_ip="10.0.0.100",
        destination_ip="10.0.0.10",
        attack_type="normal",
        threat_score=0.05,
        confidence=0.9,
        detection_reason="test",
        features={},
    )
    decision = policy.decide(build_security_context(event))
    assert decision.action == DefenseAction.ALLOW
    assert decision.context["ppo_fallback"] == "RuleBasedDefensePolicy"


def test_ppo_policy_rejects_missing_model_without_fallback(tmp_path):
    try:
        PPODefensePolicy(tmp_path / "missing-model")
    except FileNotFoundError as error:
        assert "Train it first" in str(error)
    else:
        raise AssertionError("Missing PPO model should fail without an explicit fallback")


def test_ppo_action_output_is_valid():
    class FakeModel:
        def predict(self, observation, deterministic=True):
            assert observation.shape == (16,)
            return ACTION_TO_INDEX[DefenseAction.DECOY], None

    policy = PPODefensePolicy("unused", fallback=RuleBasedDefensePolicy())
    policy.model = FakeModel()
    policy.fallback = None
    decision = policy.decide(context_for_scenario("reconnaissance_port_scan"))
    assert decision.action == DefenseAction.DECOY