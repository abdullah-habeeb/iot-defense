import ast
import inspect

import gymnasium as gym
import numpy as np
import pytest
from gymnasium import spaces

from iot_defense.defense import ppo_env as ppo_env_module
from iot_defense.defense.context import build_security_context
from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.objective import Objective
from iot_defense.defense.policy import RuleBasedDefensePolicy
from iot_defense.defense.ppo_env import (
    ACTION_TO_INDEX,
    CRITICALITY_LEVELS,
    INTENTIONS,
    OBSERVATION_SIZE,
    TRAINING_SCENARIOS,
    DefenseDecisionEnv,
    SecurityContextEncoder,
    context_for_scenario,
    load_ppo_training_config,
    noisy_context,
)
from iot_defense.defense.ppo_policy import PPODefensePolicy
from iot_defense.detection.threat_event import ThreatEvent
from iot_defense.evaluation.outcome import OutcomeTable
from iot_defense.simulation import train_ppo as train_ppo_module


def test_config_has_the_outcome_environment_settings():
    config = load_ppo_training_config()
    assert config["training_timesteps"] > 0
    assert 0.0 <= config["label_error_rate"] < 1.0
    assert config["reward_scale"] > 0
    assert "reward" not in config, "the preferred_action reward block must be gone"


def test_observation_carries_no_other_policys_output():
    assert OBSERVATION_SIZE() == 6 + len(TRAINING_SCENARIOS()) + len(INTENTIONS)
    assert list(inspect.signature(SecurityContextEncoder.encode).parameters) == ["self", "context"]
    assert list(inspect.signature(PPODefensePolicy.decide).parameters) == ["self", "context"]


@pytest.mark.parametrize("module", [ppo_env_module, train_ppo_module])
def test_ppo_training_code_never_reads_preferred_action(module):
    tree = ast.parse(inspect.getsource(module))
    used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | {
        n.id for n in ast.walk(tree) if isinstance(n, ast.Name)
    }
    assert "preferred_action" not in used


def test_context_encoding_is_normalized_and_deterministic():
    context = context_for_scenario("reconnaissance_port_scan")
    encoder = SecurityContextEncoder()
    first, second = encoder.encode(context), encoder.encode(context)
    assert first.shape == (OBSERVATION_SIZE(),)
    assert first.dtype == np.float32
    assert np.array_equal(first, second)
    assert np.all(first >= 0.0) and np.all(first <= 1.0)


def test_every_scenarios_encoding_is_distinct():
    encodings = {tuple(SecurityContextEncoder().encode(context_for_scenario(s))) for s in TRAINING_SCENARIOS()}
    assert len(encodings) == len(TRAINING_SCENARIOS())


def test_action_mapping_matches_defense_actions():
    assert ACTION_TO_INDEX == {action: index for index, action in enumerate(DefenseAction)}
    assert len(ACTION_TO_INDEX) == 10


class TestNoisyContext:
    def kwargs(self, **over):
        base = dict(label_error_rate=0.0, score_sigma=0.07, feature_jitter=0.5)
        base.update(over)
        return base

    def test_zero_error_rate_never_mislabels(self):
        rng = np.random.default_rng(0)
        for condition in TRAINING_SCENARIOS():
            _, reported = noisy_context(condition, rng, **self.kwargs())
            assert reported == condition

    def test_error_rate_one_always_mislabels_to_a_different_condition(self):
        rng = np.random.default_rng(0)
        for condition in TRAINING_SCENARIOS():
            _, reported = noisy_context(condition, rng, **self.kwargs(label_error_rate=1.0))
            assert reported != condition and reported in TRAINING_SCENARIOS()

    def test_empirical_error_rate_matches_the_configured_rate(self):
        rng = np.random.default_rng(1)
        errors = sum(noisy_context("dos_flood", rng, **self.kwargs(label_error_rate=0.3))[1] != "dos_flood" for _ in range(2000))
        assert 0.26 < errors / 2000 < 0.34

    def test_scores_stay_in_range_and_features_nonnegative(self):
        rng = np.random.default_rng(2)
        for _ in range(300):
            context, _ = noisy_context("dos_flood", rng, **self.kwargs(score_sigma=0.5, feature_jitter=0.9))
            assert 0.0 <= context.beliefs.threat_score <= 1.0
            assert 0.0 <= context.beliefs.confidence <= 1.0
            assert all(v >= 0.0 for v in context.beliefs.observed_features.values())

    def test_device_criticality_varies_so_the_policy_cannot_depend_on_it(self):
        rng = np.random.default_rng(3)
        seen = {noisy_context("dos_flood", rng, **self.kwargs())[0].beliefs.device_criticality for _ in range(200)}
        assert seen == set(CRITICALITY_LEVELS)


class TestEnvironment:
    def test_reset_step_reward_and_termination(self, synthetic_table):
        env = DefenseDecisionEnv(synthetic_table, episode_length=2)
        observation, info = env.reset(seed=7)
        assert observation.shape == (OBSERVATION_SIZE(),)
        assert info["true_condition"] in TRAINING_SCENARIOS()
        _, reward, terminated, truncated, step_info = env.step(ACTION_TO_INDEX[DefenseAction.ALLOW])
        assert step_info["true_condition"] == info["true_condition"]
        assert terminated is False and truncated is False
        _, _, terminated, _, _ = env.step(0)
        assert terminated is True

    def test_reward_is_the_scaled_measured_utility_of_the_true_condition(self, synthetic_table):
        env = DefenseDecisionEnv(synthetic_table, label_error_rate=1.0, reward_scale=10.0)
        _, info = env.reset(seed=11)
        true = info["true_condition"]
        assert info["reported_condition"] != true
        measured = set(synthetic_table.samples(true, DefenseAction.ISOLATE))
        _, reward, _, _, step_info = env.step(ACTION_TO_INDEX[DefenseAction.ISOLATE])
        assert step_info["utility"] in measured
        assert reward == pytest.approx(step_info["utility"] / 10.0)

    def test_measured_best_action_earns_the_highest_reward(self, synthetic_table):
        from conftest import synthetic_best_actions

        for condition, best in synthetic_best_actions().items():
            best_mean = synthetic_table.mean(condition, best)
            assert all(best_mean >= synthetic_table.mean(condition, a) for a in DefenseAction)

    def test_conditions_are_drawn_across_the_whole_registry(self, synthetic_table):
        env = DefenseDecisionEnv(synthetic_table, episode_length=10_000)
        _, info = env.reset(seed=5)
        seen = {info["true_condition"]}
        for _ in range(600):
            _, _, _, _, step_info = env.step(0)
            seen.add(step_info["next_true_condition"])
        assert seen == set(TRAINING_SCENARIOS())

    def test_incomplete_table_is_rejected(self):
        with pytest.raises(ValueError, match="no valid measurement"):
            DefenseDecisionEnv(OutcomeTable([], Objective.load()))

    def test_invalid_action_is_rejected(self, synthetic_table):
        env = DefenseDecisionEnv(synthetic_table)
        env.reset(seed=1)
        with pytest.raises(ValueError):
            env.step(99)


def test_ppo_policy_fallback_is_explicit_when_model_is_absent(tmp_path):
    policy = PPODefensePolicy(tmp_path / "missing-model", fallback=RuleBasedDefensePolicy())
    event = ThreatEvent.from_result(
        source_ip="10.0.0.100", destination_ip="10.0.0.10", attack_type="normal",
        threat_score=0.05, confidence=0.9, detection_reason="test", features={},
    )
    decision = policy.decide(build_security_context(event))
    assert decision.action == DefenseAction.ALLOW
    assert decision.context["ppo_fallback"] == "RuleBasedDefensePolicy"


def test_ppo_policy_rejects_missing_model_without_fallback(tmp_path):
    with pytest.raises(FileNotFoundError, match="Train it first"):
        PPODefensePolicy(tmp_path / "missing-model")


def test_ppo_action_output_is_valid():
    class FakeModel:
        def predict(self, observation, deterministic=True):
            assert observation.shape == (OBSERVATION_SIZE(),)
            return ACTION_TO_INDEX[DefenseAction.DECOY], None

    policy = PPODefensePolicy("unused", fallback=RuleBasedDefensePolicy())
    policy.model = FakeModel()
    policy.fallback = None
    assert policy.decide(context_for_scenario("reconnaissance_port_scan")).action == DefenseAction.DECOY


def test_a_model_trained_on_a_different_observation_layout_is_rejected(tmp_path):
    from stable_baselines3 import PPO

    class Stale(gym.Env):
        observation_space = spaces.Box(0.0, 1.0, shape=(5,), dtype=np.float32)
        action_space = spaces.Discrete(10)

        def reset(self, *, seed=None, options=None):
            return np.zeros(5, dtype=np.float32), {}

        def step(self, action):
            return np.zeros(5, dtype=np.float32), 0.0, True, False, {}

    PPO("MlpPolicy", Stale(), device="cpu").save(str(tmp_path / "stale"))
    with pytest.raises(ValueError, match="different observation layout"):
        PPODefensePolicy(tmp_path / "stale")


def test_training_on_measured_outcomes_learns_the_measured_best_action(trained_ppo_path, synthetic_table):
    """Trains for real (not mocked) on the synthetic table, whose best action
    per condition is known by construction, and checks the learned policy
    picks it for (nearly) every condition from canonical observations."""
    from conftest import synthetic_best_actions

    policy = PPODefensePolicy(model_path=trained_ppo_path)
    best = synthetic_best_actions()
    wrong = [
        (c, policy.decide(context_for_scenario(c)).action.name, b.name)
        for c, b in best.items()
        if policy.decide(context_for_scenario(c)).action != b
    ]
    assert len(wrong) <= 2, f"PPO failed to learn the measured-best action on: {wrong}"
