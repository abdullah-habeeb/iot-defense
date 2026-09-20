import numpy as np

from iot_defense.defense.context import build_security_context
from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.policy import RuleBasedDefensePolicy
from iot_defense.defense.ppo_env import (
    ACTION_TO_INDEX,
    OBSERVATION_SIZE,
    TRAINING_SCENARIOS,
    DefenseDecisionEnv,
    RewardConfig,
    SecurityContextEncoder,
    context_for_scenario,
    load_ppo_training_config,
)
from iot_defense.defense.ppo_policy import PPODefensePolicy
from iot_defense.detection.threat_event import ThreatEvent


def test_load_ppo_training_config_actually_finds_the_yaml_file():
    """Regression coverage for the same 'config never actually loads' bug
    class already found and fixed in policy.py/detector.py -- this asserts
    the file is genuinely found rather than silently returning {}."""
    config = load_ppo_training_config()
    assert config, "config/policies.yaml's policy.ppo section must actually load"
    assert config["training_timesteps"] == 12000
    assert config["environment_episode_length"] == 6


def test_reward_config_from_mapping_reads_real_yaml_values():
    config = RewardConfig.from_mapping(load_ppo_training_config()["reward"])
    assert config.attack_contained == 5.0
    assert config.response_cost == -0.5


def test_reward_config_from_mapping_ignores_unknown_keys():
    # Defensive: a stray/renamed YAML key must not crash config loading.
    config = RewardConfig.from_mapping({"attack_contained": 9.0, "not_a_real_field": 1.0})
    assert config.attack_contained == 9.0


def test_context_encoding_is_normalized_and_deterministic():
    context = context_for_scenario("reconnaissance_port_scan")
    encoder = SecurityContextEncoder()
    first = encoder.encode(context)
    second = encoder.encode(context)
    assert first.shape == (OBSERVATION_SIZE(),)
    assert first.dtype == np.float32
    assert np.array_equal(first, second)
    assert np.all(first >= 0.0)
    assert np.all(first <= 1.0)


def test_dos_flood_context_encodes_distinct_one_hot_flag():
    recon = SecurityContextEncoder().encode(context_for_scenario("reconnaissance_port_scan"))
    dos = SecurityContextEncoder().encode(context_for_scenario("dos_flood"))
    assert dos.shape == (OBSERVATION_SIZE(),)
    # The two attack-type scenarios must not collapse to the same encoding.
    assert not np.array_equal(recon, dos)


def test_action_mapping_matches_defense_actions():
    assert ACTION_TO_INDEX == {
        DefenseAction.ALLOW: 0,
        DefenseAction.ALERT: 1,
        DefenseAction.ISOLATE: 2,
        DefenseAction.DECOY: 3,
        DefenseAction.THROTTLE: 4,
        DefenseAction.BLOCK_SOURCE: 5,
        DefenseAction.QUARANTINE: 6,
        DefenseAction.RESET_SESSIONS: 7,
        DefenseAction.FORENSIC_CAPTURE: 8,
        DefenseAction.BANDWIDTH_CAP: 9,
    }


def test_environment_reset_step_reward_and_termination():
    environment = DefenseDecisionEnv(episode_length=2)
    observation, info = environment.reset(seed=7)
    assert observation.shape == (OBSERVATION_SIZE(),)
    assert info["scenario"] == "normal"

    next_observation, reward, terminated, truncated, step_info = environment.step(ACTION_TO_INDEX[DefenseAction.ALLOW])
    assert next_observation.shape == (OBSERVATION_SIZE(),)
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


def test_dos_flood_reward_favors_isolation_over_decoy_and_allow():
    """Unlike reconnaissance, a flood should reward containment far more than
    deception -- there is nothing useful to learn by redirecting a flood."""
    environment = DefenseDecisionEnv()
    dos = context_for_scenario("dos_flood")
    isolate_reward, _ = environment.calculate_reward(dos, DefenseAction.ISOLATE)
    decoy_reward, _ = environment.calculate_reward(dos, DefenseAction.DECOY)
    allow_reward, _ = environment.calculate_reward(dos, DefenseAction.ALLOW)
    assert isolate_reward > decoy_reward > allow_reward


def test_brute_force_reward_favors_isolation_over_allow():
    """Brute-force's preferred_action is ISOLATE (until Phase 3 adds
    THROTTLE) -- letting repeated login attempts through must always score
    worse than containing them."""
    environment = DefenseDecisionEnv()
    brute_force = context_for_scenario("brute_force")
    isolate_reward, _ = environment.calculate_reward(brute_force, DefenseAction.ISOLATE)
    allow_reward, _ = environment.calculate_reward(brute_force, DefenseAction.ALLOW)
    assert isolate_reward > allow_reward


def test_environment_cycles_through_all_registered_scenarios():
    training_scenarios = TRAINING_SCENARIOS()
    environment = DefenseDecisionEnv(episode_length=len(training_scenarios))
    _, info = environment.reset(seed=7)
    assert info["scenario"] == "normal"
    seen = {info["scenario"]}
    for _ in range(len(training_scenarios)):
        _, _, _, _, step_info = environment.step(ACTION_TO_INDEX[DefenseAction.ALERT])
        seen.add(step_info["scenario"])
    assert seen == set(training_scenarios)


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
            assert observation.shape == (OBSERVATION_SIZE(),)
            return ACTION_TO_INDEX[DefenseAction.DECOY], None

    policy = PPODefensePolicy("unused", fallback=RuleBasedDefensePolicy())
    policy.model = FakeModel()
    policy.fallback = None
    decision = policy.decide(context_for_scenario("reconnaissance_port_scan"))
    assert decision.action == DefenseAction.DECOY
