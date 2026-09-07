"""Unit tests for RealMininetDefenseEnv's pure logic -- no Mininet required.

The Gym plumbing (reset/step) drives real Mininet and cannot be exercised
in a unit test; calculate_reward() and instantiation, however, are pure
and are covered here.
"""

from __future__ import annotations

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.ppo_real_env import RealMininetDefenseEnv


def _env():
    return RealMininetDefenseEnv(episode_length=4)


def test_instantiation_does_not_touch_mininet():
    env = _env()
    assert env.net is None
    assert env.executor is None


def test_normal_scenario_rewards_allow_and_penalizes_isolate():
    env = _env()
    allow_reward, _ = env.calculate_reward("normal", DefenseAction.ALLOW, {"status": "success"})
    isolate_reward, _ = env.calculate_reward("normal", DefenseAction.ISOLATE, {"status": "success"})
    assert allow_reward > isolate_reward


def test_dos_flood_rewards_verified_isolation_over_unverified():
    env = _env()
    verified, _ = env.calculate_reward("dos_flood", DefenseAction.ISOLATE, {"status": "success", "connectivity_lost": True})
    unverified, _ = env.calculate_reward("dos_flood", DefenseAction.ISOLATE, {"status": "success", "connectivity_lost": False})
    assert verified > unverified


def test_dos_flood_rewards_isolation_over_decoy_and_allow():
    env = _env()
    isolate, _ = env.calculate_reward("dos_flood", DefenseAction.ISOLATE, {"status": "success", "connectivity_lost": True})
    decoy, _ = env.calculate_reward("dos_flood", DefenseAction.DECOY, {"status": "success"})
    allow, _ = env.calculate_reward("dos_flood", DefenseAction.ALLOW, {"status": "success"})
    assert isolate > decoy > allow


def test_reconnaissance_rewards_verified_decoy_interaction_over_unverified():
    env = _env()
    verified, _ = env.calculate_reward(
        "reconnaissance_port_scan", DefenseAction.DECOY, {"status": "success", "interaction_verified": True}
    )
    unverified, _ = env.calculate_reward(
        "reconnaissance_port_scan", DefenseAction.DECOY, {"status": "success", "interaction_verified": False}
    )
    assert verified > unverified


def test_reconnaissance_penalizes_allow():
    env = _env()
    decoy, _ = env.calculate_reward(
        "reconnaissance_port_scan", DefenseAction.DECOY, {"status": "success", "interaction_verified": True}
    )
    allow, _ = env.calculate_reward("reconnaissance_port_scan", DefenseAction.ALLOW, {"status": "success"})
    assert decoy > allow


def test_failed_execution_never_scores_as_well_as_verified_success():
    """A response that reports failure must not be rewarded as if it worked,
    even for the otherwise-correct action."""
    env = _env()
    verified, _ = env.calculate_reward("dos_flood", DefenseAction.ISOLATE, {"status": "success", "connectivity_lost": True})
    failed, _ = env.calculate_reward("dos_flood", DefenseAction.ISOLATE, {"status": "failed", "connectivity_lost": False})
    assert verified > failed
