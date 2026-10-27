"""Unit tests for evaluation/ppo_seed_robustness.py (regret on measured outcomes).
Trains real small PPO models on the synthetic table -- slower than most unit
tests but Mininet-free and deterministic given a seed."""
from __future__ import annotations

import pytest

from iot_defense.defense.ppo_env import TRAINING_SCENARIOS
from iot_defense.evaluation.ppo_seed_robustness import NEAR_OPTIMAL_REGRET, regret_for_model, run, summarize


def test_regret_of_a_trained_model_is_small_and_reported_per_condition(trained_ppo_path, synthetic_table):
    result = regret_for_model(trained_ppo_path, synthetic_table)
    assert set(result["per_condition"]) == set(TRAINING_SCENARIOS())
    assert 0.0 <= result["mean_regret"] <= result["max_regret"]
    assert result["mean_regret"] < 2.0
    for entry in result["per_condition"].values():
        assert entry["regret"] >= 0.0


def test_sweep_trains_one_model_per_seed_and_summarizes(synthetic_table_path, tmp_path):
    rows = run(synthetic_table_path, seeds=(1, 2), scratch_dir=str(tmp_path), timesteps=20000)
    assert [r["seed"] for r in rows] == [1, 2]
    summary = summarize(rows)
    assert summary["seeds_tested"] == 2
    assert summary["mean_regret_worst_seed"] >= summary["mean_regret_median"] >= 0.0
    assert 0 <= summary["near_optimal_seeds"] <= 2
    assert summary["near_optimal_threshold"] == NEAR_OPTIMAL_REGRET


def test_summarize_counts_near_optimal_seeds():
    rows = [{"mean_regret": 0.0}, {"mean_regret": NEAR_OPTIMAL_REGRET}, {"mean_regret": 3.0}]
    summary = summarize(rows)
    assert summary["near_optimal_seeds"] == 2
    assert summary["mean_regret_worst_seed"] == pytest.approx(3.0)
