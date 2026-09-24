"""Unit tests for evaluation/reward_shaping_ablation.py. Trains real
(small) PPO models, so this is slower than most unit tests but still
Mininet-free and fully deterministic given a seed."""
from __future__ import annotations

from iot_defense.evaluation.reward_shaping_ablation import run, summarize


def test_both_reward_configs_report_a_fully_converged_rate_between_0_and_1():
    summary = summarize(run(seeds=(1, 7)))
    assert set(summary) == {"shaped", "flat"}
    for tag, stats in summary.items():
        assert stats["seeds_tested"] == 2
        assert 0.0 <= stats["fully_converged_rate"] <= 1.0
