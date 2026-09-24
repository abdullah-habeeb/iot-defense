"""Unit test for evaluation/ppo_seed_robustness.py. Trains real (small)
PPO models, so this is slower than most unit tests but Mininet-free and
deterministic given a seed."""
from __future__ import annotations

from iot_defense.evaluation.ppo_seed_robustness import run, summarize


def test_summary_reports_a_convergence_rate_between_0_and_1_with_a_ci():
    summary = summarize(run(seeds=(1, 7)))
    assert summary["seeds_tested"] == 2
    assert 0.0 <= summary["fully_converged_rate"] <= 1.0
    ci = summary["fully_converged_rate_ci95"]
    assert ci is not None
    assert 0.0 <= ci[0] <= ci[1] <= 1.0
