"""Unit tests for evaluation/cost_overhead.py -- no Mininet required."""
from __future__ import annotations

from iot_defense.evaluation.cost_overhead import run


def test_all_three_policies_decide_in_low_single_digit_milliseconds(trained_ppo_path):
    """Comparing three policies costs negligible time relative to this
    project's own real detection latency (thousands of milliseconds,
    dominated by packet capture, not decision-making)."""
    result = run(model_path=trained_ppo_path)
    # Median and 95th percentile, not the mean: one scheduler stall on a busy VM (an 8 s outlier was seen while another job
    # ran) would dominate a 300-sample mean without saying anything about the cost of a decision.
    assert sum(stats["median_ms"] for stats in result["per_policy"].values()) < 50
    for name, stats in result["per_policy"].items():
        assert stats["median_ms"] < 20, f"{name}'s median decision latency was unexpectedly high: {stats}"
        assert stats["p95_ms"] < 50, f"{name}'s 95th-percentile decision latency was unexpectedly high: {stats}"


def test_overhead_of_running_all_three_is_small_relative_to_the_slowest_one(trained_ppo_path):
    result = run(model_path=trained_ppo_path)
    assert result["overhead_of_comparing_vs_deploying_one_ms"] < result["slowest_single_policy_mean_ms"] * 2
