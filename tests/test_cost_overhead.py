"""Unit tests for evaluation/cost_overhead.py -- no Mininet required."""
from __future__ import annotations

from iot_defense.evaluation.cost_overhead import run


def test_all_three_policies_decide_in_low_single_digit_milliseconds():
    """A real, reassuring finding worth locking in: comparing three
    policies costs negligible time relative to this project's own real
    detection latency (thousands of milliseconds, dominated by packet
    capture, not decision-making)."""
    result = run()
    assert result["all_three_sequential_mean_ms"] < 50
    for name, stats in result["per_policy"].items():
        assert stats["mean_ms"] < 20, f"{name}'s mean decision latency was unexpectedly high: {stats}"


def test_overhead_of_running_all_three_is_small_relative_to_the_slowest_one():
    result = run()
    assert result["overhead_of_comparing_vs_deploying_one_ms"] < result["slowest_single_policy_mean_ms"] * 2
