"""Unit tests for evaluation/stackelberg_ablation.py -- no Mininet
required, pure computation."""
from __future__ import annotations

from iot_defense.evaluation.stackelberg_ablation import run, summarize


def test_match_rate_degrades_monotonically_as_noise_increases():
    """A real, honest finding: the specific hand-tuned payoff values
    matter more as noise grows, not a flat/uninformative result at
    every noise level."""
    summary = summarize(run())
    rates = [summary[key]["match_rate"] for key in ("0.05", "0.1", "0.2", "0.35", "0.5")]
    assert rates == sorted(rates, reverse=True), f"expected monotonic degradation, got {rates}"


def test_small_perturbation_still_mostly_recovers_the_registered_preferred_action():
    """At small noise (+/-5%), the qualitative structure of the payoff
    table should dominate over the exact values -- real evidence this
    isn't a maximally brittle single-point calibration."""
    summary = summarize(run())
    assert summary["0.05"]["match_rate"] > 0.9


def test_even_large_perturbation_beats_random_chance():
    """At +/-50% noise, the payoff structure should still meaningfully
    outperform picking one of 10 actions uniformly at random (10%)."""
    summary = summarize(run())
    assert summary["0.5"]["match_rate"] > 0.3
