"""Unit tests for evaluation/detector_robustness.py -- no Mininet
required."""
from __future__ import annotations

from iot_defense.evaluation.detector_robustness import run, summarize


def test_every_attacks_exact_calibrated_point_still_classifies_correctly():
    """The tautological baseline this sweep's real value is measured
    against -- if this ever fails, a detector's own docstring-claimed
    calibration point has drifted from what the code actually does."""
    summary = summarize(run())
    for key, stats in summary.items():
        assert stats["calibrated_point_correct"], f"{key}'s own calibrated point no longer classifies correctly"


def test_robustness_varies_across_attacks_not_uniformly_brittle_or_robust():
    """A real, honest finding: some attacks (e.g. dos, brute_force,
    exfiltration) have wide real margin; others (dns_amplification,
    firmware_tampering, buffer_overflow) have much tighter margins,
    consistent with this project's own documented finding that this
    region of the numeric space is more crowded. This test locks in
    that the measurement itself is meaningful -- neither all attacks at
    100% (which would suggest the perturbation range is too timid to
    mean anything) nor all attacks near 0% (which would suggest the
    calibration really is maximally brittle)."""
    summary = summarize(run())
    rates = [s["robust_rate"] for s in summary.values()]
    assert min(rates) < 0.9, "expected at least one attack with a real, tight margin"
    assert max(rates) > 0.5, "expected at least one attack with real, wide margin"
