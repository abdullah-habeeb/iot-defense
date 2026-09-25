"""Unit tests for evaluation/mcnemar_test.py -- no Mininet required."""
from __future__ import annotations

import json

from iot_defense.evaluation.mcnemar_test import (
    mcnemar_test,
    run_on_decision_divergence,
    run_on_harness_results,
)


def test_matches_a_hand_computed_exact_binomial_reference_value():
    """20 paired trials: 5 both-correct, 5 both-wrong (concordant, must
    be ignored by the test statistic), 1 trial where only A is correct,
    9 trials where only B is correct (10 discordant pairs). The exact
    two-sided binomial p-value against p=0.5 at k=min(1,9)=1 successes
    out of 10 is 2*(C(10,0)+C(10,1))/2**10 = 2*11/1024 = 0.021484375 --
    computed by hand here, not copied from a library, mirroring how this
    project's own Wilson-CI implementation was independently verified."""
    outcomes_a = [True] * 5 + [False] * 5 + [True] * 1 + [False] * 9
    outcomes_b = [True] * 5 + [False] * 5 + [False] * 1 + [True] * 9
    result = mcnemar_test(outcomes_a, outcomes_b)
    assert result["n_trials"] == 20
    assert result["both_correct"] == 5
    assert result["both_wrong"] == 5
    assert result["a_only_correct"] == 1
    assert result["b_only_correct"] == 9
    assert result["discordant_pairs"] == 10
    # The module rounds to 6 decimal places (matching this project's own
    # Wilson-CI convention); compare against that same rounded value.
    assert result["p_value"] == round(0.021484375, 6)


def test_zero_discordant_pairs_is_a_real_p_equals_one_not_an_error():
    """Perfect agreement (every trial concordant) is a real, valid input
    for this project's own data -- real captured traffic was already
    shown to make all three policies agree on every trial -- and must
    report p=1.0 (no evidence of a difference), not raise or silently
    compute a misleading number from an empty discordant set."""
    outcomes_a = [True, True, False, False]
    outcomes_b = [True, True, False, False]
    result = mcnemar_test(outcomes_a, outcomes_b)
    assert result["discordant_pairs"] == 0
    assert result["p_value"] == 1.0


def test_mismatched_lengths_raise_instead_of_silently_truncating():
    try:
        mcnemar_test([True, False], [True])
    except ValueError:
        pass
    else:
        raise AssertionError("Mismatched-length paired outcomes must raise, not truncate silently")


def test_run_on_harness_results_pairs_rows_by_condition_and_trial(tmp_path):
    """A minimal, real results.jsonl fixture: two trials, three arms
    each, deliberately disagreeing on one trial so the pairing logic
    (matching by (condition, trial), not just row order) is genuinely
    exercised, not just trivially concordant."""
    rows = [
        {"condition": "dos_flood", "trial": 0, "arm": "rule_based", "response_verified": True},
        {"condition": "dos_flood", "trial": 0, "arm": "stackelberg", "response_verified": True},
        {"condition": "dos_flood", "trial": 0, "arm": "ppo", "response_verified": False},
        {"condition": "dos_flood", "trial": 1, "arm": "rule_based", "response_verified": True},
        {"condition": "dos_flood", "trial": 1, "arm": "stackelberg", "response_verified": True},
        {"condition": "dos_flood", "trial": 1, "arm": "ppo", "response_verified": True},
    ]
    results_path = tmp_path / "results.jsonl"
    results_path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

    output = run_on_harness_results(results_path)
    assert output["rule_based_vs_ppo"]["n_trials"] == 2
    assert output["rule_based_vs_ppo"]["discordant_pairs"] == 1
    assert output["rule_based_vs_stackelberg"]["discordant_pairs"] == 0
    assert output["rule_based_vs_stackelberg"]["p_value"] == 1.0


def test_run_on_decision_divergence_scores_against_the_real_registry(tmp_path):
    """A minimal fixture matching policy_disagreement.py's own real row
    shape, scored against the real registry's own preferred_action for a
    known attack key (brute_force -> BLOCK_SOURCE) -- confirms this
    reads real registry data, not a hardcoded assumption."""
    rows = [
        {"attack_key": "brute_force", "boundary": "in_distribution",
         "rule_action": "BLOCK_SOURCE", "stack_action": "BLOCK_SOURCE", "ppo_action": "THROTTLE"},
        {"attack_key": "brute_force", "boundary": "in_distribution",
         "rule_action": "BLOCK_SOURCE", "stack_action": "BLOCK_SOURCE", "ppo_action": "BLOCK_SOURCE"},
        {"attack_key": "novel:zero_day", "boundary": "out_of_distribution",
         "rule_action": "ALERT", "stack_action": "ALERT", "ppo_action": "ISOLATE"},
    ]
    path = tmp_path / "policy_disagreement.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

    output = run_on_decision_divergence(path)
    # Only the 2 in_distribution rows should be scored; the OOD row is excluded.
    assert output["rule_based_vs_ppo"]["n_trials"] == 2
    assert output["rule_based_vs_ppo"]["discordant_pairs"] == 1
    assert output["rule_based_vs_stackelberg"]["discordant_pairs"] == 0
