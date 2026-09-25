"""McNemar's test for paired nominal outcomes: given two policies each
evaluated on the exact same trials, is one's advantage over the other --
among the trials where they disagree -- real, or within chance?

This is the right test for this project's own three-policy comparison
specifically because every arm is evaluated against the *identical*
trial (harness.py) or the *identical* synthetic context
(policy_disagreement.py) -- a paired design, not an independent-samples
one. A plain difference-in-accuracy comparison (or even two separate
Wilson CIs that happen to overlap or not) throws away that pairing;
McNemar's test uses it directly, and is only informed by trials where
the two policies actually disagree (concordant trials -- both right or
both wrong -- carry no information about which policy is better, and are
correctly excluded from the test statistic, not just this analysis).
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from scipy.stats import binomtest


def mcnemar_test(outcomes_a: list[bool], outcomes_b: list[bool]) -> dict[str, Any]:
    """Exact McNemar's test (binomial, not the chi-square approximation)
    on paired boolean outcomes for the same trials.

    The exact binomial form is used rather than the more commonly cited
    chi-square approximation because it is correct at any sample size,
    including the small discordant-pair counts expected here (these
    policies mostly agree) -- the chi-square approximation is only valid
    when discordant counts are reasonably large, and silently misleading
    when they are not.
    """
    if len(outcomes_a) != len(outcomes_b):
        raise ValueError("Paired outcomes must be the same length")
    if not outcomes_a:
        raise ValueError("Cannot run McNemar's test on zero paired trials")
    n = len(outcomes_a)
    both_correct = sum(1 for a, b in zip(outcomes_a, outcomes_b) if a and b)
    both_wrong = sum(1 for a, b in zip(outcomes_a, outcomes_b) if not a and not b)
    a_only = sum(1 for a, b in zip(outcomes_a, outcomes_b) if a and not b)
    b_only = sum(1 for a, b in zip(outcomes_a, outcomes_b) if not a and b)
    discordant = a_only + b_only
    # Zero discordant pairs is a real, valid outcome here (already
    # independently established: real captured traffic classifies far
    # from any decision boundary, so all three policies choose the same
    # action every time) -- reported as p=1.0 (no evidence whatsoever of
    # a difference), not an error, and discordant_pairs=0 makes that
    # degeneracy visible rather than hidden behind a computed p-value
    # that would look like real statistical evidence.
    p_value = 1.0 if discordant == 0 else binomtest(
        min(a_only, b_only), discordant, 0.5, alternative="two-sided"
    ).pvalue
    return {
        "n_trials": n,
        "both_correct": both_correct,
        "both_wrong": both_wrong,
        "a_only_correct": a_only,
        "b_only_correct": b_only,
        "discordant_pairs": discordant,
        "p_value": round(p_value, 6),
    }


def _harness_outcomes(results_path: str | Path, outcome_field: str = "response_verified") -> dict[str, dict[tuple[str, int], bool]]:
    """Pull paired per-arm outcomes from a real harness results.jsonl,
    keyed by (condition, trial) so the same physical trial's rows across
    arms can be matched up for a paired test. None outcomes (e.g. a
    policy that never chose the preferred action, so response_verified
    was never evaluated) are treated as failures -- a policy that never
    even attempted the right action did not succeed, which is the
    correct reading for this specific test's purpose."""
    by_arm: dict[str, dict[tuple[str, int], bool]] = defaultdict(dict)
    with open(results_path, encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            key = (row["condition"], row["trial"])
            by_arm[row["arm"]][key] = bool(row.get(outcome_field))
    return by_arm


def _paired(a_outcomes: dict[tuple[str, int], bool], b_outcomes: dict[tuple[str, int], bool]) -> tuple[list[bool], list[bool]]:
    shared_keys = sorted(set(a_outcomes) & set(b_outcomes))
    return [a_outcomes[k] for k in shared_keys], [b_outcomes[k] for k in shared_keys]


def run_on_harness_results(results_path: str | Path = "data/evaluation/results.jsonl") -> dict[str, Any]:
    by_arm = _harness_outcomes(results_path)
    pairs = [("rule_based", "stackelberg"), ("rule_based", "ppo"), ("stackelberg", "ppo")]
    results = {}
    for arm_a, arm_b in pairs:
        a_vals, b_vals = _paired(by_arm[arm_a], by_arm[arm_b])
        results[f"{arm_a}_vs_{arm_b}"] = mcnemar_test(a_vals, b_vals)
    return results


def run_on_decision_divergence(disagreement_path: str | Path = "data/evaluation/policy_disagreement.jsonl") -> dict[str, Any]:
    """Same test against the synthetic decision-boundary dataset
    (policy_disagreement.py), restricted to in-distribution rows (a real
    registered preferred_action exists to score correctness against --
    the 12 out-of-distribution rows have no such ground truth and are too
    few for a meaningful paired test regardless)."""
    from iot_defense.attacks.registry import ATTACK_SCENARIOS

    preferred_by_key = {key: scenario.preferred_action.value for key, scenario in ATTACK_SCENARIOS.items()}
    rule_vals, stack_vals, ppo_vals = [], [], []
    with open(disagreement_path, encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            if row.get("boundary") != "in_distribution":
                continue
            preferred = preferred_by_key.get(row["attack_key"])
            if preferred is None:
                continue
            rule_vals.append(row["rule_action"] == preferred)
            stack_vals.append(row["stack_action"] == preferred)
            ppo_vals.append(row["ppo_action"] == preferred)
    return {
        "rule_based_vs_stackelberg": mcnemar_test(rule_vals, stack_vals),
        "rule_based_vs_ppo": mcnemar_test(rule_vals, ppo_vals),
        "stackelberg_vs_ppo": mcnemar_test(stack_vals, ppo_vals),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", default="data/evaluation/results.jsonl")
    parser.add_argument("--disagreement", default="data/evaluation/policy_disagreement.jsonl")
    parser.add_argument("--output", default="data/evaluation/mcnemar_test.json")
    args = parser.parse_args()

    output = {
        "real_harness_trials": run_on_harness_results(args.results),
        "synthetic_decision_boundary_trials": run_on_decision_divergence(args.disagreement),
    }
    Path(args.output).write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
