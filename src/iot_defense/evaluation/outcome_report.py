"""Statistics on the measured-outcome evaluation (harness.py results).

Every comparison is on realized utility computed from measured outcomes,
paired by (condition, trial) because all arms are scored on the identical
trial. A trial enters the paired analysis only if every one of the three
policy arms has a valid measurement in it (a probe that could not be read is
excluded, never scored as a success).

Also reports how often the policies actually choose different actions (the
independence question directly), re-scores the same measurements under
alternative objective weightings, and compares the Stackelberg arm's
a-priori containment priors against what was measured.
"""

from __future__ import annotations

import argparse
import itertools
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np
from scipy.stats import binomtest, wilcoxon

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.objective import Objective, load_policy_section

POLICY_ARMS = ("rule_based", "stackelberg", "ppo")
BASELINE_ARMS = ("naive_block_all", "always_allow")
ALL_ARMS = POLICY_ARMS + BASELINE_ARMS
BOOTSTRAP_RESAMPLES = 10000
BOOTSTRAP_SEED = 20260929


def load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def rescored(row: dict[str, Any], objective: Objective) -> float:
    """Utility of one harness row under `objective`, from its measured vector."""
    is_attack = row["condition"] != "normal"
    return objective.utility(
        DefenseAction(row["action"]),
        containment=row["containment"] if is_attack else None,
        service=1.0 - row["service_loss"],
        intelligence=1.0 if row["intel_verified"] else 0.0,
    )


def paired_trials(rows: list[dict[str, Any]]) -> tuple[dict[tuple[str, int], dict[str, dict[str, Any]]], int]:
    """Trials where every arm has a valid measurement, keyed
    (condition, trial) -> arm -> row; also the count of excluded trials."""
    by_trial: dict[tuple[str, int], dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in rows:
        by_trial[(row["condition"], row["trial"])][row["arm"]] = row
    kept, excluded = {}, 0
    for key, arms in by_trial.items():
        if all(arm in arms and arms[arm]["valid_measurement"] for arm in ALL_ARMS):
            kept[key] = arms
        else:
            excluded += 1
    return kept, excluded


def bootstrap_mean_ci(values: np.ndarray, seed: int = BOOTSTRAP_SEED) -> tuple[float, float]:
    rng = np.random.default_rng(seed)
    means = rng.choice(values, size=(BOOTSTRAP_RESAMPLES, len(values)), replace=True).mean(axis=1)
    low, high = np.percentile(means, [2.5, 97.5])
    return float(low), float(high)


def paired_comparison(diffs: np.ndarray) -> dict[str, Any]:
    """Paired comparison of per-trial utility differences (a - b)."""
    n = len(diffs)
    nonzero = diffs[diffs != 0]
    if n == 0:
        raise ValueError("no paired trials")
    if len(nonzero) == 0:
        # Identical utility on every trial: no evidence of any difference.
        return {"n_trials": n, "n_nonzero": 0, "mean_diff": 0.0, "mean_diff_ci95": [0.0, 0.0],
                "wilcoxon_p": 1.0, "sign_test_p": 1.0}
    wins = int((nonzero > 0).sum())
    return {
        "n_trials": n,
        "n_nonzero": int(len(nonzero)),
        "mean_diff": float(diffs.mean()),
        "mean_diff_ci95": list(bootstrap_mean_ci(diffs)),
        "wilcoxon_p": float(wilcoxon(nonzero, zero_method="wilcox").pvalue),
        "sign_test_p": float(binomtest(wins, len(nonzero), 0.5).pvalue),
    }


def holm(p_values: dict[str, float]) -> dict[str, float]:
    """Holm-Bonferroni step-down adjusted p-values."""
    ordered = sorted(p_values.items(), key=lambda kv: kv[1])
    m = len(ordered)
    adjusted: dict[str, float] = {}
    running = 0.0
    for rank, (name, p) in enumerate(ordered):
        running = max(running, min(1.0, (m - rank) * p))
        adjusted[name] = running
    return adjusted


def arm_summary(trials: dict[tuple[str, int], dict[str, dict[str, Any]]], objective: Objective) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for arm in ALL_ARMS:
        rows = [arms[arm] for arms in trials.values()]
        utilities = np.array([rescored(r, objective) for r in rows])
        attack_rows = [r for r in rows if r["condition"] != "normal"]
        low, high = bootstrap_mean_ci(utilities)
        summary[arm] = {
            "n_trials": len(rows),
            "mean_utility": float(utilities.mean()),
            "mean_utility_ci95": [low, high],
            "mean_containment_on_attacks": float(np.mean([r["containment"] for r in attack_rows])) if attack_rows else None,
            "mean_service_loss": float(np.mean([r["service_loss"] for r in rows])),
            "intel_verified_rate_on_attacks": float(np.mean([r["intel_verified"] for r in attack_rows])) if attack_rows else None,
            "execution_failure_rate": float(np.mean([not r["execution_ok"] for r in rows])),
            "agreement_with_registry_preferred_action_on_attacks": (
                float(np.mean([r["matches_preferred_action"] for r in attack_rows])) if attack_rows else None
            ),
        }
    return summary


def pairwise(trials: dict[tuple[str, int], dict[str, dict[str, Any]]], objective: Objective) -> dict[str, Any]:
    results: dict[str, Any] = {}
    for a, b in itertools.combinations(POLICY_ARMS, 2):
        diffs = np.array([rescored(arms[a], objective) - rescored(arms[b], objective) for arms in trials.values()])
        results[f"{a}_minus_{b}"] = paired_comparison(diffs)
    adjusted = holm({name: r["wilcoxon_p"] for name, r in results.items()})
    for name, p in adjusted.items():
        results[name]["wilcoxon_p_holm"] = p
    for baseline in BASELINE_ARMS:
        for arm in POLICY_ARMS:
            diffs = np.array([rescored(arms[arm], objective) - rescored(arms[baseline], objective) for arms in trials.values()])
            results[f"{arm}_minus_{baseline}"] = paired_comparison(diffs)
    return results


def action_disagreement(trials: dict[tuple[str, int], dict[str, dict[str, Any]]]) -> dict[str, Any]:
    """How often two policies choose different actions on the same trial --
    the direct answer to whether the arms are independent mechanisms."""
    out: dict[str, Any] = {}
    n = len(trials)
    for a, b in itertools.combinations(POLICY_ARMS, 2):
        differing = sum(1 for arms in trials.values() if arms[a]["action"] != arms[b]["action"])
        out[f"{a}_vs_{b}"] = {"trials": n, "different_action": differing, "rate": differing / n if n else None}
    out["all_three_identical"] = sum(
        1 for arms in trials.values() if len({arms[a]["action"] for a in POLICY_ARMS}) == 1
    ) / n if n else None
    return out


def per_condition(trials: dict[tuple[str, int], dict[str, dict[str, Any]]], objective: Objective) -> dict[str, Any]:
    grouped: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    actions: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for (condition, _), arms in trials.items():
        for arm in POLICY_ARMS:
            grouped[condition][arm].append(rescored(arms[arm], objective))
            actions[condition][arm].add(arms[arm]["action"])
    return {
        condition: {
            arm: {"mean_utility": float(np.mean(values)), "n": len(values), "actions": sorted(actions[condition][arm])}
            for arm, values in by_arm.items()
        }
        for condition, by_arm in grouped.items()
    }


SENSITIVITY_OBJECTIVES = {
    "service_heavy": {"containment": 3.0, "service": 5.0, "intelligence": 2.0},
    "containment_heavy": {"containment": 7.0, "service": 2.0, "intelligence": 2.0},
    "no_action_cost": {"zero_cost": True},
}


def sensitivity(trials: dict[tuple[str, int], dict[str, dict[str, Any]]], base: Objective) -> dict[str, Any]:
    """Re-score the SAME measured outcomes under alternative weightings: does
    the arm ordering depend on the declared objective?"""
    out: dict[str, Any] = {}
    for name, spec in SENSITIVITY_OBJECTIVES.items():
        if spec.get("zero_cost"):
            objective = Objective(base.containment, base.service, base.intelligence, {a: 0.0 for a in DefenseAction})
        else:
            objective = Objective(spec["containment"], spec["service"], spec["intelligence"], base.action_cost)
        means = {
            arm: float(np.mean([rescored(arms[arm], objective) for arms in trials.values()])) for arm in ALL_ARMS
        }
        out[name] = {"mean_utility": means, "ranking": sorted(ALL_ARMS, key=lambda arm: -means[arm])}
    return out


def prior_vs_measured(table_rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Stackelberg's a-priori containment prior vs mean measured containment,
    per (action, attack class), from the outcome table."""
    from iot_defense.evaluation.outcome import Measurement

    model = load_policy_section("game_model")
    attack_class = model["attack_class"]
    measured: dict[tuple[str, str], list[float]] = defaultdict(list)
    for row in table_rows:
        m = Measurement.from_row(row)
        if m.valid and m.is_attack:
            measured[(m.action.value, attack_class[m.condition])].append(m.containment)
    cells = []
    for (action, klass), values in sorted(measured.items()):
        prior = float(model["containment_prior"].get(action, {}).get(klass, 0.0))
        mean = float(np.mean(values))
        cells.append({"action": action, "class": klass, "prior": prior, "measured": mean, "n": len(values), "abs_error": abs(prior - mean)})
    return {
        "mean_abs_error": float(np.mean([c["abs_error"] for c in cells])) if cells else None,
        "cells": cells,
    }


def build_report(results_path: str | Path, table_path: str | Path | None = None) -> dict[str, Any]:
    objective = Objective.load()
    rows = load_jsonl(results_path)
    trials, excluded = paired_trials(rows)
    if not trials:
        raise ValueError("no trial has a valid measurement for every arm")
    report: dict[str, Any] = {
        "results": str(results_path),
        "objective": {
            "containment": objective.containment, "service": objective.service, "intelligence": objective.intelligence,
            "action_cost": {a.value: c for a, c in objective.action_cost.items()},
        },
        "paired_trials": len(trials),
        "excluded_trials_invalid_measurement": excluded,
        "detection_accuracy": float(np.mean([arms["rule_based"]["detection_correct"] for arms in trials.values()])),
        "arms": arm_summary(trials, objective),
        "pairwise": pairwise(trials, objective),
        "action_disagreement": action_disagreement(trials),
        "per_condition": per_condition(trials, objective),
        "sensitivity": sensitivity(trials, objective),
    }
    if table_path is not None:
        report["stackelberg_prior_vs_measured_containment"] = prior_vs_measured(load_jsonl(table_path))
    return report


def render_markdown(report: dict[str, Any]) -> str:
    def ci(pair: list[float]) -> str:
        return f"[{pair[0]:.2f}, {pair[1]:.2f}]"

    lines = [
        "# Measured-outcome evaluation",
        "",
        f"Source `{report['results']}`: {report['paired_trials']} paired trials "
        f"({report['excluded_trials_invalid_measurement']} excluded for an unreadable probe). "
        f"Detection accuracy {report['detection_accuracy'] * 100:.1f}% (shared by all arms; not a policy metric).",
        "",
        "Utility = containment x measured containment + service x measured service + intelligence x verified intel "
        "- action cost; weights in `config/policies.yaml` `policy.objective`. 95% CIs are bootstrap over trials.",
        "",
        "| Arm | Mean utility | 95% CI | Containment (attacks) | Service loss | Intel (attacks) | Exec failures |",
        "|---|---|---|---|---|---|---|",
    ]
    for arm in ALL_ARMS:
        s = report["arms"][arm]
        lines.append(
            f"| {arm} | {s['mean_utility']:.3f} | {ci(s['mean_utility_ci95'])} | "
            f"{(s['mean_containment_on_attacks'] or 0) * 100:.1f}% | {s['mean_service_loss'] * 100:.1f}% | "
            f"{(s['intel_verified_rate_on_attacks'] or 0) * 100:.1f}% | {s['execution_failure_rate'] * 100:.1f}% |"
        )
    lines += ["", "## Paired utility differences", "",
              "| Comparison | Mean diff | 95% CI | Wilcoxon p | Holm p | Sign-test p | Non-tied trials |", "|---|---|---|---|---|---|---|"]
    for name, r in report["pairwise"].items():
        holm_p = f"{r['wilcoxon_p_holm']:.4g}" if "wilcoxon_p_holm" in r else "--"
        lines.append(
            f"| {name} | {r['mean_diff']:+.3f} | {ci(r['mean_diff_ci95'])} | {r['wilcoxon_p']:.4g} | {holm_p} | "
            f"{r['sign_test_p']:.4g} | {r['n_nonzero']}/{r['n_trials']} |"
        )
    lines += ["", "## Do the policies choose different actions?", "", "| Pair | Trials with different actions |", "|---|---|"]
    for name, r in report["action_disagreement"].items():
        if isinstance(r, dict):
            lines.append(f"| {name} | {r['different_action']}/{r['trials']} ({r['rate'] * 100:.1f}%) |")
    lines.append(f"\nAll three identical on {report['action_disagreement']['all_three_identical'] * 100:.1f}% of trials.")
    lines += ["", "## Sensitivity: same measurements, other objective weights", "", "| Weighting | Ranking (best first) |", "|---|---|"]
    for name, r in report["sensitivity"].items():
        lines.append(f"| {name} | {' > '.join(r['ranking'])} |")
    prior = report.get("stackelberg_prior_vs_measured_containment")
    if prior and prior["mean_abs_error"] is not None:
        lines.append(f"\nStackelberg containment prior vs measured: mean absolute error {prior['mean_abs_error']:.3f} over {len(prior['cells'])} (action, class) cells.")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", default="data/evaluation/results.jsonl")
    parser.add_argument("--table", default="data/outcomes/outcome_table.jsonl")
    parser.add_argument("--json-output", default="data/evaluation/outcome_report.json")
    parser.add_argument("--markdown-output", default="data/evaluation/outcome_report.md")
    args = parser.parse_args()
    table = args.table if Path(args.table).exists() else None
    report = build_report(args.results, table)
    Path(args.json_output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    Path(args.markdown_output).write_text(render_markdown(report), encoding="utf-8")
    print(render_markdown(report))


if __name__ == "__main__":
    main()
