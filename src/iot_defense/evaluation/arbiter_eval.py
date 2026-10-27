"""Score the arbiter on the held-out harness trials, without a new live run.

The arbiter only ever executes one of the three policies' proposals, and the
harness already applied and measured every distinct proposal in every trial
(arms that chose the same action share one measurement). So the arbiter's
measured utility in a trial is the utility of the arm whose proposal it
picked. Its evidence comes from the outcome table, which never contains these
held-out trials.

Also reports the best-of-three-in-hindsight utility per trial: the ceiling for
ANY rule that chooses among these three proposals, so the arbiter's gain can
be read against what was possible.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np

from iot_defense.defense.arbiter import ArbiterPolicy
from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.objective import Objective
from iot_defense.evaluation.outcome import OutcomeTable
from iot_defense.evaluation.outcome_report import (
    POLICY_ARMS,
    bootstrap_mean_ci,
    load_jsonl,
    paired_comparison,
    paired_trials,
    rescored,
)


def _proposal(row: dict[str, Any]) -> DefenseDecision:
    return DefenseDecision.create(
        action=DefenseAction(row["action"]), target_ip="10.0.0.10", source_ip="10.0.0.100", reason="harness proposal",
        confidence=0.0, threat_score=0.0, policy_name=row["arm"], context={},
    )


def evaluate(
    results_path: str | Path,
    table_path: str | Path,
    *,
    risk_aversion: float = 1.0,
    min_samples: int = 2,
) -> dict[str, Any]:
    objective = Objective.load()
    arbiter = ArbiterPolicy(OutcomeTable.from_jsonl(table_path, objective), risk_aversion=risk_aversion, min_samples=min_samples)
    trials, excluded = paired_trials(load_jsonl(results_path))
    if not trials:
        raise ValueError("no trial has a valid measurement for every arm")

    utilities: dict[str, list[float]] = {name: [] for name in (*POLICY_ARMS, "arbiter", "best_of_three")}
    chose = {name: 0 for name in POLICY_ARMS}
    differs = {name: 0 for name in POLICY_ARMS}
    no_evidence = 0
    per_condition: dict[str, dict[str, list[float]]] = {}
    for (condition, _trial), arms in trials.items():
        proposals = {name: _proposal(arms[name]) for name in POLICY_ARMS}
        label = arms["rule_based"]["detected_attack_type"]
        decision = arbiter.arbitrate(label, proposals)
        winner = decision.context["arbiter_reasoning"]["chosen_from"]
        no_evidence += decision.context["arbiter_reasoning"]["basis"] != "measured evidence"
        chose[winner] += 1
        for name in POLICY_ARMS:
            differs[name] += arms[name]["action"] != decision.action.value
            utilities[name].append(rescored(arms[name], objective))
        utilities["arbiter"].append(rescored(arms[winner], objective))
        utilities["best_of_three"].append(max(rescored(arms[name], objective) for name in POLICY_ARMS))
        per_condition.setdefault(condition, {}).setdefault("arbiter", []).append(utilities["arbiter"][-1])
        per_condition[condition].setdefault("stackelberg", []).append(utilities["stackelberg"][-1])
        per_condition[condition].setdefault("ppo", []).append(utilities["ppo"][-1])

    n = len(trials)
    arrays = {name: np.array(values) for name, values in utilities.items()}
    summary = {}
    for name, values in arrays.items():
        low, high = bootstrap_mean_ci(values)
        summary[name] = {"mean_utility": float(values.mean()), "mean_utility_ci95": [low, high]}
    return {
        "paired_trials": n,
        "excluded_trials": excluded,
        "risk_aversion": risk_aversion,
        "arms": summary,
        "arbiter_minus": {name: paired_comparison(arrays["arbiter"] - arrays[name]) for name in POLICY_ARMS},
        "best_of_three_minus_arbiter": paired_comparison(arrays["best_of_three"] - arrays["arbiter"]),
        "arbiter_chose_proposal_of": chose,
        "trials_arbiter_action_differs_from": {name: {"trials": count, "rate": count / n} for name, count in differs.items()},
        "trials_without_evidence": no_evidence,
        "conditions_where_arbiter_differs_from_stackelberg": {
            c: {"arbiter": float(np.mean(v["arbiter"])), "stackelberg": float(np.mean(v["stackelberg"])), "ppo": float(np.mean(v["ppo"]))}
            for c, v in per_condition.items()
            if abs(np.mean(v["arbiter"]) - np.mean(v["stackelberg"])) > 1e-9
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", default="data/evaluation/results_measured.jsonl")
    parser.add_argument("--table", default="data/outcomes/outcome_table.jsonl")
    parser.add_argument("--risk-aversion", type=float, default=1.0)
    parser.add_argument("--output", default="data/evaluation/arbiter_eval.json")
    args = parser.parse_args()
    report = evaluate(args.results, args.table, risk_aversion=args.risk_aversion)
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
