"""Where do the three strategies actually differ? Two generalisation tests.

On the measured table the rule-based arm is clearly worse, but Stackelberg and
PPO converge on the same action in most conditions because one action
dominates, so the comparison says little about them. These tests remove that
shortcut without any new live measurement:

1. Leave-one-out. PPO is trained on the outcome table with one attack's rows
   (`attack` mode) or every attack of one mechanism class's rows (`class`
   mode) removed entirely, then asked what to do about the attack it never
   saw. Stackelberg never reads the table, so it is the control; the arbiter's
   evidence has no rows for the held-out attack, so it falls back to
   Stackelberg by design. Held-out regret is scored against the measured
   table, which the held-out policies never saw.

2. Objective shift. The operator's weights change (all four shifts are fixed
   in OBJECTIVE_SHIFTS before any result is looked at). The measured rows are
   raw (packets, service loss, intelligence), so the table is re-scored under
   the new objective exactly, with no new measurement. Stackelberg rebuilds
   its payoffs from its priors; PPO is either left stale (trained for the old
   objective) or retrained; the arbiter's evidence is re-scored immediately.

Honest limits, stated here so a reader does not have to find them: Stackelberg
is not blind in a strict sense (its priors were written by people who knew how
the responses work); the retrained PPO is scored on the same table it learned
from, so it is an in-sample upper bound; canonical (noise-free) contexts are
used for every decision; conditions are the unit of analysis, so n is 20.
"""

from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import numpy as np

from iot_defense.defense.arbiter import ArbiterPolicy
from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.game_model import build_game_payoffs
from iot_defense.defense.objective import Objective, load_policy_section
from iot_defense.defense.policy import RuleBasedDefensePolicy, StackelbergDefensePolicy
from iot_defense.defense.ppo_env import TRAINING_SCENARIOS, context_for_scenario
from iot_defense.defense.ppo_policy import PPODefensePolicy
from iot_defense.defense.stackelberg import StackelbergGame
from iot_defense.evaluation.outcome import OutcomeTable
from iot_defense.evaluation.outcome_report import bootstrap_mean_ci, paired_comparison

DEFAULT_TABLE = "data/outcomes/outcome_table.jsonl"
DEFAULT_RESULTS = "data/evaluation/generalization.jsonl"
DEFAULT_SCRATCH = "/tmp/generalization"

# Fixed before any result was inspected. Each is a plausible operator
# preference, expressed as a change to the base objective (5 / 3 / 2, costs).
OBJECTIVE_SHIFTS: dict[str, Any] = {
    "service_critical": lambda o: replace(o, service=o.service * 3),  # the device must stay up
    "intelligence_priority": lambda o: replace(o, intelligence=o.intelligence * 4),  # a research honeypot
    "cost_averse": lambda o: replace(o, action_cost={a: c * 4 for a, c in o.action_cost.items()}),
    "security_first": lambda o: replace(o, containment=o.containment * 1.6, service=o.service / 3),
}
SHIFT_DESCRIPTIONS = {
    "service_critical": "service weight x3 (the protected device must stay reachable)",
    "intelligence_priority": "intelligence weight x4 (a research honeypot)",
    "cost_averse": "every action cost x4 (operations-averse)",
    "security_first": "containment x1.6 and service /3 (collateral damage is acceptable)",
}


# ── Tasks ─────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Task:
    kind: str  # "attack" | "class" | "shift"
    name: str
    seed: int

    @property
    def id(self) -> str:
        return f"{self.kind}:{self.name}:s{self.seed}"


def attack_conditions() -> tuple[str, ...]:
    return tuple(c for c in TRAINING_SCENARIOS() if c != "normal")


def condition_classes() -> dict[str, str]:
    mapping = load_policy_section("game_model")["attack_class"]
    return {condition: mapping[condition] for condition in attack_conditions()}


def class_members() -> dict[str, tuple[str, ...]]:
    members: dict[str, list[str]] = defaultdict(list)
    for condition, klass in condition_classes().items():
        members[klass].append(condition)
    return {klass: tuple(items) for klass, items in members.items()}


def holdout_for(task: Task) -> tuple[str, ...]:
    if task.kind == "attack":
        return (task.name,)
    if task.kind == "class":
        return class_members()[task.name]
    return ()


def enumerate_tasks(seeds: tuple[int, ...]) -> list[Task]:
    """One training run per (held-out attack | held-out class | objective shift) and seed.
    A class with a single attack is the same experiment as leaving that attack out, so
    only multi-attack classes get their own run."""
    tasks: list[Task] = []
    for seed in seeds:
        tasks += [Task("attack", c, seed) for c in attack_conditions()]
        tasks += [Task("class", k, seed) for k, items in class_members().items() if len(items) > 1]
        tasks += [Task("shift", name, seed) for name in OBJECTIVE_SHIFTS]
    return tasks


# ── Running ───────────────────────────────────────────────────────────────────
def load_rows(path: str | Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def objective_for(task: Task, base: Objective) -> Objective:
    return OBJECTIVE_SHIFTS[task.name](base) if task.kind == "shift" else base


def decide_all(policy: Any) -> dict[str, str]:
    """The action `policy` picks for the canonical observation of every condition."""
    return {c: policy.decide(context_for_scenario(c)).action.value for c in TRAINING_SCENARIOS()}


def run_task(task: Task, rows: list[dict[str, Any]], base: Objective, *, timesteps: int, scratch: str) -> dict[str, Any]:
    from iot_defense.simulation.train_ppo import train_on_table

    holdout = holdout_for(task)
    training_conditions = tuple(c for c in TRAINING_SCENARIOS() if c not in holdout)
    # Held-out rows are removed from the training table entirely, not just never drawn.
    visible = [row for row in rows if row["condition"] not in holdout]
    objective = objective_for(task, base)
    table = OutcomeTable(visible, objective)
    path = f"{scratch}/{task.kind}_{task.name}_s{task.seed}"
    info = train_on_table(
        table,
        total_timesteps=timesteps,
        output_path=path,
        seed=task.seed,
        conditions=training_conditions,
        reward_scale=objective.max_utility,
    )
    choices = decide_all(PPODefensePolicy(model_path=path))
    return {
        "task": task.id,
        "kind": task.kind,
        "name": task.name,
        "seed": task.seed,
        "holdout": list(holdout),
        "timesteps": timesteps,
        "training_seconds": info["training_seconds"],
        "choices": choices,
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }


def completed_ids(path: str | Path) -> set[str]:
    path = Path(path)
    return {json.loads(line)["task"] for line in path.read_text(encoding="utf-8").splitlines() if line.strip()} if path.exists() else set()


def run(
    tasks: list[Task],
    *,
    table_path: str | Path,
    results_path: str | Path,
    timesteps: int,
    scratch: str,
    worker: int = 0,
    workers: int = 1,
) -> None:
    """Run this worker's share of `tasks`, skipping any already recorded (so a
    reboot or a reload loses at most the run in flight)."""
    rows = load_rows(table_path)
    base = Objective.load()
    Path(results_path).parent.mkdir(parents=True, exist_ok=True)
    Path(scratch).mkdir(parents=True, exist_ok=True)
    mine = [t for i, t in enumerate(tasks) if i % workers == worker]
    for position, task in enumerate(mine, 1):
        if task.id in completed_ids(results_path):
            continue
        record = run_task(task, rows, base, timesteps=timesteps, scratch=scratch)
        with Path(results_path).open("a", encoding="utf-8") as fh:  # one short line: atomic enough on Linux
            fh.write(json.dumps(record) + "\n")
        print(f"[generalization] worker {worker}: {position}/{len(mine)} {task.id} ({record['training_seconds']}s)", flush=True)


# ── Analysis ──────────────────────────────────────────────────────────────────
def _decision(action: str) -> DefenseDecision:
    return DefenseDecision.create(
        action=DefenseAction(action), target_ip="10.0.0.10", source_ip="10.0.0.100", reason="proposal",
        confidence=0.0, threat_score=0.0, policy_name="proposal", context={},
    )


def regret(table: OutcomeTable, condition: str, action: str) -> float:
    return table.mean(condition, table.best_action(condition)) - table.mean(condition, DefenseAction(action))


def rule_choices() -> dict[str, str]:
    return decide_all(RuleBasedDefensePolicy())


def stackelberg_choices(objective: Objective) -> dict[str, str]:
    return decide_all(StackelbergDefensePolicy(StackelbergGame(build_game_payoffs(objective=objective))))


def best_fixed_action(table: OutcomeTable, conditions: tuple[str, ...]) -> str:
    """The single action with the best mean utility over `conditions`: the
    'one default for everything' baseline a trivial design would use."""
    return max(DefenseAction, key=lambda a: np.mean([table.mean(c, a) for c in conditions])).value


def arbiter_choice(table: OutcomeTable, condition: str, proposals: dict[str, str]) -> str:
    arbiter = ArbiterPolicy(table)
    return arbiter.arbitrate(condition, {name: _decision(action) for name, action in proposals.items()}).action.value


def _mean_over_seeds(per_seed: list[float]) -> float:
    return float(np.mean(per_seed))


def analyze_holdouts(rows: list[dict[str, Any]], records: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    """Held-out regret per attack (kind="attack") or per class (kind="class") for
    every arm, scored against the measured table (base objective)."""
    base = Objective.load()
    full = OutcomeTable(rows, base)
    rule, stack = rule_choices(), stackelberg_choices(base)
    selected = [r for r in records if r["kind"] == kind]
    by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in selected:
        by_name[record["name"]].append(record)

    per_unit: dict[str, dict[str, Any]] = {}
    for name, seeds in sorted(by_name.items()):
        holdout = tuple(seeds[0]["holdout"])
        visible = OutcomeTable([row for row in rows if row["condition"] not in holdout], base)
        training = tuple(c for c in TRAINING_SCENARIOS() if c not in holdout)
        fixed = best_fixed_action(visible, training)
        cells = []
        for condition in holdout:
            ppo_actions = [record["choices"][condition] for record in seeds]
            arbiter_actions = [
                arbiter_choice(visible, condition, {"rule_based": rule[condition], "stackelberg": stack[condition], "ppo": a})
                for a in ppo_actions
            ]
            cells.append(
                {
                    "condition": condition,
                    "best_measured": full.best_action(condition).value,
                    "rule_based": {"action": rule[condition], "regret": regret(full, condition, rule[condition])},
                    "stackelberg": {"action": stack[condition], "regret": regret(full, condition, stack[condition])},
                    "ppo_heldout": {
                        "actions": ppo_actions,
                        "regret": _mean_over_seeds([regret(full, condition, a) for a in ppo_actions]),
                    },
                    "arbiter": {
                        "actions": arbiter_actions,
                        "regret": _mean_over_seeds([regret(full, condition, a) for a in arbiter_actions]),
                    },
                    "best_fixed": {"action": fixed, "regret": regret(full, condition, fixed)},
                }
            )
        per_unit[name] = {"holdout": list(holdout), "seeds": [r["seed"] for r in seeds], "cells": cells}

    flat = [cell for unit in per_unit.values() for cell in unit["cells"]]
    if not flat:
        return {"units": per_unit, "summary": None}
    arms = ("rule_based", "stackelberg", "ppo_heldout", "arbiter", "best_fixed")
    regrets = {arm: np.array([c[arm]["regret"] for c in flat]) for arm in arms}
    summary: dict[str, Any] = {
        "n_conditions": len(flat),
        "mean_regret": {arm: float(v.mean()) for arm, v in regrets.items()},
        "mean_regret_ci95": {arm: list(bootstrap_mean_ci(v)) for arm, v in regrets.items()},
        "picks_measured_best": {
            arm: int(sum(np.isclose(c[arm]["regret"], 0.0) for c in flat)) for arm in arms
        },
        "stackelberg_vs_ppo": paired_comparison(regrets["ppo_heldout"] - regrets["stackelberg"]),
        "stackelberg_better_equal_worse": [
            int((regrets["stackelberg"] < regrets["ppo_heldout"] - 1e-9).sum()),
            int((np.abs(regrets["stackelberg"] - regrets["ppo_heldout"]) <= 1e-9).sum()),
            int((regrets["stackelberg"] > regrets["ppo_heldout"] + 1e-9).sum()),
        ],
    }
    return {"units": per_unit, "summary": summary}


def analyze_shifts(
    rows: list[dict[str, Any]], records: list[dict[str, Any]], stale_choices: list[dict[str, str]]
) -> dict[str, Any]:
    """Per shift and arm, mean regret over all 21 conditions under the SHIFTED
    objective (the measured rows re-scored exactly)."""
    base = Objective.load()
    base_table = OutcomeTable(rows, base)
    rule = rule_choices()
    stack_stale = stackelberg_choices(base)
    out: dict[str, Any] = {}
    for name in OBJECTIVE_SHIFTS:
        objective = OBJECTIVE_SHIFTS[name](base)
        table = OutcomeTable(rows, objective)
        retrained = [r["choices"] for r in records if r["kind"] == "shift" and r["name"] == name]
        stack = stackelberg_choices(objective)
        conditions = TRAINING_SCENARIOS()
        fixed = best_fixed_action(table, conditions)

        def mean_regret(actions_by_condition: dict[str, str]) -> float:
            return float(np.mean([regret(table, c, actions_by_condition[c]) for c in conditions]))

        def mean_over(choice_sets: list[dict[str, str]]) -> float | None:
            return float(np.mean([mean_regret(c) for c in choice_sets])) if choice_sets else None

        def arbiter_set(ppo: dict[str, str]) -> dict[str, str]:
            return {c: arbiter_choice(table, c, {"rule_based": rule[c], "stackelberg": stack[c], "ppo": ppo[c]}) for c in conditions}

        out[name] = {
            "description": SHIFT_DESCRIPTIONS[name],
            "optimum_changed_in": int(sum(base_table.best_action(c) != table.best_action(c) for c in conditions)),
            "mean_regret": {
                "rule_based": mean_regret(rule),
                "stackelberg_rebuilt": mean_regret(stack),
                "stackelberg_stale": mean_regret(stack_stale),
                "ppo_stale": mean_over(stale_choices),
                "ppo_retrained": mean_over(retrained),
                "arbiter_with_stale_ppo": mean_over([arbiter_set(c) for c in stale_choices]),
                "arbiter_with_retrained_ppo": mean_over([arbiter_set(c) for c in retrained]),
                "best_fixed_action": mean_regret({c: fixed for c in conditions}),
            },
            "best_fixed_action": fixed,
            "n_seeds": {"stale": len(stale_choices), "retrained": len(retrained)},
            "stackelberg_vs_ppo_stale_disagree_in": (
                int(sum(stack[c] != stale_choices[0][c] for c in conditions)) if stale_choices else None
            ),
        }
    return out


def offline_consistency(rows: list[dict[str, Any]], harness_path: str | Path, ppo_choices: dict[str, str]) -> dict[str, Any]:
    """Do canonical-context decisions reproduce what the live harness's arms chose?
    (They are the decisions every analysis above is built from.)"""
    modal: dict[str, dict[str, str]] = defaultdict(dict)
    counts: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for row in load_rows(harness_path):
        if row["arm"] in ("rule_based", "stackelberg", "ppo"):
            counts[(row["condition"], row["arm"])][row["action"]] += 1
    for (condition, arm), actions in counts.items():
        modal[arm][condition] = max(actions, key=actions.get)
    offline = {"rule_based": rule_choices(), "stackelberg": stackelberg_choices(Objective.load()), "ppo": ppo_choices}
    return {
        arm: {"agree": int(sum(offline[arm][c] == modal[arm][c] for c in modal[arm])), "of": len(modal[arm])}
        for arm in offline
    }


def load_full_choices(model_paths: list[str]) -> list[dict[str, str]]:
    return [decide_all(PPODefensePolicy(model_path=path)) for path in model_paths]


def build_report(
    table_path: str | Path, results_path: str | Path, harness_path: str | Path, full_models: list[str]
) -> dict[str, Any]:
    rows = load_rows(table_path)
    records = [json.loads(line) for line in Path(results_path).read_text(encoding="utf-8").splitlines() if line.strip()]
    stale = load_full_choices(full_models)
    return {
        "runs_recorded": len(records),
        "leave_one_attack_out": analyze_holdouts(rows, records, "attack"),
        "leave_one_class_out": analyze_holdouts(rows, records, "class"),
        "objective_shift": analyze_shifts(rows, records, stale),
        "offline_vs_live_consistency": offline_consistency(rows, harness_path, stale[0]) if Path(harness_path).exists() else None,
        "full_models": full_models,
    }


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def render_markdown(report: dict[str, Any]) -> str:
    lines = ["# Generalisation tests: where the three strategies differ", ""]
    for title, key in (("Leave-one-attack-out", "leave_one_attack_out"), ("Leave-one-class-out", "leave_one_class_out")):
        block = report[key]
        summary = block["summary"]
        lines += [f"## {title}", ""]
        if summary is None:
            lines += ["No runs recorded yet.", ""]
            continue
        lines += [
            f"{summary['n_conditions']} held-out attacks. Mean regret against the measured table (lower is better; "
            "0 means the measured-best action):", "",
            "| Arm | Mean regret [95% CI] | Picks the measured-best |", "|---|---|---|",
        ]
        for arm, label in (("rule_based", "Rule-based"), ("stackelberg", "Stackelberg"), ("ppo_heldout", "PPO (never saw it)"),
                           ("arbiter", "Arbiter"), ("best_fixed", "One fixed action for all")):
            lo, hi = summary["mean_regret_ci95"][arm]
            lines.append(f"| {label} | {summary['mean_regret'][arm]:.2f} [{lo:.2f}, {hi:.2f}] | {summary['picks_measured_best'][arm]}/{summary['n_conditions']} |")
        better, equal, worse = summary["stackelberg_better_equal_worse"]
        cmp_ = summary["stackelberg_vs_ppo"]
        lines += ["", f"Stackelberg vs PPO (regret): better in {better}, equal in {equal}, worse in {worse} "
                  f"(mean difference PPO - Stackelberg {cmp_['mean_diff']:+.2f}, sign-test p = {cmp_['sign_test_p']:.3f}).", ""]
    lines += ["## Objective shift", "", "Mean regret over all 21 conditions under the shifted objective (lower is better).", "",
              "| Shift | Optimum changed in | Rule-based | Stackelberg rebuilt | Stackelberg stale | PPO stale | PPO retrained | Arbiter + stale PPO | One fixed action |",
              "|---|---|---|---|---|---|---|---|---|"]
    for name, entry in report["objective_shift"].items():
        m = entry["mean_regret"]
        lines.append(f"| {name} | {entry['optimum_changed_in']} | {_fmt(m['rule_based'])} | {_fmt(m['stackelberg_rebuilt'])} | "
                     f"{_fmt(m['stackelberg_stale'])} | {_fmt(m['ppo_stale'])} | {_fmt(m['ppo_retrained'])} | "
                     f"{_fmt(m['arbiter_with_stale_ppo'])} | {_fmt(m['best_fixed_action'])} |")
    lines += ["", "Shift definitions: " + "; ".join(f"{k}: {v}" for k, v in SHIFT_DESCRIPTIONS.items()) + ".", ""]
    consistency = report.get("offline_vs_live_consistency")
    if consistency:
        lines += ["Canonical-context decisions vs the live harness's modal choices: "
                  + ", ".join(f"{arm} {v['agree']}/{v['of']}" for arm, v in consistency.items()) + ".", ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run_p = sub.add_parser("run", help="train this worker's share of the held-out / shifted PPO models")
    run_p.add_argument("--table", default=DEFAULT_TABLE)
    run_p.add_argument("--results", default=DEFAULT_RESULTS)
    run_p.add_argument("--scratch", default=DEFAULT_SCRATCH)
    run_p.add_argument("--seeds", type=int, nargs="+", default=[1])
    run_p.add_argument("--timesteps", type=int, default=None, help="default: policy.ppo.training_timesteps")
    run_p.add_argument("--worker", type=int, default=0)
    run_p.add_argument("--workers", type=int, default=1)
    an_p = sub.add_parser("analyze", help="score the recorded runs and write the report")
    an_p.add_argument("--table", default=DEFAULT_TABLE)
    an_p.add_argument("--results", default=DEFAULT_RESULTS)
    an_p.add_argument("--harness", default="data/evaluation/results_measured.jsonl")
    an_p.add_argument("--full-model", action="append", default=None,
                      help="a PPO trained on the complete table; repeat for more seeds (the 'stale' model under a shift)")
    an_p.add_argument("--output", default="data/evaluation/generalization_report.json")
    args = parser.parse_args()

    if args.command == "run":
        timesteps = args.timesteps or int(load_policy_section("ppo")["training_timesteps"])
        run(enumerate_tasks(tuple(args.seeds)), table_path=args.table, results_path=args.results, timesteps=timesteps,
            scratch=args.scratch, worker=args.worker, workers=args.workers)
        return
    report = build_report(args.table, args.results, args.harness, args.full_model or ["models/ppo_defense"])
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    markdown = render_markdown(report)
    Path(args.output).with_suffix(".md").write_text(markdown + "\n", encoding="utf-8")
    print(markdown)


if __name__ == "__main__":
    main()
