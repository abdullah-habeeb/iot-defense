"""PPO trained on the mechanism model only, graded on the measured table.

Trains PPO against ModelOutcomeTable (no measurement is read during training), then asks each trained
policy for its decision on every condition and scores that decision against the measured outcome table. The
same scoring is applied to Stackelberg, to the PPO trained on the measured table, to the rule-based policy
and to the model's own argmax (the best a defender could do if it trusted the priors exactly).

    python -m iot_defense.evaluation.model_trained_ppo --seeds 1 7 13 --timesteps 120000
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import numpy as np

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.game_model import build_game_payoffs
from iot_defense.defense.model_outcomes import ModelOutcomeTable
from iot_defense.defense.objective import Objective
from iot_defense.defense.policy import RuleBasedDefensePolicy, StackelbergDefensePolicy
from iot_defense.defense.ppo_env import TRAINING_SCENARIOS
from iot_defense.defense.ppo_policy import PPODefensePolicy
from iot_defense.defense.stackelberg import StackelbergGame
from iot_defense.evaluation.generalization import decide_all
from iot_defense.evaluation.outcome import OutcomeTable
from iot_defense.simulation.train_ppo import train_on_table


def regret(table: OutcomeTable, condition: str, action: str) -> float:
    return table.mean(condition, table.best_action(condition)) - table.mean(condition, DefenseAction(action))


def score(table: OutcomeTable, choices: dict[str, str]) -> dict[str, Any]:
    per = {c: regret(table, c, choices[c]) for c in TRAINING_SCENARIOS()}
    values = list(per.values())
    return {
        "mean_regret": float(np.mean(values)),
        "max_regret": float(max(values)),
        "picks_best": int(sum(v < 1e-9 for v in values)),
        "mean_utility": float(np.mean([table.mean(c, DefenseAction(choices[c])) for c in TRAINING_SCENARIOS()])),
        "per_condition_regret": per,
    }


def run(
    seeds: tuple[int, ...],
    timesteps: int,
    table_path: str | Path,
    output_dir: str | Path,
    noise_sigma: float,
    measured_ppo: str = "models/ppo_defense",
) -> dict[str, Any]:
    objective = Objective.load()
    measured = OutcomeTable.from_jsonl(table_path, objective)
    model_table = ModelOutcomeTable(objective=objective, noise_sigma=noise_sigma)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    arms: dict[str, list[dict[str, str]]] = {}
    arms["rule_based"] = [decide_all(RuleBasedDefensePolicy())]
    arms["stackelberg"] = [decide_all(StackelbergDefensePolicy(StackelbergGame(build_game_payoffs(objective=objective))))]
    arms["model_argmax"] = [{c: model_table.best_action(c).value for c in TRAINING_SCENARIOS()}]
    if Path(measured_ppo).with_suffix(".zip").exists():
        arms["ppo_trained_on_measured_table"] = [decide_all(PPODefensePolicy(model_path=measured_ppo))]

    training = []
    arms["ppo_trained_on_model"] = []
    for seed in seeds:
        path = out / f"ppo_model_s{seed}"
        started = time.perf_counter()
        info = train_on_table(model_table, total_timesteps=timesteps, output_path=path, seed=seed)  # type: ignore[arg-type]
        training.append({"seed": seed, "seconds": round(time.perf_counter() - started, 1), "model": info["model_path"]})
        arms["ppo_trained_on_model"].append(decide_all(PPODefensePolicy(model_path=path)))

    summary: dict[str, Any] = {}
    for arm, choice_sets in arms.items():
        scored = [score(measured, choices) for choices in choice_sets]
        summary[arm] = {
            "n_models": len(scored),
            "mean_regret": float(np.mean([s["mean_regret"] for s in scored])),
            "mean_regret_by_model": [s["mean_regret"] for s in scored],
            "max_regret": float(np.mean([s["max_regret"] for s in scored])),
            "picks_best": float(np.mean([s["picks_best"] for s in scored])),
            "mean_utility": float(np.mean([s["mean_utility"] for s in scored])),
            "per_condition_regret": {
                c: float(np.mean([s["per_condition_regret"][c] for s in scored])) for c in TRAINING_SCENARIOS()
            },
        }
    # How well did PPO learn the model it was given, independent of whether the model is right?
    learned = [
        float(np.mean([choices[c] == model_table.best_action(c).value for c in TRAINING_SCENARIOS()]))
        for choices in arms["ppo_trained_on_model"]
    ]
    agree_stack = [
        float(np.mean([choices[c] == arms["stackelberg"][0][c] for c in TRAINING_SCENARIOS()]))
        for choices in arms["ppo_trained_on_model"]
    ]
    report = {
        "timesteps": timesteps,
        "seeds": list(seeds),
        "noise_sigma": noise_sigma,
        "training": training,
        "summary": summary,
        "ppo_matches_model_argmax": learned,
        "ppo_matches_stackelberg": agree_stack,
        "choices": {arm: choice_sets for arm, choice_sets in arms.items()},
        "model_vs_measured_best": {
            c: [model_table.best_action(c).value, measured.best_action(c).value] for c in TRAINING_SCENARIOS()
        },
    }
    (out / "model_trained_ppo.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (out / "model_trained_ppo.md").write_text(render_markdown(report), encoding="utf-8")
    return report


def render_markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        "# PPO trained on the mechanism model (no measurements), graded on the measured table",
        "",
        f"{len(report['seeds'])} seeds, {report['timesteps']} timesteps each; model noise sigma {report['noise_sigma']}. "
        "Regret is against the measured table's best response (0 = best).",
        "",
        "| Arm | Models | Mean regret | Worst-case regret | Picks the measured-best (of 21) | Mean utility |",
        "|---|---|---|---|---|---|",
    ]
    order = ("rule_based", "stackelberg", "model_argmax", "ppo_trained_on_model", "ppo_trained_on_measured_table")
    for arm in order:
        if arm in s:
            v = s[arm]
            lines.append(
                f"| {arm} | {v['n_models']} | {v['mean_regret']:.3f} | {v['max_regret']:.2f} | {v['picks_best']:.1f} | {v['mean_utility']:.3f} |"
            )
    lines += [
        "",
        f"PPO reproduces the model's own best response in {np.mean(report['ppo_matches_model_argmax']) * 100:.1f}% of the 21 conditions "
        f"(per seed: {', '.join(f'{x * 100:.0f}%' for x in report['ppo_matches_model_argmax'])}), "
        f"and agrees with Stackelberg in {np.mean(report['ppo_matches_stackelberg']) * 100:.1f}%.",
        "",
        "## Per-condition regret",
        "",
        "| Condition | model best | measured best | Stackelberg | PPO (model) | PPO (measured table) |",
        "|---|---|---|---|---|---|",
    ]
    for c in TRAINING_SCENARIOS():
        measured_ppo = s.get("ppo_trained_on_measured_table", {}).get("per_condition_regret", {}).get(c)
        lines.append(
            f"| {c} | {report['model_vs_measured_best'][c][0]} | {report['model_vs_measured_best'][c][1]} "
            f"| {s['stackelberg']['per_condition_regret'][c]:.2f} | {s['ppo_trained_on_model']['per_condition_regret'][c]:.2f} "
            f"| {'' if measured_ppo is None else f'{measured_ppo:.2f}'} |"
        )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=int, nargs="+", default=[1, 7, 13])
    parser.add_argument("--timesteps", type=int, default=120000)
    parser.add_argument("--table", default="data/outcomes/outcome_table.jsonl")
    parser.add_argument("--output-dir", default="data/evaluation/model_trained_ppo")
    parser.add_argument("--noise-sigma", type=float, default=0.0)
    args = parser.parse_args()
    run(tuple(args.seeds), args.timesteps, args.table, args.output_dir, args.noise_sigma)
    print((Path(args.output_dir) / "model_trained_ppo.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
