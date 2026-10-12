"""PPO seed-robustness sweep on measured outcomes.

Trains N independent PPO models from the measured outcome table, varying
only the seed, and scores each by REGRET against the table: for every
condition, how much measured mean utility the model's chosen action leaves
on the table relative to the best measured action. Nothing here consults a
registered preferred_action.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np

from iot_defense.defense.ppo_env import TRAINING_SCENARIOS, context_for_scenario
from iot_defense.defense.ppo_policy import PPODefensePolicy
from iot_defense.evaluation.outcome import OutcomeTable
from iot_defense.simulation.train_ppo import train

DEFAULT_SEEDS: tuple[int, ...] = (1, 2, 3, 7, 13, 17, 42, 55, 88, 99)
# A model is "near-optimal" if its mean per-condition regret is within this
# many utility units (the objective spans roughly [-1, 10]).
NEAR_OPTIMAL_REGRET = 0.25


def regret_for_model(model_path: str, table: OutcomeTable) -> dict[str, Any]:
    policy = PPODefensePolicy(model_path=model_path)
    per_condition: dict[str, dict[str, Any]] = {}
    for condition in TRAINING_SCENARIOS():
        chosen = policy.decide(context_for_scenario(condition)).action
        best = table.best_action(condition)
        per_condition[condition] = {
            "chosen": chosen.value,
            "best_measured": best.value,
            "regret": table.mean(condition, best) - table.mean(condition, chosen),
        }
    return {
        "mean_regret": float(np.mean([c["regret"] for c in per_condition.values()])),
        "max_regret": float(max(c["regret"] for c in per_condition.values())),
        "per_condition": per_condition,
    }


def run(
    table_path: str | Path,
    seeds: tuple[int, ...] = DEFAULT_SEEDS,
    scratch_dir: str = "/tmp/ppo_seed_sweep",
    timesteps: int | None = None,
) -> list[dict[str, Any]]:
    Path(scratch_dir).mkdir(parents=True, exist_ok=True)
    table = OutcomeTable.from_jsonl(table_path)
    rows = []
    for seed in seeds:
        output_path = f"{scratch_dir}/seed_{seed}"
        train(total_timesteps=timesteps, output_path=output_path, table_path=table_path, seed=seed)
        result = regret_for_model(output_path, table)
        rows.append({"seed": seed, **result})
        print(f"[seed_robustness] seed={seed} mean_regret={result['mean_regret']:.3f}", flush=True)
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    regrets = np.array([r["mean_regret"] for r in rows])
    return {
        "seeds_tested": len(rows),
        "mean_regret_mean": float(regrets.mean()),
        "mean_regret_median": float(np.median(regrets)),
        "mean_regret_worst_seed": float(regrets.max()),
        "near_optimal_seeds": int((regrets <= NEAR_OPTIMAL_REGRET).sum()),
        "near_optimal_threshold": NEAR_OPTIMAL_REGRET,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--table", default="data/outcomes/outcome_table.jsonl")
    parser.add_argument("--output", default="data/evaluation/ppo_seed_robustness.jsonl")
    parser.add_argument("--summary-output", default="data/evaluation/ppo_seed_robustness.summary.json")
    args = parser.parse_args()

    rows = run(args.table)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    summary = summarize(rows)
    Path(args.summary_output).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
