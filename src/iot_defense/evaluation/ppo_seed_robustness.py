"""PPO synthetic-training seed-robustness sweep: how often does the
project's own training recipe converge every scenario to its registered
preferred_action across different random seeds, not just this project's
own hardcoded seed=7?

Trains N independent models (fast, deterministic, no Mininet -- each run
is a few tens of seconds) at the exact recipe train_ppo.py actually uses,
varying only the seed, and checks each one's convergence the same way
tests/test_ppo.py's own regression test does. Reports the aggregate
success rate with a Wilson confidence interval, not a single anecdote --
this is what a methods section can actually cite instead of "we found a
good seed."
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from iot_defense.attacks.registry import ATTACK_SCENARIOS
from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.ppo_env import context_for_scenario
from iot_defense.defense.ppo_policy import PPODefensePolicy
from iot_defense.evaluation.report import _wilson_ci
from iot_defense.simulation.train_ppo import train

DEFAULT_SEEDS: tuple[int, ...] = (1, 2, 3, 7, 13, 17, 42, 55, 88, 99)


def _mismatches_for_model(model_path: str) -> list[tuple[str, str, str]]:
    policy = PPODefensePolicy(model_path=model_path)
    mismatches = []
    normal_decision = policy.decide(context_for_scenario("normal"))
    if normal_decision.action != DefenseAction.ALLOW:
        mismatches.append(("normal", normal_decision.action.name, "ALLOW"))
    for key, scenario in ATTACK_SCENARIOS.items():
        decision = policy.decide(context_for_scenario(scenario.attack_type))
        if decision.action != scenario.preferred_action:
            mismatches.append((key, decision.action.name, scenario.preferred_action.name))
    return mismatches


def run(seeds: tuple[int, ...] = DEFAULT_SEEDS, scratch_dir: str = "/tmp/ppo_seed_sweep") -> list[dict[str, Any]]:
    Path(scratch_dir).mkdir(parents=True, exist_ok=True)
    rows = []
    for seed in seeds:
        output_path = f"{scratch_dir}/seed_{seed}"
        # train_ppo.py's own PPO(..., seed=7) is hardcoded; reproduce its
        # exact recipe here with only the seed varied, by monkeypatching
        # is riskier than it looks, so instead call the real training
        # internals the same way tests/test_ppo.py's own regression test
        # does, via a thin, explicit seed override.
        from stable_baselines3 import PPO as _PPO
        from iot_defense.defense.ppo_env import TRAINING_SCENARIOS, DefenseDecisionEnv, RewardConfig, load_ppo_training_config

        ppo_config = load_ppo_training_config()
        episode_length = max(int(ppo_config.get("environment_episode_length", len(TRAINING_SCENARIOS()))), len(TRAINING_SCENARIOS()))
        reward_config = RewardConfig.from_mapping(ppo_config.get("reward", {}))
        environment = DefenseDecisionEnv(episode_length=episode_length, reward_config=reward_config)
        model = _PPO(
            "MlpPolicy", environment, policy_kwargs={"net_arch": [64, 64]},
            n_steps=170, batch_size=170, learning_rate=0.001, ent_coef=0.01,
            device="cpu", verbose=0, seed=seed,
        )
        model.learn(total_timesteps=int(ppo_config.get("training_timesteps", 25500)))
        model.save(output_path)

        mismatches = _mismatches_for_model(output_path)
        rows.append({
            "seed": seed,
            "fully_converged": len(mismatches) == 0,
            "mismatch_count": len(mismatches),
            "mismatches": mismatches,
        })
        print(f"[seed_robustness] seed={seed} mismatches={len(mismatches)} {mismatches}", flush=True)
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(rows)
    converged = sum(1 for r in rows if r["fully_converged"])
    ci = _wilson_ci(converged, n)
    return {
        "seeds_tested": n,
        "fully_converged_count": converged,
        "fully_converged_rate": round(converged / n, 4) if n else None,
        "fully_converged_rate_ci95": ci,
        "mean_mismatch_count": round(sum(r["mismatch_count"] for r in rows) / n, 3) if n else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="data/evaluation/ppo_seed_robustness.jsonl")
    parser.add_argument("--summary-output", default="data/evaluation/ppo_seed_robustness.summary.json")
    args = parser.parse_args()

    rows = run()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")

    summary = summarize(rows)
    Path(args.summary_output).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
