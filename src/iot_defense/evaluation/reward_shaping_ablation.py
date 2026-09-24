"""PPO reward-shaping ablation: does the project's real, multi-tier reward
(different magnitudes for different kinds of success/failure -- e.g. letting
an attack through unopposed is penalized far more than choosing a merely
suboptimal-but-still-defensive response) matter, or would a flat
correct/incorrect signal train just as well? Trains the real
DefenseDecisionEnv under both reward configurations, holding the rest of the
validated recipe and a fixed seed sweep constant, and compares convergence
rate the same way ppo_seed_robustness.py already does -- reusing that
module's own convergence check rather than reimplementing it.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from stable_baselines3 import PPO as _PPO

from iot_defense.defense.ppo_env import (
    TRAINING_SCENARIOS,
    DefenseDecisionEnv,
    RewardConfig,
    load_ppo_training_config,
)
from iot_defense.evaluation.ppo_seed_robustness import _mismatches_for_model
from iot_defense.evaluation.report import _wilson_ci

DEFAULT_SEEDS: tuple[int, ...] = (1, 2, 3, 7, 42)

# The project's real, deployed reward (see config/policies.yaml's own
# `reward` block, read via load_ppo_training_config()) gives different
# magnitudes to different outcomes -- e.g. successful_compromise (-6, an
# attack let through) is penalized twice as hard as service_disruption (-3,
# a wrong-but-still-defensive response). The flat variant collapses every
# "correct" outcome to the same reward and every "incorrect" outcome to the
# same penalty, removing that differentiation while keeping the same
# overall reward scale (see calculate_reward() in ppo_env.py for exactly
# which fields combine for which outcome).
FLAT_REWARD_OVERRIDE = {
    "attack_contained": 1.0,
    "attacker_diverted": 0.5,
    "intelligence_gained": 0.5,
    "service_preserved": 1.0,
    "successful_compromise": -1.0,
    "false_positive_intervention": -1.0,
    "unnecessary_isolation": 0.0,
    "service_disruption": -1.0,
    "response_cost": 0.0,
}


def _train_and_check(seed: int, reward_config: RewardConfig, scratch_dir: str, tag: str) -> dict[str, Any]:
    ppo_config = load_ppo_training_config()
    episode_length = max(
        int(ppo_config.get("environment_episode_length", len(TRAINING_SCENARIOS()))),
        len(TRAINING_SCENARIOS()),
    )
    environment = DefenseDecisionEnv(episode_length=episode_length, reward_config=reward_config)
    model = _PPO(
        "MlpPolicy", environment, policy_kwargs={"net_arch": [64, 64]},
        n_steps=170, batch_size=170, learning_rate=0.001, ent_coef=0.01,
        device="cpu", verbose=0, seed=seed,
    )
    model.learn(total_timesteps=int(ppo_config.get("training_timesteps", 25500)))
    output_path = f"{scratch_dir}/{tag}_seed_{seed}"
    model.save(output_path)

    mismatches = _mismatches_for_model(output_path)
    row = {
        "reward_config": tag,
        "seed": seed,
        "fully_converged": len(mismatches) == 0,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
    }
    print(f"[reward_shaping_ablation] {tag} seed={seed} mismatches={len(mismatches)}", flush=True)
    return row


def run(seeds: tuple[int, ...] = DEFAULT_SEEDS, scratch_dir: str = "/tmp/reward_shaping_sweep") -> list[dict[str, Any]]:
    Path(scratch_dir).mkdir(parents=True, exist_ok=True)
    ppo_config = load_ppo_training_config()
    shaped_reward = RewardConfig.from_mapping(ppo_config.get("reward", {}))
    flat_reward = RewardConfig.from_mapping(FLAT_REWARD_OVERRIDE)

    rows: list[dict[str, Any]] = []
    for seed in seeds:
        rows.append(_train_and_check(seed, shaped_reward, scratch_dir, "shaped"))
    for seed in seeds:
        rows.append(_train_and_check(seed, flat_reward, scratch_dir, "flat"))
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_config: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_config.setdefault(row["reward_config"], []).append(row)
    summary = {}
    for tag, sub in by_config.items():
        n = len(sub)
        converged = sum(1 for r in sub if r["fully_converged"])
        summary[tag] = {
            "seeds_tested": n,
            "fully_converged_count": converged,
            "fully_converged_rate": round(converged / n, 4) if n else None,
            "fully_converged_rate_ci95": _wilson_ci(converged, n),
            "mean_mismatch_count": round(sum(r["mismatch_count"] for r in sub) / n, 3) if n else None,
        }
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="data/evaluation/reward_shaping_ablation.jsonl")
    parser.add_argument("--summary-output", default="data/evaluation/reward_shaping_ablation.summary.json")
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
