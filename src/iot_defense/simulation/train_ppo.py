"""CPU-only PPO training from the measured live-Mininet outcome table."""

from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Any

from stable_baselines3 import PPO

from iot_defense.defense.ppo_env import DefenseDecisionEnv, load_ppo_training_config
from iot_defense.evaluation.outcome import OutcomeTable

DEFAULT_SEED = 7


def train_on_table(
    table: OutcomeTable,
    *,
    total_timesteps: int,
    output_path: str | Path,
    seed: int = DEFAULT_SEED,
    conditions: tuple[str, ...] | None = None,
    reward_scale: float | None = None,
    label_sampler: Any = None,
    condition_weights: dict[str, float] | None = None,
) -> dict[str, float | int | str]:
    """Train and persist a PPO policy against `table`, optionally drawing only
    from `conditions` (the rest are invisible to training: never shown,
    mislabelled as, or rewarded). The shared training protocol lives here so
    the deployed model and the generalisation experiments use identical
    hyperparameters."""
    environment = DefenseDecisionEnv.from_config(
        table, conditions=conditions, reward_scale=reward_scale, label_sampler=label_sampler,
        condition_weights=condition_weights,
    )
    start = time.perf_counter()
    # gamma=0: every step draws an independent condition, so the chosen
    # action cannot affect future rewards -- a contextual bandit. With the
    # default gamma=0.99, GAE folded unrelated future rewards into every
    # advantage and the policy learned only 5 of 17 best actions. n_steps=1020
    # (not 170): with 170 the policy often collapsed onto ALLOW, which pays
    # moderately in every condition; the larger rollout gives the
    # lower-variance advantages needed to escape it (0 of 17 wrong across
    # seeds 1, 7, 13 on the synthetic table, vs 4 wrong at 170).
    model = PPO(
        "MlpPolicy",
        environment,
        policy_kwargs={"net_arch": [64, 64]},
        n_steps=1020,
        batch_size=170,
        learning_rate=0.001,
        ent_coef=0.01,
        gamma=0.0,
        device="cpu",
        verbose=0,
        seed=seed,
    )
    model.learn(total_timesteps=total_timesteps)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    model.save(str(output))
    return {
        "timesteps": total_timesteps,
        "seed": seed,
        "model_path": str(output.with_suffix(".zip")),
        "training_seconds": round(time.perf_counter() - start, 1),
    }


def train(
    total_timesteps: int | None = None,
    output_path: str | Path = "models/ppo_defense",
    table_path: str | Path | None = None,
    seed: int = DEFAULT_SEED,
) -> dict[str, float | int | str]:
    """Train and persist the deployed PPO policy against the outcome table.

    The reward is the measured realized utility of the chosen action for the
    TRUE condition (see defense/ppo_env.py); nothing here reads a registered
    preferred_action.
    """
    config = load_ppo_training_config()
    total_timesteps = int(total_timesteps if total_timesteps is not None else config["training_timesteps"])
    table_path = Path(table_path or config["outcome_table_path"])
    result = train_on_table(
        OutcomeTable.from_jsonl(table_path), total_timesteps=total_timesteps, output_path=output_path, seed=seed
    )
    return {**result, "outcome_table": str(table_path)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timesteps", type=int, default=None)
    parser.add_argument("--output", default="models/ppo_defense")
    parser.add_argument("--table", default=None)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()
    print(train(args.timesteps, args.output, args.table, args.seed))


if __name__ == "__main__":
    main()
