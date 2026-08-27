"""Short CPU-only PPO training entry point for the decision simulator."""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from stable_baselines3 import PPO

from iot_defense.defense.ppo_env import DefenseDecisionEnv


def train(total_timesteps: int = 512, output_path: str | Path = "models/ppo_defense") -> dict[str, float | int | str]:
    """Train and persist a deliberately small PPO policy."""
    environment = DefenseDecisionEnv()
    start = time.perf_counter()
    model = PPO(
        "MlpPolicy",
        environment,
        policy_kwargs={"net_arch": [32, 32]},
        n_steps=32,
        batch_size=32,
        learning_rate=0.001,
        device="cpu",
        verbose=0,
        seed=7,
    )
    model.learn(total_timesteps=total_timesteps)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    model.save(str(output))
    elapsed = time.perf_counter() - start
    return {"timesteps": total_timesteps, "model_path": str(output.with_suffix(".zip")), "training_seconds": elapsed}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timesteps", type=int, default=512)
    parser.add_argument("--output", default="models/ppo_defense")
    args = parser.parse_args()
    print(train(args.timesteps, args.output))


if __name__ == "__main__":
    main()
