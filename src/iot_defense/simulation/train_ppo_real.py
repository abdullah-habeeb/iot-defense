"""Fine-tune the PPO policy against real, verified Mininet outcomes.

This does NOT train from scratch: it loads the existing synthetic-trained
model as a warm start and continues training against RealMininetDefenseEnv,
where every step's reward comes from an actually-executed, actually-verified
Mininet outcome (a real ping check, a real redirected connection) rather
than an assumed reward table.

Requires root (creates and drives a real Mininet network). Each step costs
several real seconds, so this is intentionally bounded to a short run, not
an exhaustive one.

SAFE BY DEFAULT: saves to a separate file (models/ppo_defense_real.zip) and
never overwrites the currently-deployed models/ppo_defense.zip. Promote it
manually only after verifying it still behaves sensibly across every registered
scenarios.
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from stable_baselines3 import PPO

from iot_defense.defense.ppo_real_env import RealMininetDefenseEnv


def fine_tune(
    base_model_path: str | Path = "models/ppo_defense",
    output_path: str | Path = "models/ppo_defense_real",
    total_timesteps: int = 64,
    episode_length: int | None = None,
) -> dict[str, float | int | str]:
    env = RealMininetDefenseEnv(episode_length=episode_length)
    try:
        model = PPO.load(str(base_model_path), device="cpu")
        model.set_env(env)
        start = time.perf_counter()
        model.learn(total_timesteps=total_timesteps, reset_num_timesteps=False)
        elapsed = time.perf_counter() - start
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        model.save(str(output))
        metadata = {
            "base_model": str(base_model_path),
            "output_model": str(output.with_suffix(".zip")),
            "timesteps": total_timesteps,
            "episode_length": env.episode_length,
            "training_seconds": round(elapsed, 1),
            "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        }
        # Matches ml/random_forest.py's save_model_metadata() convention:
        # every trained model in this project gets a human-readable
        # metadata file alongside it, so how/when/from-what a model was
        # produced is never only in a terminal scrollback.
        output.with_suffix(".metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        return metadata
    finally:
        env.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-model", default="models/ppo_defense")
    parser.add_argument("--output", default="models/ppo_defense_real")
    parser.add_argument("--timesteps", type=int, default=64)
    # Defaults to None (self-sizes to the current registered scenario
    # count -- see RealMininetDefenseEnv.__init__) rather than a fixed
    # number, so this CLI default can't silently fall out of sync the
    # same way the class default itself once did.
    parser.add_argument("--episode-length", type=int, default=None)
    args = parser.parse_args()
    result = fine_tune(
        base_model_path=args.base_model,
        output_path=args.output,
        total_timesteps=args.timesteps,
        episode_length=args.episode_length,
    )
    print(result)


if __name__ == "__main__":
    main()
