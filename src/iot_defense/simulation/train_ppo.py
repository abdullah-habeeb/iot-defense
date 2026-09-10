"""Short CPU-only PPO training entry point for the decision simulator."""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from stable_baselines3 import PPO

from iot_defense.defense.ppo_env import TRAINING_SCENARIOS, DefenseDecisionEnv, RewardConfig, load_ppo_training_config


def _default_timesteps() -> int:
    # config/policies.yaml's policy.ppo.training_timesteps documents a
    # real, previously-tuned value (raised from 768 to fix data_exfiltration
    # non-convergence -- see that key's own comment) -- read it here so
    # editing the YAML actually changes what a bare `train_ppo` run does,
    # instead of the YAML being silently decorative.
    return int(load_ppo_training_config().get("training_timesteps", 512))


def train(total_timesteps: int | None = None, output_path: str | Path = "models/ppo_defense") -> dict[str, float | int | str]:
    """Train and persist a deliberately small PPO policy."""
    ppo_config = load_ppo_training_config()
    if total_timesteps is None:
        total_timesteps = int(ppo_config.get("training_timesteps", 512))
    # Never below len(TRAINING_SCENARIOS()): with a shorter episode, step()
    # cycles the scenario index past the episode boundary before the agent
    # ever *acts* on the later scenarios in that cycle, so they never
    # receive a training signal at all -- a real, previously confirmed
    # non-convergence bug (see DefenseDecisionEnv's own docstring comment).
    # Only enforced here, not inside DefenseDecisionEnv itself, since tests
    # legitimately construct short episodes to exercise termination logic
    # in isolation -- this constraint is specific to a real training run.
    episode_length = max(
        int(ppo_config.get("environment_episode_length", len(TRAINING_SCENARIOS()))),
        len(TRAINING_SCENARIOS()),
    )
    reward_config = RewardConfig.from_mapping(ppo_config.get("reward", {}))
    environment = DefenseDecisionEnv(episode_length=episode_length, reward_config=reward_config)
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
    # Omitting --timesteps falls through to train()'s own config-driven
    # default (config/policies.yaml's policy.ppo.training_timesteps) rather
    # than a second hardcoded number here that could drift out of sync with
    # it -- the way this project's own history shows it already did once
    # (see that YAML key's comment).
    parser.add_argument("--timesteps", type=int, default=None)
    parser.add_argument("--output", default="models/ppo_defense")
    args = parser.parse_args()
    print(train(args.timesteps, args.output))


if __name__ == "__main__":
    main()
