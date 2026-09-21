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
    # net_arch=[64, 64] and ent_coef=0.01: both found necessary by direct
    # reproduction after the registry grew to 17 training scenarios (16
    # attacks + normal) / 10 actions, not assumed. The reward function
    # gives identical -3.5 for *any* non-preferred, non-ALLOW action (see
    # calculate_reward's service_disruption branch) -- nothing in the
    # reward landscape distinguishes one wrong action from another, so
    # this is effectively a 17-state, 10-action contextual-bandit problem.
    # With the previous net_arch=[32, 32] and ent_coef=0.0, raising
    # training_timesteps from 12750 to 30000 made convergence *worse* (5
    # scenario mismatches against each scenario's own preferred_action
    # became 7, the policy collapsing onto THROTTLE for several unrelated
    # scenarios) -- more training without exploration pressure just
    # locked in an early, wrong generalization faster. Adding
    # ent_coef=0.01 alone got to 3 mismatches at 12750 timesteps and only
    # 1 (the "normal" scenario, misrouted to DECOY) even at 35000 -- a
    # single, *persistent* miss across three different timestep budgets,
    # not noise, pointing at capacity rather than training time: DECOY is
    # the optimal action for 3 of the 17 states (reconnaissance, exploit,
    # dns_tunneling) with a large reward (+6.5), and [32, 32] wasn't
    # reliably separating the "normal" state from those in the shared
    # policy network. Doubling to [64, 64] converged all 17 scenarios to
    # their own registered preferred_action, confirmed at both 12750 and
    # 20000 timesteps -- see train_ppo's own verification run.
    model = PPO(
        "MlpPolicy",
        environment,
        policy_kwargs={"net_arch": [64, 64]},
        n_steps=32,
        batch_size=32,
        learning_rate=0.001,
        ent_coef=0.01,
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
