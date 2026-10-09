"""Gymnasium environment that trains PPO from MEASURED response outcomes.

Each step draws a true condition, shows the policy a noisy and sometimes
mislabelled detector observation of it, and rewards the chosen action with a
realized utility measured in live Mininet for the TRUE condition (the
evaluation/outcome_table.py table). The reward never reads a registered
attack's preferred_action, and the observation carries no other policy's
output.
"""

from __future__ import annotations

import random
from pathlib import Path
from typing import TYPE_CHECKING, Any

import gymnasium as gym
import numpy as np
import yaml
from gymnasium import spaces

from iot_defense.defense.context import Beliefs, Desires, SecurityContext
from iot_defense.defense.decision import DefenseAction

if TYPE_CHECKING:
    from iot_defense.evaluation.outcome import OutcomeTable

ACTION_TO_INDEX = {action: index for index, action in enumerate(DefenseAction)}
INDEX_TO_ACTION = {index: action for action, index in ACTION_TO_INDEX.items()}

# Intentions are a distinct axis from attack identity -- several attacks may
# share one -- so this stays an explicit, static list rather than one
# auto-derived 1:1 from ATTACK_SCENARIOS.
INTENTIONS = (
    "protect_legitimate_iot_service",
    "contain_malicious_activity",
    "gather_attacker_intelligence_when_appropriate",
    "minimize_unnecessary_disruption",
)

CRITICALITY_LEVELS = ("unknown", "low", "medium", "high")


# Functions, not module-level constants: this module is eagerly imported by
# iot_defense.defense's package __init__, which the registry itself pulls in
# while building ATTACK_SCENARIOS -- a top-level import would deadlock that
# cycle.
def TRAINING_SCENARIOS() -> tuple[str, ...]:
    """The 'normal' condition plus one entry per registered attack, in registry order."""
    from iot_defense.attacks.registry import ATTACK_SCENARIOS

    return ("normal",) + tuple(scenario.attack_type for scenario in ATTACK_SCENARIOS.values())


def _scenario_by_attack_type() -> dict[str, Any]:
    from iot_defense.attacks.registry import ATTACK_SCENARIOS

    return {scenario.attack_type: scenario for scenario in ATTACK_SCENARIOS.values()}


def OBSERVATION_SIZE() -> int:
    return 6 + len(TRAINING_SCENARIOS()) + len(INTENTIONS)


def load_ppo_training_config() -> dict[str, Any]:
    config_path = Path(__file__).resolve().parents[3] / "config" / "policies.yaml"
    with config_path.open("r", encoding="utf-8") as fh:
        loaded = yaml.safe_load(fh) or {}
    return loaded.get("policy", {}).get("ppo", {})


class SecurityContextEncoder:
    """Deterministically map SecurityContext values to a normalized observation."""

    criticality = {"unknown": 0.0, "low": 0.33, "medium": 0.66, "high": 1.0}

    def encode(self, context: SecurityContext) -> np.ndarray:
        beliefs = context.beliefs
        features = beliefs.observed_features
        threat_type = beliefs.threat_type.lower()
        packet_rate = min(max(float(features.get("packets_per_second", 0.0)), 0.0) / 100.0, 1.0)
        unique_ports = min(max(float(features.get("unique_destination_ports", 0.0)), 0.0) / 20.0, 1.0)
        history = min(len(beliefs.previous_relevant_events) / 5.0, 1.0)
        threat_one_hot = [float(threat_type == scenario) for scenario in TRAINING_SCENARIOS()]
        intention_one_hot = [float(context.intention == candidate) for candidate in INTENTIONS]
        return np.array(
            [
                np.clip(beliefs.threat_score, 0.0, 1.0),
                np.clip(beliefs.confidence, 0.0, 1.0),
                packet_rate,
                unique_ports,
                self.criticality.get(beliefs.device_criticality.lower(), 0.0),
                history,
            ]
            + threat_one_hot
            + intention_one_hot,
            dtype=np.float32,
        )


def context_for_scenario(scenario: str) -> SecurityContext:
    """The canonical, noise-free detector observation for one condition."""
    if scenario == "normal":
        beliefs = Beliefs(
            threat_type="normal",
            threat_score=0.05,
            confidence=0.9,
            source_device="10.0.0.30",
            destination_device="10.0.0.10",
            observed_features={"packets_per_second": 1.0, "unique_destination_ports": 0},
        )
        return SecurityContext(beliefs=beliefs, desires=Desires(), intention="protect_legitimate_iot_service")

    attack = _scenario_by_attack_type().get(scenario)
    if attack is None:
        raise ValueError(f"Unsupported training scenario: {scenario!r}")
    beliefs = Beliefs(
        threat_type=attack.attack_type,
        threat_score=attack.ppo_threat_score,
        confidence=attack.ppo_confidence,
        source_device="10.0.0.100",
        destination_device="10.0.0.10",
        observed_features=dict(attack.ppo_example_features),
    )
    return SecurityContext(beliefs=beliefs, desires=Desires(), intention=attack.intention)


def noisy_context(
    true_condition: str,
    rng: np.random.Generator,
    *,
    label_error_rate: float,
    score_sigma: float,
    feature_jitter: float,
) -> tuple[SecurityContext, str]:
    """A detector observation of `true_condition` as a real detector could
    produce it: sometimes mislabelled, with jittered score/confidence/
    features and an arbitrary device-criticality tag. Returns the context
    and the label the detector reported."""
    conditions = TRAINING_SCENARIOS()
    reported = true_condition
    if rng.random() < label_error_rate:
        reported = str(rng.choice([c for c in conditions if c != true_condition]))
    base = context_for_scenario(reported)
    beliefs = base.beliefs
    features = {
        key: max(0.0, float(value) * (1.0 + rng.uniform(-feature_jitter, feature_jitter)))
        for key, value in beliefs.observed_features.items()
    }
    noisy = Beliefs(
        threat_type=beliefs.threat_type,
        threat_score=float(np.clip(beliefs.threat_score + rng.normal(0.0, score_sigma), 0.0, 1.0)),
        confidence=float(np.clip(beliefs.confidence + rng.normal(0.0, score_sigma), 0.0, 1.0)),
        source_device=beliefs.source_device,
        destination_device=beliefs.destination_device,
        observed_features=features,
        device_criticality=str(rng.choice(CRITICALITY_LEVELS)),
    )
    return SecurityContext(beliefs=noisy, desires=base.desires, intention=base.intention), reported


class DefenseDecisionEnv(gym.Env[np.ndarray, int]):
    """Contextual-bandit environment over the measured outcome table."""

    metadata = {"render_modes": []}

    def __init__(
        self,
        table: "OutcomeTable",
        *,
        episode_length: int = 68,
        label_error_rate: float = 0.15,
        score_sigma: float = 0.07,
        feature_jitter: float = 0.5,
        reward_scale: float = 10.0,
    ) -> None:
        super().__init__()
        table.require_complete(TRAINING_SCENARIOS())
        self.table = table
        self.action_space = spaces.Discrete(len(DefenseAction))
        self.observation_space = spaces.Box(0.0, 1.0, shape=(OBSERVATION_SIZE(),), dtype=np.float32)
        self.episode_length = episode_length
        self.label_error_rate = label_error_rate
        self.score_sigma = score_sigma
        self.feature_jitter = feature_jitter
        self.reward_scale = reward_scale
        self.encoder = SecurityContextEncoder()
        self._reward_rng = random.Random(0)
        self._step = 0
        self._true_condition = "normal"

    @classmethod
    def from_config(cls, table: "OutcomeTable", episode_length: int | None = None) -> "DefenseDecisionEnv":
        config = load_ppo_training_config()
        return cls(
            table,
            episode_length=episode_length or int(config["environment_episode_length"]),
            label_error_rate=float(config["label_error_rate"]),
            score_sigma=float(config["score_noise_sigma"]),
            feature_jitter=float(config["feature_jitter"]),
            reward_scale=float(config["reward_scale"]),
        )

    def _draw(self) -> tuple[np.ndarray, str]:
        self._true_condition = str(self.np_random.choice(TRAINING_SCENARIOS()))
        context, reported = noisy_context(
            self._true_condition,
            self.np_random,
            label_error_rate=self.label_error_rate,
            score_sigma=self.score_sigma,
            feature_jitter=self.feature_jitter,
        )
        return self.encoder.encode(context), reported

    def reset(self, *, seed: int | None = None, options: dict[str, Any] | None = None):
        super().reset(seed=seed)
        if seed is not None:
            self._reward_rng = random.Random(seed)
        self._step = 0
        observation, reported = self._draw()
        return observation, {"true_condition": self._true_condition, "reported_condition": reported}

    def step(self, action: int):
        if action not in INDEX_TO_ACTION:
            raise ValueError(f"Invalid defense action index: {action}")
        selected = INDEX_TO_ACTION[action]
        true_condition = self._true_condition
        utility = self.table.sample(true_condition, selected, self._reward_rng)
        self._step += 1
        observation, reported = self._draw()
        info = {
            "true_condition": true_condition,
            "action": selected.value,
            "utility": utility,
            "next_true_condition": self._true_condition,
            "next_reported_condition": reported,
        }
        return observation, utility / self.reward_scale, self._step >= self.episode_length, False, info
