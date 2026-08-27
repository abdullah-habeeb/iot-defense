"""Small Gymnasium decision simulator used exclusively for PPO training."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import gymnasium as gym
import numpy as np
from gymnasium import spaces

from iot_defense.defense.context import Beliefs, Desires, SecurityContext
from iot_defense.defense.decision import DefenseAction


ACTION_TO_INDEX = {action: index for index, action in enumerate(DefenseAction)}
INDEX_TO_ACTION = {index: action for action, index in ACTION_TO_INDEX.items()}
OBSERVATION_SIZE = 16


@dataclass(frozen=True, slots=True)
class RewardConfig:
    """Configurable reward coefficients; values are modelling assumptions."""

    attack_contained: float = 5.0
    attacker_diverted: float = 4.0
    intelligence_gained: float = 3.0
    service_preserved: float = 3.0
    successful_compromise: float = -6.0
    false_positive_intervention: float = -4.0
    unnecessary_isolation: float = -3.0
    service_disruption: float = -3.0
    response_cost: float = -0.5


class SecurityContextEncoder:
    """Deterministically map SecurityContext values to a normalized observation."""

    criticality = {"unknown": 0.0, "low": 0.33, "medium": 0.66, "high": 1.0}

    def encode(self, context: SecurityContext, stackelberg_info: dict[str, Any] | None = None) -> np.ndarray:
        beliefs = context.beliefs
        features = beliefs.observed_features
        threat_type = beliefs.threat_type.lower()
        intention = context.intention
        packet_rate = min(max(float(features.get("packets_per_second", 0.0)), 0.0) / 100.0, 1.0)
        unique_ports = min(max(float(features.get("unique_destination_ports", 0.0)), 0.0) / 20.0, 1.0)
        history = min(len(beliefs.previous_relevant_events) / 5.0, 1.0)
        base_vector = [
                np.clip(beliefs.threat_score, 0.0, 1.0),
                np.clip(beliefs.confidence, 0.0, 1.0),
                packet_rate,
                unique_ports,
                self.criticality.get(beliefs.device_criticality.lower(), 0.0),
                history,
                float(threat_type == "normal"),
                float(threat_type == "reconnaissance_port_scan"),
                float(intention == "protect_legitimate_iot_service"),
                float(intention == "contain_malicious_activity"),
                float(intention == "gather_attacker_intelligence_when_appropriate"),
                float(intention == "minimize_unnecessary_disruption"),
            ]
        stack_vector = [0.0, 0.0, 0.0, 0.0]
        if stackelberg_info:
            selected = stackelberg_info.get("selected_action")
            if selected in {action.value for action in DefenseAction}:
                stack_vector[ACTION_TO_INDEX[DefenseAction(selected)]] = 1.0
        return np.array(base_vector + stack_vector, dtype=np.float32)


def context_for_scenario(scenario: str) -> SecurityContext:
    """Create one deterministic training scenario from supported detector states."""
    if scenario == "normal":
        beliefs = Beliefs(
            threat_type="normal",
            threat_score=0.05,
            confidence=0.9,
            source_device="10.0.0.30",
            destination_device="10.0.0.10",
            observed_features={"packets_per_second": 1.0, "unique_destination_ports": 0},
        )
        intention = "protect_legitimate_iot_service"
    else:
        beliefs = Beliefs(
            threat_type="reconnaissance_port_scan",
            threat_score=0.9,
            confidence=0.88,
            source_device="10.0.0.100",
            destination_device="10.0.0.10",
            observed_features={"packets_per_second": 20.0, "unique_destination_ports": 4},
        )
        intention = "gather_attacker_intelligence_when_appropriate"
    return SecurityContext(beliefs=beliefs, desires=Desires(), intention=intention)


class DefenseDecisionEnv(gym.Env[np.ndarray, int]):
    """Deterministic repeated decision simulator; it never starts Mininet."""

    metadata = {"render_modes": []}

    def __init__(self, episode_length: int = 4, reward_config: RewardConfig | None = None) -> None:
        super().__init__()
        self.action_space = spaces.Discrete(len(DefenseAction))
        self.observation_space = spaces.Box(0.0, 1.0, shape=(OBSERVATION_SIZE,), dtype=np.float32)
        self.episode_length = episode_length
        self.reward_config = reward_config or RewardConfig()
        self.encoder = SecurityContextEncoder()
        self._step = 0
        self._scenario_index = 0

    def reset(self, *, seed: int | None = None, options: dict[str, Any] | None = None):
        super().reset(seed=seed)
        self._step = 0
        self._scenario_index = 0
        context = context_for_scenario("normal")
        return self.encoder.encode(context), {"scenario": "normal"}

    def step(self, action: int):
        if action not in INDEX_TO_ACTION:
            raise ValueError(f"Invalid defense action index: {action}")
        scenario = "normal" if self._scenario_index % 2 == 0 else "reconnaissance_port_scan"
        context = context_for_scenario(scenario)
        selected_action = INDEX_TO_ACTION[action]
        reward, components = self.calculate_reward(context, selected_action)
        self._step += 1
        self._scenario_index += 1
        terminated = self._step >= self.episode_length
        next_scenario = "normal" if self._scenario_index % 2 == 0 else "reconnaissance_port_scan"
        observation = self.encoder.encode(context_for_scenario(next_scenario))
        return observation, reward, terminated, False, {"scenario": scenario, "reward_components": components}

    def calculate_reward(self, context: SecurityContext, action: DefenseAction) -> tuple[float, dict[str, float]]:
        """Calculate the configured, deterministic reward for one simulated outcome."""
        config = self.reward_config
        normal = context.beliefs.threat_type == "normal"
        components: dict[str, float] = {"response_cost": config.response_cost}
        reward = config.response_cost
        if normal and action == DefenseAction.ALLOW:
            components["service_preserved"] = config.service_preserved
            reward += config.service_preserved
        elif normal:
            components["false_positive_intervention"] = config.false_positive_intervention
            reward += config.false_positive_intervention
            if action == DefenseAction.ISOLATE:
                components["unnecessary_isolation"] = config.unnecessary_isolation
                reward += config.unnecessary_isolation
                components["service_disruption"] = config.service_disruption
                reward += config.service_disruption
        elif action == DefenseAction.DECOY:
            components["attacker_diverted"] = config.attacker_diverted
            components["intelligence_gained"] = config.intelligence_gained
            reward += config.attacker_diverted + config.intelligence_gained
        elif action == DefenseAction.ISOLATE:
            components["attack_contained"] = config.attack_contained
            components["service_disruption"] = config.service_disruption
            reward += config.attack_contained + config.service_disruption
        elif action == DefenseAction.ALLOW:
            components["successful_compromise"] = config.successful_compromise
            reward += config.successful_compromise
        return float(reward), components
