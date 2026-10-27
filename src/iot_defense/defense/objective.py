"""The single operator objective all policies optimize and all evaluations score against.

Realized utility of one response, from quantities measured in live Mininet:

    containment * (1 - residual_attack_fraction)   attack conditions only
  + service     * (1 - legit_service_loss)
  + intelligence * intel_verified                   attack conditions only
  - action_cost[action]

Nothing here reads an attack's registered preferred_action.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from iot_defense.defense.decision import DefenseAction


def load_policy_section(name: str) -> dict[str, Any]:
    config_path = Path(__file__).resolve().parents[3] / "config" / "policies.yaml"
    with config_path.open("r", encoding="utf-8") as fh:
        loaded = yaml.safe_load(fh) or {}
    section = loaded.get("policy", {}).get(name)
    if not section:
        raise KeyError(f"config/policies.yaml is missing policy.{name}")
    return section


@dataclass(frozen=True, slots=True)
class Objective:
    containment: float
    service: float
    intelligence: float
    action_cost: dict[DefenseAction, float]

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "Objective":
        costs = {DefenseAction(name): float(value) for name, value in data["action_cost"].items()}
        missing = [action.value for action in DefenseAction if action not in costs]
        if missing:
            raise ValueError(f"objective.action_cost is missing actions: {missing}")
        return cls(
            containment=float(data["containment"]),
            service=float(data["service"]),
            intelligence=float(data["intelligence"]),
            action_cost=costs,
        )

    @classmethod
    def load(cls) -> "Objective":
        return cls.from_mapping(load_policy_section("objective"))

    @property
    def max_utility(self) -> float:
        return self.containment + self.service + self.intelligence

    def utility(
        self,
        action: DefenseAction,
        *,
        containment: float | None,
        service: float,
        intelligence: float,
    ) -> float:
        """containment is None for a benign condition (nothing to contain)."""
        value = self.service * service - self.action_cost[action]
        if containment is not None:
            value += self.containment * containment + self.intelligence * intelligence
        return value
