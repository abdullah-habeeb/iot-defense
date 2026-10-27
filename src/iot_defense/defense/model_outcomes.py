"""Outcomes predicted by the a-priori mechanism model, in the shape PPO trains on.

The measured outcome table (evaluation/outcome_table.py) is what a lab experiment produced. A deployed
defender does not have one. This table is what the same defender can write down before measuring anything:
for each response and class of attack, the containment, service loss and intelligence that
config/policies.yaml's policy.game_model says the mechanism provides, scored with the shared objective.

It exposes the part of OutcomeTable's interface that DefenseDecisionEnv uses, so a PPO trained on it never
reads a measurement. The measured table is then used only to grade what it learned.
"""

from __future__ import annotations

import random
from typing import Any

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.objective import Objective, load_policy_section


class ModelOutcomeTable:
    """Predicted realized utility per (true condition, action), from the mechanism priors alone."""

    def __init__(
        self,
        model: dict[str, Any] | None = None,
        objective: Objective | None = None,
        noise_sigma: float = 0.0,
    ) -> None:
        from iot_defense.attacks.registry import ATTACK_SCENARIOS

        self.model = model if model is not None else load_policy_section("game_model")
        self.objective = objective or Objective.load()
        self.noise_sigma = float(noise_sigma)
        self.invalid_rows = 0
        attack_class = self.model["attack_class"]
        missing = sorted(s.attack_type for s in ATTACK_SCENARIOS.values() if s.attack_type not in attack_class)
        if missing:
            raise ValueError(f"policy.game_model.attack_class has no class for: {missing}")
        self._mean: dict[tuple[str, DefenseAction], float] = {}
        for action in DefenseAction:
            service = 1.0 - float(self.model["service_loss_prior"].get(action.value, 0.0))
            self._mean[("normal", action)] = self.objective.utility(
                action, containment=None, service=service, intelligence=0.0
            )
            for scenario in ATTACK_SCENARIOS.values():
                klass = attack_class[scenario.attack_type]
                contain = float(self.model["containment_prior"].get(action.value, {}).get(klass, 0.0))
                intel = float(self.model["intelligence_prior"].get(action.value, 0.0))
                self._mean[(scenario.attack_type, action)] = self.objective.utility(
                    action, containment=contain, service=service, intelligence=intel
                )

    def samples(self, condition: str, action: DefenseAction) -> list[float]:
        return [self._mean[(condition, action)]]

    def mean(self, condition: str, action: DefenseAction) -> float:
        return self._mean[(condition, action)]

    def sample(self, condition: str, action: DefenseAction, rng: random.Random) -> float:
        value = self._mean[(condition, action)]
        return value + rng.gauss(0.0, self.noise_sigma) if self.noise_sigma > 0 else value

    def best_action(self, condition: str) -> DefenseAction:
        return max(DefenseAction, key=lambda action: self.mean(condition, action))

    def missing_cells(self, conditions: tuple[str, ...]) -> list[tuple[str, str]]:
        return [(c, a.value) for c in conditions for a in DefenseAction if (c, a) not in self._mean]

    def require_complete(self, conditions: tuple[str, ...]) -> None:
        missing = self.missing_cells(conditions)
        if missing:
            raise ValueError(f"mechanism model has no prediction for {len(missing)} cells, e.g. {missing[:5]}")
