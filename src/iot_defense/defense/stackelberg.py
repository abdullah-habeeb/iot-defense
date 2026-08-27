"""Lightweight, explicit Stackelberg game model for defense policy selection."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from iot_defense.defense.decision import DefenseAction


OBSERVED_THREAT_TYPES = ("NORMAL", "RECONNAISSANCE_PORT_SCAN")
ATTACKER_RESPONSE_STRATEGIES = ("CONTINUE", "RETREAT")
DEFENDER_STRATEGIES = tuple(DefenseAction)


@dataclass(frozen=True, slots=True)
class Payoff:
    """Attacker and defender utility for one strategy pair."""

    attacker: float
    defender: float


@dataclass(frozen=True, slots=True)
class StrategyEvaluation:
    """Intermediate leader/follower reasoning for one defender action."""

    defender_action: DefenseAction
    predicted_attacker_strategy: str
    attacker_utility: float
    defender_utility: float
    attacker_utilities: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["defender_action"] = self.defender_action.value
        return data


@dataclass(frozen=True, slots=True)
class StackelbergSolution:
    """Complete solution including all candidate strategy evaluations."""

    observed_threat: str
    selected_action: DefenseAction
    predicted_attacker_strategy: str
    selected_attacker_utility: float
    selected_defender_utility: float
    candidates: tuple[StrategyEvaluation, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "observed_threat": self.observed_threat,
            "selected_action": self.selected_action.value,
            "predicted_attacker_strategy": self.predicted_attacker_strategy,
            "selected_attacker_utility": self.selected_attacker_utility,
            "selected_defender_utility": self.selected_defender_utility,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
        }


def _load_game_config() -> dict[str, Any]:
    config_path = Path(__file__).resolve().parents[3] / "config" / "policies.yaml"
    if not config_path.exists():
        return {}
    with config_path.open("r", encoding="utf-8") as stream:
        loaded = yaml.safe_load(stream) or {}
    return loaded.get("policy", {}).get("stackelberg", {})


class StackelbergGame:
    """Solve a finite leader-follower game using explicit payoff values."""

    def __init__(self, payoffs: dict[str, dict[str, dict[str, dict[str, float]]]] | None = None) -> None:
        raw_payoffs = payoffs or _load_game_config().get("payoffs", {})
        self.payoffs = self._parse_payoffs(raw_payoffs)

    @staticmethod
    def _parse_payoffs(
        raw_payoffs: dict[str, dict[str, dict[str, dict[str, float]]]]
    ) -> dict[str, dict[DefenseAction, dict[str, Payoff]]]:
        parsed: dict[str, dict[DefenseAction, dict[str, Payoff]]] = {}
        for observed_threat in OBSERVED_THREAT_TYPES:
            threat_values = raw_payoffs.get(observed_threat, {})
            parsed[observed_threat] = {}
            for action in DEFENDER_STRATEGIES:
                response_values = threat_values.get(action.value, {})
                parsed[observed_threat][action] = {
                    response: Payoff(
                        attacker=float(response_values.get(response, {}).get("attacker", 0.0)),
                        defender=float(response_values.get(response, {}).get("defender", 0.0)),
                    )
                    for response in ATTACKER_RESPONSE_STRATEGIES
                }
        return parsed

    def attacker_best_response(self, observed_threat: str, defender_action: DefenseAction) -> tuple[str, float]:
        """Return the follower response maximizing utility for an observed threat."""
        if observed_threat not in OBSERVED_THREAT_TYPES:
            raise ValueError(f"Unsupported observed threat type: {observed_threat}")
        candidates = [
            (response, self.payoffs[observed_threat][defender_action][response].attacker)
            for response in ATTACKER_RESPONSE_STRATEGIES
        ]
        return max(candidates, key=lambda candidate: candidate[1])

    def defender_utility(
        self,
        observed_threat: str,
        defender_action: DefenseAction,
        attacker_response: str,
    ) -> float:
        """Return defender utility under the follower's predicted response."""
        if observed_threat not in OBSERVED_THREAT_TYPES:
            raise ValueError(f"Unsupported observed threat type: {observed_threat}")
        if attacker_response not in ATTACKER_RESPONSE_STRATEGIES:
            raise ValueError(f"Unsupported attacker response strategy: {attacker_response}")
        return self.payoffs[observed_threat][defender_action][attacker_response].defender

    def solve(self, observed_threat: str) -> StackelbergSolution:
        """Select the leader action against each follower best response.

        All possible attacker utilities are still calculated for every candidate
        action. The observed IDS threat is state, while the returned response is
        the attacker's strategic choice after the leader action.
        """
        if observed_threat not in OBSERVED_THREAT_TYPES:
            raise ValueError(f"Unsupported observed threat type: {observed_threat}")
        evaluations = []
        for action in DEFENDER_STRATEGIES:
            attacker_response, attacker_utility = self.attacker_best_response(observed_threat, action)
            attacker_utilities = {
                response: self.payoffs[observed_threat][action][response].attacker
                for response in ATTACKER_RESPONSE_STRATEGIES
            }
            evaluations.append(
                StrategyEvaluation(
                    defender_action=action,
                    predicted_attacker_strategy=attacker_response,
                    attacker_utility=attacker_utility,
                    defender_utility=self.defender_utility(observed_threat, action, attacker_response),
                    attacker_utilities=attacker_utilities,
                )
            )
        selected = max(evaluations, key=lambda evaluation: evaluation.defender_utility)
        return StackelbergSolution(
            observed_threat=observed_threat,
            selected_action=selected.defender_action,
            predicted_attacker_strategy=selected.predicted_attacker_strategy,
            selected_attacker_utility=selected.attacker_utility,
            selected_defender_utility=selected.defender_utility,
            candidates=tuple(evaluations),
        )
