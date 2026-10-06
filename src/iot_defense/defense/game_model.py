"""Stackelberg payoffs derived from an a-priori mechanism model.

Payoffs come from config/policies.yaml's policy.game_model (what each
response can mechanically do against each class of attack) combined with
the shared policy.objective. This module never reads a registered attack's
preferred_action, nor any measured outcome.

Per observed threat and defender action a, with containment prior e, service
loss prior s, intelligence prior i and action cost c:

  attacker CONTINUE : gain * (1 - e) - exposure_penalty * e
  attacker RETREAT  : 0
  defender | CONTINUE: Wc*e + Ws*(1 - s) + Wi*i - c
  defender | RETREAT : Wc   + Ws*(1 - s)        - c     (attack ceases; nothing to observe)

For NORMAL traffic the follower is a legitimate user who continues unless
service is fully cut:

  user CONTINUE : Ws * (1 - s)         user RETREAT : 0
  defender      : Ws * (1 - s) - c     (both responses)
"""

from __future__ import annotations

from typing import Any

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.objective import Objective, load_policy_section


def _prior(table: dict[str, dict[str, float]], action: DefenseAction, key: str) -> float:
    return float(table.get(action.value, {}).get(key, 0.0))


def _flat_prior(table: dict[str, float], action: DefenseAction) -> float:
    return float(table.get(action.value, 0.0))


def build_game_payoffs(
    model: dict[str, Any] | None = None, objective: Objective | None = None
) -> dict[str, dict[str, dict[str, dict[str, float]]]]:
    """Return payoffs[threat_key][ACTION][RESPONSE] = {"attacker", "defender"}."""
    from iot_defense.attacks.registry import ATTACK_SCENARIOS

    model = model if model is not None else load_policy_section("game_model")
    objective = objective or Objective.load()
    attacker = model["attacker"]
    gain = float(attacker["gain"])
    penalty = float(attacker["exposure_penalty"])
    attack_class = model["attack_class"]

    unclassified = sorted(
        scenario.attack_type for scenario in ATTACK_SCENARIOS.values() if scenario.attack_type not in attack_class
    )
    if unclassified:
        raise ValueError(f"policy.game_model.attack_class has no class for: {unclassified}")

    def cell(action: DefenseAction, klass: str | None) -> dict[str, dict[str, float]]:
        cost = objective.action_cost[action]
        service = objective.service * (1.0 - _flat_prior(model["service_loss_prior"], action))
        if klass is None:
            utility = service - cost
            return {
                "CONTINUE": {"attacker": service, "defender": utility},
                "RETREAT": {"attacker": 0.0, "defender": utility},
            }
        contain = _prior(model["containment_prior"], action, klass)
        intel = _flat_prior(model["intelligence_prior"], action)
        return {
            "CONTINUE": {
                "attacker": gain * (1.0 - contain) - penalty * contain,
                "defender": objective.containment * contain + service + objective.intelligence * intel - cost,
            },
            "RETREAT": {
                "attacker": 0.0,
                "defender": objective.containment + service - cost,
            },
        }

    payoffs: dict[str, dict[str, dict[str, dict[str, float]]]] = {
        "NORMAL": {action.value: cell(action, None) for action in DefenseAction}
    }
    for scenario in ATTACK_SCENARIOS.values():
        klass = attack_class[scenario.attack_type]
        payoffs[scenario.observed_threat_key] = {action.value: cell(action, klass) for action in DefenseAction}
    return payoffs
