"""Shared fixtures: a SYNTHETIC measured-outcome table with a known best action
per condition, and a PPO model trained on it.

These exist only so the training/evaluation plumbing can be tested without
Mininet. They are test fixtures with invented measurements -- never a
substitute for the live-measured table the deployed model is trained on.
"""

from __future__ import annotations

import json

import pytest

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.ppo_env import TRAINING_SCENARIOS

ACTIONS = list(DefenseAction)
BASELINE_PACKETS = 100


def synthetic_best_actions() -> dict[str, DefenseAction]:
    """Condition -> its (invented) best action: normal -> ALLOW, attacks
    spread over the non-ALLOW actions so no single action is a lazy answer."""
    non_allow = [a for a in ACTIONS if a != DefenseAction.ALLOW]
    best = {"normal": DefenseAction.ALLOW}
    for index, condition in enumerate(TRAINING_SCENARIOS()[1:]):
        best[condition] = non_allow[index % len(non_allow)]
    return best


def synthetic_rows(reps: int = 3) -> list[dict]:
    """The best action fully contains the attack with no service loss; every
    other action leaks 80% of it and costs 50% of the service."""
    best = synthetic_best_actions()
    rows = []
    for condition in TRAINING_SCENARIOS():
        for rep in range(reps):
            for action in ACTIONS:
                is_best = action == best[condition]
                is_allow = action == DefenseAction.ALLOW
                if condition == "normal":
                    residual, service_loss = BASELINE_PACKETS, (0.0 if is_best else 0.5)
                elif is_allow:
                    residual, service_loss = BASELINE_PACKETS, 0.0
                else:
                    residual, service_loss = (0 if is_best else 80), (0.0 if is_best else 0.5)
                rows.append(
                    {
                        "condition": condition,
                        "action": action.value,
                        "status": "success",
                        "baseline_packets": BASELINE_PACKETS if not is_allow else residual,
                        "residual_packets": residual,
                        "service_loss": service_loss,
                        "intel_verified": False,
                        "rep": rep,
                    }
                )
    return rows


@pytest.fixture(scope="session")
def synthetic_table_path(tmp_path_factory):
    path = tmp_path_factory.mktemp("outcomes") / "outcome_table.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in synthetic_rows()), encoding="utf-8")
    return path


@pytest.fixture(scope="session")
def synthetic_table(synthetic_table_path):
    from iot_defense.evaluation.outcome import OutcomeTable

    return OutcomeTable.from_jsonl(synthetic_table_path)


@pytest.fixture(scope="session")
def trained_ppo_path(tmp_path_factory, synthetic_table_path):
    """A PPO model trained for real on the synthetic table (path without .zip)."""
    from iot_defense.simulation.train_ppo import train

    output = tmp_path_factory.mktemp("ppo") / "model"
    train(total_timesteps=40000, output_path=output, table_path=synthetic_table_path)
    return str(output)
