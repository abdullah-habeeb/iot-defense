"""PPO trained on the mechanism model instead of the measured table (defense/model_outcomes.py).

Needs no Mininet and no measured data: the table is built from config/policies.yaml alone.
"""

from __future__ import annotations

import random

import pytest

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.model_outcomes import ModelOutcomeTable
from iot_defense.defense.objective import Objective
from iot_defense.defense.ppo_env import DefenseDecisionEnv, TRAINING_SCENARIOS


@pytest.fixture(scope="module")
def table():
    return ModelOutcomeTable()


def test_every_condition_and_action_has_a_prediction(table):
    assert table.missing_cells(TRAINING_SCENARIOS()) == []
    table.require_complete(TRAINING_SCENARIOS())


def test_the_prediction_is_the_objective_applied_to_the_priors(table):
    objective = Objective.load()
    model = table.model
    # BLOCK_SOURCE against a flood: containment prior, no service loss, no intelligence.
    contain = model["containment_prior"]["BLOCK_SOURCE"]["flood"]
    expected = objective.utility(DefenseAction.BLOCK_SOURCE, containment=contain, service=1.0, intelligence=0.0)
    assert table.mean("dos_flood", DefenseAction.BLOCK_SOURCE) == pytest.approx(expected)
    # Benign traffic has nothing to contain or learn, so only service and cost count.
    isolate_service = 1.0 - model["service_loss_prior"]["ISOLATE"]
    assert table.mean("normal", DefenseAction.ISOLATE) == pytest.approx(
        objective.utility(DefenseAction.ISOLATE, containment=None, service=isolate_service, intelligence=0.0)
    )


def test_doing_nothing_is_best_for_normal_traffic_and_never_for_an_attack(table):
    assert table.best_action("normal") == DefenseAction.ALLOW
    assert all(table.best_action(c) != DefenseAction.ALLOW for c in TRAINING_SCENARIOS() if c != "normal")


def test_the_model_knows_a_source_block_does_not_stop_a_spoofed_flood(table):
    assert table.mean("dos_flood", DefenseAction.BLOCK_SOURCE) > table.mean(
        "dos_flood_distributed", DefenseAction.BLOCK_SOURCE
    )
    assert table.best_action("dos_flood_distributed") != DefenseAction.BLOCK_SOURCE


def test_it_reads_no_measurement_file_and_no_registered_preferred_action():
    import inspect

    from iot_defense.defense import model_outcomes

    source = inspect.getsource(model_outcomes)
    assert not hasattr(model_outcomes, "OutcomeTable")
    assert ".jsonl" not in source and "read_text" not in source
    assert "preferred_action" not in source


def test_noise_is_optional_and_seeded_by_the_caller(table):
    rng = random.Random(3)
    assert table.sample("dos_flood", DefenseAction.THROTTLE, rng) == table.mean("dos_flood", DefenseAction.THROTTLE)
    noisy = ModelOutcomeTable(noise_sigma=0.5)
    draws = {noisy.sample("dos_flood", DefenseAction.THROTTLE, random.Random(s)) for s in range(5)}
    assert len(draws) > 1
    assert noisy.sample("dos_flood", DefenseAction.THROTTLE, random.Random(9)) == noisy.sample(
        "dos_flood", DefenseAction.THROTTLE, random.Random(9)
    )


def test_the_training_environment_accepts_it_and_rewards_the_true_condition(table):
    env = DefenseDecisionEnv.from_config(table)
    obs, info = env.reset(seed=5)
    assert obs.shape == env.observation_space.shape
    truth = info["true_condition"]
    _, reward, _, _, step_info = env.step(int(list(DefenseAction).index(DefenseAction.ALLOW)))
    assert step_info["true_condition"] == truth
    assert reward == pytest.approx(table.mean(truth, DefenseAction.ALLOW) / env.reward_scale)


def test_a_short_training_run_produces_a_loadable_policy(table, tmp_path):
    from iot_defense.defense.ppo_policy import PPODefensePolicy
    from iot_defense.evaluation.generalization import decide_all
    from iot_defense.simulation.train_ppo import train_on_table

    path = tmp_path / "ppo_model"
    train_on_table(table, total_timesteps=2040, output_path=path, seed=1)
    choices = decide_all(PPODefensePolicy(model_path=path))
    assert set(choices) == set(TRAINING_SCENARIOS())
    assert all(DefenseAction(a) in DefenseAction for a in choices.values())
