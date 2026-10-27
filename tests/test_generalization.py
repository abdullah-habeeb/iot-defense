"""Leave-one-out and objective-shift experiments (evaluation/generalization.py).

Runs on the synthetic outcome table (see conftest.py): invented measurements
that exist only to exercise the plumbing without Mininet.
"""

from __future__ import annotations

import json

import numpy as np
import pytest

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.objective import Objective
from iot_defense.defense.ppo_env import DefenseDecisionEnv, TRAINING_SCENARIOS
from iot_defense.evaluation import generalization as gen
from iot_defense.evaluation.outcome import OutcomeTable


@pytest.fixture(scope="module")
def rows(synthetic_table_path):
    return gen.load_rows(synthetic_table_path)


def test_task_enumeration_covers_every_attack_class_and_shift_once_per_seed():
    tasks = gen.enumerate_tasks((1, 2))
    per_seed = [t for t in tasks if t.seed == 1]
    assert len({t.id for t in tasks}) == len(tasks)
    assert [t.name for t in per_seed if t.kind == "attack"] == list(gen.attack_conditions())
    assert {t.name for t in per_seed if t.kind == "shift"} == set(gen.OBJECTIVE_SHIFTS)
    multi = {k for k, members in gen.class_members().items() if len(members) > 1}
    assert {t.name for t in per_seed if t.kind == "class"} == multi
    assert len(tasks) == 2 * len(per_seed)


def test_class_holdouts_are_whole_classes_and_never_include_normal():
    seen = set()
    for task in gen.enumerate_tasks((1,)):
        holdout = gen.holdout_for(task)
        assert "normal" not in holdout
        if task.kind == "class":
            assert len(holdout) > 1
            assert {gen.condition_classes()[c] for c in holdout} == {task.name}
            seen |= set(holdout)
        if task.kind == "shift":
            assert holdout == ()
    assert gen.attack_conditions()[0] not in seen or gen.condition_classes()[gen.attack_conditions()[0]] in {
        k for k, m in gen.class_members().items() if len(m) > 1
    }


def test_objective_shifts_change_only_what_they_say():
    base = Objective.load()
    for name, shift in gen.OBJECTIVE_SHIFTS.items():
        shifted = shift(base)
        assert set(shifted.action_cost) == set(base.action_cost), name
    assert gen.OBJECTIVE_SHIFTS["service_critical"](base).service == pytest.approx(base.service * 3)
    assert gen.OBJECTIVE_SHIFTS["service_critical"](base).containment == base.containment
    assert gen.OBJECTIVE_SHIFTS["intelligence_priority"](base).intelligence == pytest.approx(base.intelligence * 4)
    cost = gen.OBJECTIVE_SHIFTS["cost_averse"](base)
    assert cost.action_cost[DefenseAction.ISOLATE] == pytest.approx(base.action_cost[DefenseAction.ISOLATE] * 4)
    assert gen.OBJECTIVE_SHIFTS["security_first"](base).containment > base.containment
    assert gen.OBJECTIVE_SHIFTS["security_first"](base).service < base.service


def test_every_shift_has_a_description():
    assert set(gen.SHIFT_DESCRIPTIONS) == set(gen.OBJECTIVE_SHIFTS)


def test_training_environment_never_shows_or_mislabels_a_held_out_condition(synthetic_table, rows):
    held_out = set(gen.attack_conditions()[:3])
    conditions = tuple(c for c in TRAINING_SCENARIOS() if c not in held_out)
    table = OutcomeTable([r for r in rows if r["condition"] not in held_out], Objective.load())
    env = DefenseDecisionEnv.from_config(table, conditions=conditions)
    observation, info = env.reset(seed=3)
    seen = {info["true_condition"], info["reported_condition"]}
    for step in range(600):
        observation, _, done, _, info = env.step(step % len(DefenseAction))
        seen |= {info["true_condition"], info["next_true_condition"], info["next_reported_condition"]}
        if done:
            env.reset()
    assert seen
    assert not (seen & held_out)


def test_environment_without_a_subset_still_covers_every_condition(synthetic_table):
    env = DefenseDecisionEnv.from_config(synthetic_table)
    assert env.conditions == TRAINING_SCENARIOS()


def test_run_task_trains_without_the_held_out_rows_and_decides_every_condition(rows, tmp_path, monkeypatch):
    import iot_defense.simulation.train_ppo as train_module

    held_out = gen.attack_conditions()[0]
    captured = {}
    real = train_module.train_on_table

    def spy(table, **kwargs):
        captured["held_out_samples"] = [table.samples(held_out, a) for a in DefenseAction]
        captured["conditions"] = kwargs["conditions"]
        return real(table, **kwargs)

    monkeypatch.setattr(train_module, "train_on_table", spy)
    record = gen.run_task(gen.Task("attack", held_out, 1), rows, Objective.load(), timesteps=1020, scratch=str(tmp_path))
    assert all(samples == [] for samples in captured["held_out_samples"])
    assert held_out not in captured["conditions"] and "normal" in captured["conditions"]
    assert record["holdout"] == [held_out]
    assert set(record["choices"]) == set(TRAINING_SCENARIOS())
    assert all(a in {x.value for x in DefenseAction} for a in record["choices"].values())


def test_shift_task_scales_the_reward_to_the_shifted_objective(rows, tmp_path, monkeypatch):
    import iot_defense.simulation.train_ppo as train_module

    seen = {}
    real = train_module.train_on_table

    def spy(table, **kwargs):
        seen.update(kwargs)
        seen["service"] = table.objective.service
        return real(table, **kwargs)

    monkeypatch.setattr(train_module, "train_on_table", spy)
    base = Objective.load()
    gen.run_task(gen.Task("shift", "service_critical", 1), rows, base, timesteps=1020, scratch=str(tmp_path))
    assert seen["service"] == pytest.approx(base.service * 3)
    assert seen["reward_scale"] == pytest.approx(gen.OBJECTIVE_SHIFTS["service_critical"](base).max_utility)
    assert seen["conditions"] == TRAINING_SCENARIOS()


def test_run_skips_recorded_tasks_and_partitions_work_between_workers(rows, tmp_path, monkeypatch):
    table_path = tmp_path / "table.jsonl"
    table_path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    results = tmp_path / "results.jsonl"
    tasks = [gen.Task("attack", c, 1) for c in gen.attack_conditions()[:4]]
    results.write_text(json.dumps({"task": tasks[0].id}) + "\n", encoding="utf-8")
    ran = []

    def fake_run_task(task, *_args, **_kwargs):
        ran.append(task.id)
        return {"task": task.id, "training_seconds": 0.0}

    monkeypatch.setattr(gen, "run_task", fake_run_task)
    for worker in (0, 1):
        gen.run(tasks, table_path=table_path, results_path=results, timesteps=1, scratch=str(tmp_path), worker=worker, workers=2)
    assert tasks[0].id not in ran
    assert sorted(ran) == sorted(t.id for t in tasks[1:])
    assert gen.completed_ids(results) == {t.id for t in tasks}
    # a second pass does nothing
    ran.clear()
    gen.run(tasks, table_path=table_path, results_path=results, timesteps=1, scratch=str(tmp_path))
    assert ran == []


def test_regret_is_zero_for_the_measured_best_action_and_positive_otherwise(rows):
    table = OutcomeTable(rows, Objective.load())
    condition = gen.attack_conditions()[0]
    best = table.best_action(condition)
    other = next(a for a in DefenseAction if a != best)
    assert gen.regret(table, condition, best.value) == pytest.approx(0.0)
    assert gen.regret(table, condition, other.value) > 0.0


def test_holdout_analysis_scores_against_the_full_table_and_arbiter_falls_back(rows):
    table = OutcomeTable(rows, Objective.load())
    condition = gen.attack_conditions()[0]
    best = {c: table.best_action(c).value for c in TRAINING_SCENARIOS()}
    record = {"kind": "attack", "name": condition, "seed": 1, "holdout": [condition], "choices": best}
    report = gen.analyze_holdouts(rows, [record], "attack")
    cell = report["units"][condition]["cells"][0]
    assert cell["ppo_heldout"]["regret"] == pytest.approx(0.0)
    # No evidence exists for a held-out attack, so the arbiter defers to Stackelberg.
    assert cell["arbiter"]["regret"] == pytest.approx(cell["stackelberg"]["regret"])
    assert report["summary"]["n_conditions"] == 1
    assert report["summary"]["picks_measured_best"]["ppo_heldout"] == 1


def test_best_fixed_action_is_one_action_for_everything(rows):
    table = OutcomeTable(rows, Objective.load())
    action = gen.best_fixed_action(table, gen.attack_conditions())
    assert action in {a.value for a in DefenseAction}


def test_shift_analysis_reports_every_arm_for_every_shift(rows):
    base = {c: "ALLOW" for c in TRAINING_SCENARIOS()}
    record = {"kind": "shift", "name": "cost_averse", "seed": 1, "holdout": [], "choices": base}
    report = gen.analyze_shifts(rows, [record], [base])
    assert set(report) == set(gen.OBJECTIVE_SHIFTS)
    arms = report["cost_averse"]["mean_regret"]
    assert arms["ppo_retrained"] is not None and arms["ppo_stale"] is not None
    assert report["service_critical"]["mean_regret"]["ppo_retrained"] is None  # no run recorded for that shift
    assert np.isfinite(arms["stackelberg_rebuilt"]) and arms["rule_based"] >= 0.0
    assert 0 <= report["cost_averse"]["optimum_changed_in"] <= len(TRAINING_SCENARIOS())
