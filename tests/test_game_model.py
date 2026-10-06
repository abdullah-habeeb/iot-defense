"""Unit tests for defense/game_model.py: the Stackelberg payoffs come from an
a-priori mechanism model, independent of every registered preferred_action."""

from __future__ import annotations

import ast
import copy
import dataclasses
import inspect

import pytest

from iot_defense.attacks.registry import ATTACK_SCENARIOS
from iot_defense.defense import game_model, stackelberg
from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.game_model import build_game_payoffs
from iot_defense.defense.objective import Objective, load_policy_section
from iot_defense.defense.stackelberg import StackelbergGame


def test_payoffs_cover_normal_and_every_threat_and_action():
    payoffs = build_game_payoffs()
    assert set(payoffs) == {"NORMAL"} | {s.observed_threat_key for s in ATTACK_SCENARIOS.values()}
    for by_action in payoffs.values():
        assert set(by_action) == {a.value for a in DefenseAction}
        for by_response in by_action.values():
            assert set(by_response) == {"CONTINUE", "RETREAT"}
            for cell in by_response.values():
                assert set(cell) == {"attacker", "defender"}


def test_every_registered_attack_has_a_class():
    classes = load_policy_section("game_model")["attack_class"]
    assert {s.attack_type for s in ATTACK_SCENARIOS.values()} <= set(classes)


def test_unclassified_attack_fails_loudly():
    model = copy.deepcopy(load_policy_section("game_model"))
    del model["attack_class"]["dos_flood"]
    with pytest.raises(ValueError, match="dos_flood"):
        build_game_payoffs(model)


def test_solver_returns_a_valid_action_for_every_threat():
    game = StackelbergGame()
    for key in build_game_payoffs():
        solution = game.solve(key)
        assert isinstance(solution.selected_action, DefenseAction)
        assert len(solution.candidates) == len(DefenseAction)


def test_normal_traffic_is_allowed():
    assert StackelbergGame().solve("NORMAL").selected_action == DefenseAction.ALLOW


def test_isolate_destroys_benign_service_value():
    objective = Objective.load()
    cell = build_game_payoffs()["NORMAL"]["ISOLATE"]["CONTINUE"]
    assert cell["defender"] == pytest.approx(-objective.action_cost[DefenseAction.ISOLATE])


def test_strong_containment_deters_the_attacker_and_weak_containment_does_not():
    payoffs = build_game_payoffs()
    flood = payoffs["DOS_FLOOD"]
    game = StackelbergGame(payoffs)
    assert game.attacker_best_response("DOS_FLOOD", DefenseAction.ISOLATE)[0] == "RETREAT"
    assert game.attacker_best_response("DOS_FLOOD", DefenseAction.ALLOW)[0] == "CONTINUE"
    assert flood["ALLOW"]["CONTINUE"]["attacker"] > 0


def test_changing_a_mechanism_prior_changes_the_decision():
    model = copy.deepcopy(load_policy_section("game_model"))
    baseline = StackelbergGame(build_game_payoffs(model)).solve("DOS_FLOOD").selected_action
    # Make the baseline's chosen action mechanically useless against floods.
    model["containment_prior"][baseline.value]["flood"] = 0.0
    changed = StackelbergGame(build_game_payoffs(model)).solve("DOS_FLOOD").selected_action
    assert changed != baseline


def test_payoffs_do_not_depend_on_any_registered_preferred_action(monkeypatch):
    before = build_game_payoffs()
    for key, scenario in ATTACK_SCENARIOS.items():
        monkeypatch.setitem(ATTACK_SCENARIOS, key, dataclasses.replace(scenario, preferred_action=DefenseAction.QUARANTINE))
    assert build_game_payoffs() == before


@pytest.mark.parametrize("module", [game_model, stackelberg])
def test_stackelberg_modules_never_read_preferred_action(module):
    tree = ast.parse(inspect.getsource(module))
    used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | {
        n.id for n in ast.walk(tree) if isinstance(n, ast.Name)
    }
    assert "preferred_action" not in used
