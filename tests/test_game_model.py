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
from iot_defense.defense.game_model import build_game_payoffs, with_rotation
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


class TestFollowerRotation:
    """The optional third follower strategy: switch to a fresh source address."""

    @staticmethod
    def rotating():
        return build_game_payoffs(model=with_rotation(load_policy_section("game_model")))

    def test_it_is_off_by_default_so_the_deployed_game_is_unchanged(self):
        assert load_policy_section("game_model")["follower_rotation"]["enabled"] is False
        for by_action in build_game_payoffs().values():
            for by_response in by_action.values():
                assert set(by_response) == {"CONTINUE", "RETREAT"}

    def test_only_the_configured_spoofable_attacks_gain_the_strategy(self):
        configured = set(load_policy_section("game_model")["follower_rotation"]["rotatable_attack_types"])
        payoffs = self.rotating()
        for scenario in ATTACK_SCENARIOS.values():
            has = "ROTATE_SOURCE" in payoffs[scenario.observed_threat_key]["BLOCK_SOURCE"]
            assert has == (scenario.attack_type in configured), scenario.attack_type
        assert "ROTATE_SOURCE" not in payoffs["NORMAL"]["BLOCK_SOURCE"]

    def test_a_source_keyed_response_is_dodged_by_rotating_and_an_unkeyed_one_is_not(self):
        game = StackelbergGame(self.rotating())
        assert game.attacker_best_response("DOS_FLOOD", DefenseAction.BLOCK_SOURCE)[0] == "ROTATE_SOURCE"
        assert game.attacker_best_response("DOS_FLOOD", DefenseAction.THROTTLE)[0] == "RETREAT"
        assert game.attacker_best_response("DOS_FLOOD", DefenseAction.ALLOW)[0] == "CONTINUE"  # nothing to dodge: rotating only costs

    def test_rotation_cost_is_what_makes_it_a_choice_and_not_a_free_move(self):
        cheap = with_rotation(load_policy_section("game_model"))
        cheap["follower_rotation"]["cost"] = 0.0
        costly = with_rotation(load_policy_section("game_model"))
        costly["follower_rotation"]["cost"] = 100.0
        free = build_game_payoffs(model=cheap)["DOS_FLOOD"]["ALLOW"]
        assert free["ROTATE_SOURCE"]["attacker"] == pytest.approx(free["CONTINUE"]["attacker"])
        prohibitive = StackelbergGame(build_game_payoffs(model=costly))
        assert prohibitive.attacker_best_response("DOS_FLOOD", DefenseAction.BLOCK_SOURCE)[0] != "ROTATE_SOURCE"

    def test_the_leader_anticipates_rotation_and_moves_off_the_source_block(self):
        plain = StackelbergGame(build_game_payoffs()).solve("DOS_FLOOD")
        anticipating = StackelbergGame(self.rotating()).solve("DOS_FLOOD")
        assert plain.selected_action == DefenseAction.BLOCK_SOURCE
        assert anticipating.selected_action not in (DefenseAction.BLOCK_SOURCE, DefenseAction.DECOY, DefenseAction.RESET_SESSIONS)
        assert anticipating.predicted_attacker_strategy in ("RETREAT", "CONTINUE")
        assert "ROTATE_SOURCE" in {c.predicted_attacker_strategy for c in anticipating.candidates}

    def test_attacks_that_cannot_spoof_are_not_second_guessed(self):
        for threat in ("BRUTE_FORCE", "RECONNAISSANCE_PORT_SCAN", "DATA_EXFILTRATION"):
            key = next(s.observed_threat_key for s in ATTACK_SCENARIOS.values() if s.observed_threat_key.upper() == threat)
            assert StackelbergGame(self.rotating()).solve(key).selected_action == StackelbergGame(build_game_payoffs()).solve(key).selected_action

    def test_a_response_keyed_on_the_address_loses_its_intelligence_when_the_attacker_moves(self):
        payoffs = self.rotating()["DOS_FLOOD"]["DECOY"]
        gap = payoffs["CONTINUE"]["defender"] - payoffs["ROTATE_SOURCE"]["defender"]
        assert gap > 0  # the decoy's containment and intelligence both vanish after the switch

    def test_the_config_names_only_real_attacks_and_actions(self):
        config = load_policy_section("game_model")["follower_rotation"]
        assert set(config["rotatable_attack_types"]) <= {s.attack_type for s in ATTACK_SCENARIOS.values()}
        assert set(config["source_keyed_actions"]) <= {a.value for a in DefenseAction}

    def test_with_rotation_does_not_mutate_the_loaded_model(self):
        model = load_policy_section("game_model")
        before = copy.deepcopy(model)
        with_rotation(model)
        assert model == before
