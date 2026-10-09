"""Tests for defense/arbiter.py (evidence-based arbitration), the demo
controller's policy modes, and evaluation/arbiter_eval.py. No Mininet."""

from __future__ import annotations

import ast
import inspect
import json
from unittest.mock import patch

import pytest

from iot_defense.defense import arbiter as arbiter_module
from iot_defense.defense.arbiter import ARBITER_NAME, POLICY_MODES, ArbiterPolicy, select_decision
from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.objective import Objective
from iot_defense.demo.controller import DemoController
from iot_defense.detection.threat_event import ThreatEvent
from iot_defense.evaluation.arbiter_eval import evaluate
from iot_defense.evaluation.outcome import Measurement, OutcomeTable

OBJECTIVE = Objective.load()
LABEL = "dos_flood_distributed"


def decision(action: DefenseAction, policy="p") -> DefenseDecision:
    return DefenseDecision.create(
        action=action, target_ip="10.0.0.10", source_ip="10.0.0.100", reason="r", confidence=0.8,
        threat_score=0.9, policy_name=policy, context={"beliefs": {"observed_features": {"protocol": "UDP"}}},
    )


def table_with(spec: dict[DefenseAction, list[tuple[int, float]]], label=LABEL) -> OutcomeTable:
    """spec: action -> [(residual packets out of 100, service_loss), ...] per measured run."""
    rows = [
        Measurement(label, action, "success", 100, residual, loss, False).to_row()
        for action, runs in spec.items()
        for residual, loss in runs
    ]
    return OutcomeTable(rows, OBJECTIVE)


A, B, C = DefenseAction.THROTTLE, DefenseAction.QUARANTINE, DefenseAction.ISOLATE


class TestArbitration:
    def test_executes_the_proposal_with_the_best_measured_utility(self):
        table = table_with({A: [(0, 0.0)] * 3, B: [(0, 0.35)] * 3, C: [(0, 1.0)] * 3})
        proposals = {"rule_based": decision(C), "stackelberg": decision(B), "ppo": decision(A)}
        chosen = ArbiterPolicy(table).arbitrate(LABEL, proposals)
        assert chosen.action == A
        assert chosen.policy_name == ARBITER_NAME
        assert chosen.context["arbiter_reasoning"]["chosen_from"] == "ppo"

    def test_never_executes_an_action_nobody_proposed(self):
        table = table_with({A: [(0, 0.0)] * 3, B: [(50, 0.0)] * 3, C: [(100, 1.0)] * 3})  # A is best
        chosen = ArbiterPolicy(table).arbitrate(LABEL, {"stackelberg": decision(B), "rule_based": decision(C)})
        assert chosen.action == B  # A scores higher but was not proposed

    def test_risk_aversion_trades_a_higher_mean_for_dependability(self):
        high_mean_erratic = [(0, 0.0)] * 3 + [(100, 0.0)]    # mean containment .75
        steady_lower = [(40, 0.0)] * 4                       # containment .60
        table = table_with({A: high_mean_erratic, B: steady_lower})
        proposals = {"stackelberg": decision(A), "ppo": decision(B)}
        assert ArbiterPolicy(table, risk_aversion=0.0).arbitrate(LABEL, proposals).action == A
        assert ArbiterPolicy(table, risk_aversion=2.0).arbitrate(LABEL, proposals).action == B

    def test_ties_go_to_stackelberg_then_ppo_then_rule_based(self):
        table = table_with({A: [(0, 0.0)] * 3})
        same = {"rule_based": decision(A), "ppo": decision(A), "stackelberg": decision(A)}
        assert ArbiterPolicy(table).arbitrate(LABEL, same).context["arbiter_reasoning"]["chosen_from"] == "stackelberg"
        without_stack = {"rule_based": decision(A), "ppo": decision(A)}
        assert ArbiterPolicy(table).arbitrate(LABEL, without_stack).context["arbiter_reasoning"]["chosen_from"] == "ppo"

    def test_with_no_evidence_for_any_proposal_it_falls_back_and_says_so(self):
        table = table_with({A: [(0, 0.0)] * 3}, label="some_other_attack")
        chosen = ArbiterPolicy(table).arbitrate(LABEL, {"rule_based": decision(C), "stackelberg": decision(B)})
        assert chosen.action == B
        assert "fell back to stackelberg" in chosen.context["arbiter_reasoning"]["basis"]
        assert "no measurements" in chosen.reason

    def test_actions_with_too_few_measurements_carry_no_evidence(self):
        table = table_with({A: [(0, 0.0)], B: [(50, 0.0)] * 3})  # A is perfect but measured only once
        chosen = ArbiterPolicy(table, min_samples=2).arbitrate(LABEL, {"ppo": decision(A), "stackelberg": decision(B)})
        assert chosen.action == B

    def test_a_single_proposal_is_returned_with_its_own_context(self):
        chosen = ArbiterPolicy(table_with({A: [(0, 0.0)] * 3})).arbitrate(LABEL, {"ppo": decision(A)})
        assert chosen.action == A and chosen.context["beliefs"]["observed_features"]["protocol"] == "UDP"
        assert chosen.target_ip == "10.0.0.10" and chosen.source_ip == "10.0.0.100"

    def test_no_proposals_is_an_error(self):
        with pytest.raises(ValueError):
            ArbiterPolicy(table_with({A: [(0, 0.0)] * 3})).arbitrate(LABEL, {})

    def test_reasoning_lists_every_proposal_with_its_evidence(self):
        table = table_with({A: [(0, 0.0)] * 3, C: [(0, 1.0)] * 3})
        chosen = ArbiterPolicy(table).arbitrate(LABEL, {"rule_based": decision(C), "ppo": decision(A)})
        proposals = chosen.context["arbiter_reasoning"]["proposals"]
        assert set(proposals) == {"rule_based", "ppo"} and proposals["ppo"]["evidence"]["n"] == 3
        assert "THROTTLE from ppo" in chosen.reason and "ISOLATE from rule_based" in chosen.reason

    def test_the_arbiter_never_reads_a_registered_preferred_action(self):
        tree = ast.parse(inspect.getsource(arbiter_module))
        used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        assert "preferred_action" not in used


class TestFromConfig:
    def test_missing_table_gives_none_not_an_error(self, tmp_path):
        with patch("iot_defense.defense.arbiter.load_policy_section", return_value={
            "outcome_table_path": str(tmp_path / "nope.jsonl"), "risk_aversion": 1.0, "min_samples": 2,
        }):
            assert ArbiterPolicy.from_config() is None

    def test_builds_from_a_real_table(self, tmp_path, synthetic_table_path):
        with patch("iot_defense.defense.arbiter.load_policy_section", return_value={
            "outcome_table_path": str(synthetic_table_path), "risk_aversion": 0.5, "min_samples": 3,
        }):
            built = ArbiterPolicy.from_config()
        assert built is not None and built.risk_aversion == 0.5 and built.min_samples == 3


class TestSelectDecision:
    rule, stack, ppo, arb = decision(C, "rule"), decision(B, "stack"), decision(A, "ppo"), decision(A, ARBITER_NAME)

    @pytest.mark.parametrize("mode,expected", [("arbiter", "arbiter"), ("stackelberg", "stack"), ("rule_based", "rule"), ("ppo", "ppo")])
    def test_each_mode_executes_its_own_decision(self, mode, expected):
        picked = select_decision(mode, rule=self.rule, stackelberg=self.stack, ppo=self.ppo, arbiter=self.arb)
        assert picked.policy_name.lower().startswith(expected)

    def test_a_missing_decision_degrades_to_stackelberg_then_rule_based(self):
        assert select_decision("ppo", rule=self.rule, stackelberg=self.stack, ppo=None, arbiter=None) is self.stack
        assert select_decision("arbiter", rule=self.rule, stackelberg=self.stack, ppo=None, arbiter=None) is self.stack
        assert select_decision("arbiter", rule=self.rule, stackelberg=None, ppo=None, arbiter=None) is self.rule

    def test_unknown_mode_is_rejected(self):
        with pytest.raises(ValueError, match="unknown policy mode"):
            select_decision("democracy", rule=self.rule, stackelberg=None, ppo=None, arbiter=None)


class TestDemoControllerModes:
    def event(self):
        return ThreatEvent.from_result(
            source_ip="10.0.0.100", destination_ip="10.0.0.10", attack_type="dos_flood",
            threat_score=0.9, confidence=0.9, detection_reason="t",
            features={"packets_per_second": 40.0, "unique_destination_ports": 1}, detector_name="t",
        )

    def test_default_mode_is_the_arbiter_and_bad_modes_are_rejected(self):
        assert DemoController().policy_mode == "arbiter"
        assert set(POLICY_MODES) == {"arbiter", "stackelberg", "rule_based", "ppo"}
        with pytest.raises(ValueError):
            DemoController(policy_mode="vote")

    def test_non_arbiter_modes_never_load_the_table(self):
        controller = DemoController(policy_mode="stackelberg")
        context = controller.decision_agent.build_context(self.event(), device_criticality="high")
        with patch.object(ArbiterPolicy, "from_config", side_effect=AssertionError("must not load")):
            assert controller._arbitrate(context, decision(C), decision(B), decision(A)) is None

    def test_arbiter_mode_without_a_table_falls_back_to_stackelberg(self, capsys):
        controller = DemoController(policy_mode="arbiter")
        context = controller.decision_agent.build_context(self.event(), device_criticality="high")
        with patch.object(ArbiterPolicy, "from_config", return_value=None):
            assert controller._arbitrate(context, decision(C), decision(B), decision(A)) is None
        assert "no measured outcome table" in capsys.readouterr().out

    def test_arbiter_mode_arbitrates_over_whichever_policies_proposed(self, synthetic_table):
        controller = DemoController(policy_mode="arbiter")
        controller._arbiter, controller._arbiter_loaded = ArbiterPolicy(synthetic_table), True
        context = controller.decision_agent.build_context(self.event(), device_criticality="high")
        chosen = controller._arbitrate(context, decision(C, "rule"), None, decision(A, "ppo"))
        assert chosen.policy_name == ARBITER_NAME
        assert set(chosen.context["arbiter_reasoning"]["proposals"]) == {"rule_based", "ppo"}


class TestOfflineEvaluation:
    ARMS = ("rule_based", "stackelberg", "ppo", "always_allow", "naive_block_all")

    def results(self, tmp_path, actions_by_arm, trials=6):
        """Harness-shaped rows for LABEL; utility comes from the (invented) measured vectors."""
        measured = {A: (1.0, 0.0), B: (1.0, 0.35), C: (1.0, 1.0), DefenseAction.ALLOW: (0.0, 0.0)}
        rows = []
        for trial in range(trials):
            for arm in self.ARMS:
                action = actions_by_arm.get(arm, DefenseAction.ALLOW)
                containment, loss = measured[action]
                rows.append({
                    "condition": LABEL, "trial": trial, "arm": arm, "action": action.value, "containment": containment,
                    "service_loss": loss, "intel_verified": False, "valid_measurement": True, "execution_ok": True,
                    "matches_preferred_action": False, "detection_correct": True, "detected_attack_type": LABEL,
                })
        path = tmp_path / "results.jsonl"
        path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        return path

    def table_path(self, tmp_path):
        rows = [
            Measurement(LABEL, action, "success", 100, 0 if containment else 100, loss, False).to_row()
            for action, (containment, loss) in {A: (1, 0.0), B: (1, 0.35), C: (1, 1.0), DefenseAction.ALLOW: (0, 0.0)}.items()
            for _ in range(3)
        ]
        path = tmp_path / "table.jsonl"
        path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        return path

    def test_arbiter_matches_the_best_proposal_and_beats_the_weaker_policies(self, tmp_path):
        results = self.results(tmp_path, {"rule_based": C, "stackelberg": B, "ppo": A})
        report = evaluate(results, self.table_path(tmp_path))
        arms = report["arms"]
        assert arms["arbiter"]["mean_utility"] == pytest.approx(arms["ppo"]["mean_utility"])
        assert arms["arbiter"]["mean_utility"] > arms["stackelberg"]["mean_utility"] > arms["rule_based"]["mean_utility"]
        assert arms["best_of_three"]["mean_utility"] == pytest.approx(arms["arbiter"]["mean_utility"])
        assert report["arbiter_chose_proposal_of"] == {"rule_based": 0, "stackelberg": 0, "ppo": 6}
        assert report["trials_without_evidence"] == 0

    def test_when_all_policies_agree_the_arbiter_adds_nothing(self, tmp_path):
        results = self.results(tmp_path, {"rule_based": A, "stackelberg": A, "ppo": A})
        report = evaluate(results, self.table_path(tmp_path))
        assert report["arbiter_minus"]["ppo"]["mean_diff"] == 0.0 and report["arbiter_minus"]["ppo"]["wilcoxon_p"] == 1.0
        assert report["conditions_where_arbiter_differs_from_stackelberg"] == {}

    def test_it_cannot_beat_the_best_of_three_in_hindsight(self, tmp_path):
        results = self.results(tmp_path, {"rule_based": C, "stackelberg": B, "ppo": A})
        report = evaluate(results, self.table_path(tmp_path))
        assert report["best_of_three_minus_arbiter"]["mean_diff"] >= 0.0

    def test_trials_with_an_invalid_arm_are_excluded(self, tmp_path):
        path = self.results(tmp_path, {"ppo": A})
        lines = [json.loads(l) for l in path.read_text().splitlines()]
        lines[0]["valid_measurement"] = False
        path.write_text("".join(json.dumps(r) + "\n" for r in lines), encoding="utf-8")
        assert evaluate(path, self.table_path(tmp_path))["excluded_trials"] == 1
