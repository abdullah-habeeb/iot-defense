"""The arbiter's candidate set: the policies' proposals plus every action the device can perform
(policy.arbiter.consider_all_supported). No Mininet."""

from __future__ import annotations

import itertools
from pathlib import Path
from unittest.mock import patch

import pytest

from iot_defense.defense.arbiter import ARBITER_NAME, NOT_PROPOSED, ArbiterPolicy
from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.objective import Objective
from iot_defense.defense.pipeline import arbitrate_for_device
from iot_defense.evaluation.outcome import Measurement, OutcomeTable
from iot_defense.live.backend import SUPPORTED_ACTIONS

OBJECTIVE = Objective.load()
LABEL = "data_exfiltration"
THROTTLE, FORENSIC, RESET = DefenseAction.THROTTLE, DefenseAction.FORENSIC_CAPTURE, DefenseAction.RESET_SESSIONS
QUARANTINE, ISOLATE, BLOCK, ALERT, ALLOW = (
    DefenseAction.QUARANTINE, DefenseAction.ISOLATE, DefenseAction.BLOCK_SOURCE, DefenseAction.ALERT, DefenseAction.ALLOW,
)
REAL_TABLE = Path(__file__).resolve().parents[1] / "data" / "outcomes" / "outcome_table.jsonl"


def decision(action: DefenseAction, policy="p") -> DefenseDecision:
    return DefenseDecision.create(
        action=action, target_ip="10.0.0.10", source_ip="10.0.0.100", reason="r", confidence=0.8, threat_score=0.9,
        policy_name=policy,
        context={"beliefs": {"observed_features": {"protocol": "UDP"}}, "stackelberg_reasoning": {"x": 1}, "ppo_action_index": 3},
    )


def table_with(spec: dict[DefenseAction, list[tuple[int, float]]], label=LABEL) -> OutcomeTable:
    """spec: action -> [(residual packets out of 100, service_loss), ...] per measured run."""
    rows = [Measurement(label, action, "success", 100, residual, loss, False).to_row() for action, runs in spec.items() for residual, loss in runs]
    return OutcomeTable(rows, OBJECTIVE)


# THROTTLE contains 20% and loses half the service (2.1); FORENSIC contains nothing, loses nothing (2.7); RESET equals THROTTLE's cost.
POOR_THROTTLE = [(80, 0.5)] * 3
CLEAN_FORENSIC = [(100, 0.0)] * 3


class TestNonProposedCandidates:
    def test_a_supported_action_nobody_proposed_wins_on_better_evidence(self):
        table = table_with({THROTTLE: POOR_THROTTLE, FORENSIC: CLEAN_FORENSIC})
        chosen = ArbiterPolicy(table, consider_all_supported=True).arbitrate(
            LABEL, {"ppo": decision(THROTTLE)}, available={THROTTLE, FORENSIC}
        )
        reasoning = chosen.context["arbiter_reasoning"]
        assert chosen.action == FORENSIC and chosen.policy_name == ARBITER_NAME
        assert reasoning["chosen_from"] == NOT_PROPOSED and reasoning["chosen_proposed"] is False
        assert "not proposed by any policy" in chosen.reason
        by_action = {c["action"]: c for c in reasoning["candidates"]}
        assert by_action["FORENSIC_CAPTURE"]["proposed_by"] == [] and by_action["THROTTLE"]["proposed_by"] == ["ppo"]
        assert reasoning["candidates"][0]["action"] == "FORENSIC_CAPTURE"  # best-scoring first
        assert set(reasoning["proposals"]) == {"ppo"}  # the proposals view is unchanged

    def test_the_executed_decision_keeps_the_target_source_and_shared_context_but_not_one_policys_own(self):
        table = table_with({THROTTLE: POOR_THROTTLE, FORENSIC: CLEAN_FORENSIC})
        chosen = ArbiterPolicy(table, consider_all_supported=True).arbitrate(LABEL, {"stackelberg": decision(THROTTLE)}, available={THROTTLE, FORENSIC})
        assert (chosen.target_ip, chosen.source_ip) == ("10.0.0.10", "10.0.0.100")
        assert chosen.context["beliefs"]["observed_features"]["protocol"] == "UDP"
        assert "stackelberg_reasoning" not in chosen.context and "ppo_action_index" not in chosen.context

    def test_behaviour_is_unchanged_where_a_proposal_is_already_the_best_supported_action(self):
        table = table_with({THROTTLE: [(0, 0.0)] * 3, FORENSIC: CLEAN_FORENSIC})
        proposals = {"ppo": decision(THROTTLE), "rule_based": decision(FORENSIC)}
        before = ArbiterPolicy(table, consider_all_supported=False).arbitrate(LABEL, proposals)
        after = ArbiterPolicy(table, consider_all_supported=True).arbitrate(LABEL, proposals, available={THROTTLE, FORENSIC, ALERT})
        assert before.action == after.action == THROTTLE
        assert before.context["arbiter_reasoning"]["chosen_from"] == after.context["arbiter_reasoning"]["chosen_from"] == "ppo"
        assert after.context["arbiter_reasoning"]["chosen_proposed"] is True

    def test_with_the_setting_off_only_proposals_are_candidates(self):
        table = table_with({THROTTLE: POOR_THROTTLE, FORENSIC: CLEAN_FORENSIC})
        chosen = ArbiterPolicy(table, consider_all_supported=False).arbitrate(LABEL, {"ppo": decision(THROTTLE)}, available={THROTTLE, FORENSIC})
        assert chosen.action == THROTTLE
        assert [c["action"] for c in chosen.context["arbiter_reasoning"]["candidates"]] == ["THROTTLE"]

    def test_an_action_the_device_cannot_perform_is_never_a_candidate(self):
        table = table_with({THROTTLE: POOR_THROTTLE, FORENSIC: CLEAN_FORENSIC, ISOLATE: [(0, 0.0)] * 3})  # ISOLATE is best here
        chosen = ArbiterPolicy(table, consider_all_supported=True).arbitrate(LABEL, {"ppo": decision(THROTTLE)}, available={THROTTLE, FORENSIC})
        assert chosen.action == FORENSIC
        assert "ISOLATE" not in {c["action"] for c in chosen.context["arbiter_reasoning"]["candidates"]}

    def test_without_a_restriction_every_action_is_considered(self):
        table = table_with({THROTTLE: POOR_THROTTLE, ISOLATE: [(0, 0.0)] * 3})
        chosen = ArbiterPolicy(table, consider_all_supported=True).arbitrate(LABEL, {"ppo": decision(THROTTLE)})
        assert chosen.action == ISOLATE
        assert len(chosen.context["arbiter_reasoning"]["candidates"]) == len(DefenseAction)


class TestDeterministicTies:
    SAME = [(60, 0.2)] * 3  # THROTTLE and RESET_SESSIONS cost the same, so identical measurements tie exactly

    def table(self):
        return table_with({THROTTLE: self.SAME, RESET: self.SAME, FORENSIC: POOR_THROTTLE})

    def test_a_proposed_action_beats_an_unproposed_one_on_a_tie(self):
        chosen = ArbiterPolicy(self.table(), consider_all_supported=True).arbitrate(
            LABEL, {"rule_based": decision(RESET)}, available={THROTTLE, RESET, FORENSIC}
        )
        assert chosen.action == RESET and chosen.context["arbiter_reasoning"]["chosen_proposed"] is True  # THROTTLE ties and is declared earlier

    def test_among_proposals_the_policy_order_decides(self):
        arbiter = ArbiterPolicy(self.table(), consider_all_supported=True)
        proposals = {"rule_based": decision(THROTTLE), "stackelberg": decision(RESET), "ppo": decision(FORENSIC)}
        for names in itertools.permutations(proposals):
            chosen = arbiter.arbitrate(LABEL, {n: proposals[n] for n in names}, available={THROTTLE, RESET, FORENSIC})
            assert chosen.action == RESET and chosen.context["arbiter_reasoning"]["chosen_from"] == "stackelberg"

    def test_among_unproposed_actions_the_enum_order_decides(self):
        arbiter = ArbiterPolicy(self.table(), consider_all_supported=True)
        for available in ({THROTTLE, RESET, ALERT}, {RESET, ALERT, THROTTLE}):
            chosen = arbiter.arbitrate(LABEL, {"ppo": decision(FORENSIC)}, available=available)
            assert chosen.action == THROTTLE  # declared before RESET_SESSIONS
            assert chosen.context["arbiter_reasoning"]["chosen_from"] == NOT_PROPOSED


class TestNoEvidenceAndEmptyProposals:
    def test_with_no_evidence_for_any_candidate_it_falls_back_to_the_first_policy(self):
        table = table_with({THROTTLE: POOR_THROTTLE}, label="some_other_attack")
        chosen = ArbiterPolicy(table, consider_all_supported=True).arbitrate(
            LABEL, {"rule_based": decision(ISOLATE), "stackelberg": decision(QUARANTINE)}, available={THROTTLE, FORENSIC}
        )
        assert chosen.action == QUARANTINE
        assert "fell back to stackelberg" in chosen.context["arbiter_reasoning"]["basis"]

    def test_nothing_proposed_and_no_template_is_an_error_with_either_setting(self):
        table = table_with({THROTTLE: POOR_THROTTLE})
        for flag in (False, True):
            with pytest.raises(ValueError):
                ArbiterPolicy(table, consider_all_supported=flag).arbitrate(LABEL, {}, available={THROTTLE})

    def test_nothing_proposed_a_template_and_no_evidence_is_an_error(self):
        table = table_with({THROTTLE: POOR_THROTTLE}, label="some_other_attack")
        with pytest.raises(ValueError):
            ArbiterPolicy(table, consider_all_supported=True).arbitrate(LABEL, {}, available={THROTTLE}, template=decision(ISOLATE))

    def test_nothing_proposed_but_a_template_chooses_among_the_available_actions(self):
        table = table_with({THROTTLE: POOR_THROTTLE, FORENSIC: CLEAN_FORENSIC})
        chosen = ArbiterPolicy(table, consider_all_supported=True).arbitrate(LABEL, {}, available={THROTTLE, FORENSIC}, template=decision(ISOLATE, "rule_based"))
        assert chosen.action == FORENSIC and chosen.context["arbiter_reasoning"]["proposals"] == {}


class TestSetting:
    def config(self, **extra):
        return {"outcome_table_path": str(REAL_TABLE), "risk_aversion": 1.0, "min_samples": 2, **extra}

    @pytest.mark.skipif(not REAL_TABLE.exists(), reason="measured outcome table not present")
    def test_the_configured_setting_is_read_and_can_be_overridden(self):
        with patch("iot_defense.defense.arbiter.load_policy_section", return_value=self.config(consider_all_supported=True)):
            assert ArbiterPolicy.from_config().consider_all_supported is True
            assert ArbiterPolicy.from_config(consider_all_supported=False).consider_all_supported is False
        with patch("iot_defense.defense.arbiter.load_policy_section", return_value=self.config(consider_all_supported=False)):
            assert ArbiterPolicy.from_config(consider_all_supported=True).consider_all_supported is True

    @pytest.mark.skipif(not REAL_TABLE.exists(), reason="measured outcome table not present")
    def test_a_configuration_without_the_key_keeps_the_earlier_behaviour(self):
        with patch("iot_defense.defense.arbiter.load_policy_section", return_value=self.config()):
            assert ArbiterPolicy.from_config().consider_all_supported is False

    def test_the_shipped_configuration_turns_it_on(self):
        from iot_defense.defense.objective import load_policy_section

        assert load_policy_section("arbiter")["consider_all_supported"] is True


@pytest.mark.skipif(not REAL_TABLE.exists(), reason="measured outcome table not present")
class TestTheFourAttacksOnTheLiveDefender:
    """Exfiltration, C2 beaconing, DNS tunneling and firmware tampering: every policy proposes QUARANTINE or ISOLATE,
    which the live defender cannot apply."""

    LABELS = ("data_exfiltration", "c2_beaconing", "dns_tunneling_exfiltration", "firmware_tampering")

    def proposals(self):
        return {"rule_based": decision(ISOLATE, "r"), "stackelberg": decision(QUARANTINE, "s"), "ppo": decision(ISOLATE, "p")}

    def test_the_setting_off_alerts_as_before(self):
        arbiter = ArbiterPolicy.from_config(consider_all_supported=False)
        for label in self.LABELS:
            chosen, kept, excluded = arbitrate_for_device(arbiter, label, self.proposals(), SUPPORTED_ACTIONS)
            assert chosen is None and kept == {} and set(excluded) == {"rule_based", "stackelberg", "ppo"}

    def test_the_setting_on_executes_the_best_supported_action(self):
        arbiter = ArbiterPolicy.from_config(consider_all_supported=True)
        for label in self.LABELS:
            chosen, kept, excluded = arbitrate_for_device(arbiter, label, self.proposals(), SUPPORTED_ACTIONS)
            best = max(SUPPORTED_ACTIONS, key=lambda a: arbiter.score_action(label, a)["score"])
            assert chosen.action == best == FORENSIC, label
            reasoning = chosen.context["arbiter_reasoning"]
            assert reasoning["chosen_from"] == NOT_PROPOSED and reasoning["excluded_unavailable"] == excluded
            assert {c["action"] for c in reasoning["candidates"]} == {a.value for a in SUPPORTED_ACTIONS}

    def test_attacks_the_policies_already_answer_with_a_supported_action_are_unchanged(self):
        on, off = ArbiterPolicy.from_config(consider_all_supported=True), ArbiterPolicy.from_config(consider_all_supported=False)
        proposals = {"rule_based": decision(BLOCK, "r"), "stackelberg": decision(BLOCK, "s"), "ppo": decision(THROTTLE, "p")}
        for label in ("dos_flood", "tcp_syn_flood", "brute_force"):
            assert arbitrate_for_device(on, label, proposals, SUPPORTED_ACTIONS)[0].action == arbitrate_for_device(off, label, proposals, SUPPORTED_ACTIONS)[0].action


class TestArbitrateForDevice:
    def test_without_an_arbiter_it_only_filters(self):
        chosen, kept, excluded = arbitrate_for_device(None, LABEL, {"ppo": decision(ISOLATE), "rule_based": decision(BLOCK)}, SUPPORTED_ACTIONS)
        assert chosen is None and set(kept) == {"rule_based"} and excluded == {"ppo": "ISOLATE"}

    def test_a_partly_available_proposal_set_still_feeds_the_arbiter_its_supported_proposals(self):
        table = table_with({BLOCK: [(0, 0.0)] * 3, FORENSIC: CLEAN_FORENSIC})
        chosen, kept, _ = arbitrate_for_device(
            ArbiterPolicy(table, consider_all_supported=True), LABEL, {"ppo": decision(ISOLATE), "rule_based": decision(BLOCK)}, SUPPORTED_ACTIONS
        )
        assert chosen.action == BLOCK and set(kept) == {"rule_based"}
