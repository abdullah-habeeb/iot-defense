"""Proposals the device cannot perform are shown with their measured score and a reason, never executed. No Mininet."""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from iot_defense.agents.decision_agent import DecisionAgent
from iot_defense.defense.arbiter import ArbiterPolicy
from iot_defense.defense.decision import DefenseAction as A
from iot_defense.defense.decision import DefenseDecision
from iot_defense.defense.pipeline import PolicyPipeline, arbitrate_for_device
from iot_defense.detection.threat_event import ThreatEvent
from iot_defense.live import defender as defender_module
from iot_defense.live.backend import SUPPORTED_ACTIONS, UNAVAILABLE_REASONS

REAL_TABLE = Path(__file__).resolve().parents[1] / "data" / "outcomes" / "outcome_table.jsonl"
needs_table = pytest.mark.skipif(not REAL_TABLE.exists(), reason="measured outcome table not present")


def decision(action: A, policy: str) -> DefenseDecision:
    return DefenseDecision.create(action=action, target_ip="10.0.0.10", source_ip="10.0.0.100", reason="r", confidence=0.9, threat_score=0.9, policy_name=policy, context={})


def exfil_proposals():
    return {"rule_based": decision(A.ISOLATE, "r"), "stackelberg": decision(A.QUARANTINE, "s"), "ppo": decision(A.QUARANTINE, "p")}


class TestReasons:
    def test_every_response_the_device_cannot_perform_has_a_one_sentence_reason(self):
        assert set(UNAVAILABLE_REASONS) == set(A) - SUPPORTED_ACTIONS
        for action, reason in UNAVAILABLE_REASONS.items():
            assert reason.endswith(".") and len(reason) <= 140, (action, reason)

    def test_quarantine_says_why_in_plain_words(self):
        reason = UNAVAILABLE_REASONS[A.QUARANTINE]
        assert "outgoing" in reason and "incoming" in reason and "not built" in reason

    def test_the_live_defender_hands_them_to_its_pipeline(self):
        assert "unavailable_reasons=UNAVAILABLE_REASONS" in inspect.getsource(defender_module)


@needs_table
class TestUnavailableInTheVerdict:
    def verdict(self, reasons=UNAVAILABLE_REASONS, label="data_exfiltration"):
        chosen, _kept, _excluded = arbitrate_for_device(ArbiterPolicy.from_config(consider_all_supported=True), label, exfil_proposals(), SUPPORTED_ACTIONS, reasons)
        return chosen, chosen.context["arbiter_reasoning"]

    def test_the_better_measured_response_is_listed_with_its_score_who_proposed_it_and_why_it_is_unavailable(self):
        chosen, reasoning = self.verdict()
        assert chosen.action == A.FORENSIC_CAPTURE
        quarantine, isolate = reasoning["unavailable"]  # best measured first
        assert quarantine["action"] == "QUARANTINE" and sorted(quarantine["proposed_by"]) == ["ppo", "stackelberg"]
        assert quarantine["reason"] == UNAVAILABLE_REASONS[A.QUARANTINE]
        assert isolate["action"] == "ISOLATE" and isolate["proposed_by"] == ["rule_based"]
        executed = next(c for c in reasoning["candidates"] if c["action"] == "FORENSIC_CAPTURE")
        assert quarantine["evidence"]["mean"] > executed["evidence"]["mean"] + 2.0  # 7.30 against 4.70-ish: the gap the dashboard explains
        assert quarantine["evidence"]["n"] >= 2

    def test_unavailable_actions_are_never_candidates(self):
        _chosen, reasoning = self.verdict()
        assert {"QUARANTINE", "ISOLATE"}.isdisjoint(c["action"] for c in reasoning["candidates"])

    def test_without_reasons_the_entry_still_appears_with_none(self):
        _chosen, reasoning = self.verdict(reasons=None)
        assert all(u["reason"] is None for u in reasoning["unavailable"]) and len(reasoning["unavailable"]) == 2

    def test_nothing_set_aside_gives_an_empty_list(self):
        proposals = {"stackelberg": decision(A.BLOCK_SOURCE, "s"), "ppo": decision(A.BLOCK_SOURCE, "p")}
        chosen, _k, _e = arbitrate_for_device(ArbiterPolicy.from_config(consider_all_supported=True), "dos_flood", proposals, SUPPORTED_ACTIONS, UNAVAILABLE_REASONS)
        assert chosen.context["arbiter_reasoning"]["unavailable"] == []

    def test_a_set_aside_proposal_that_scores_lower_is_still_listed(self):
        proposals = {"stackelberg": decision(A.BLOCK_SOURCE, "s"), "rule_based": decision(A.DECOY, "r")}
        chosen, _k, _e = arbitrate_for_device(ArbiterPolicy.from_config(consider_all_supported=True), "dos_flood", proposals, SUPPORTED_ACTIONS, UNAVAILABLE_REASONS)
        (decoy,) = chosen.context["arbiter_reasoning"]["unavailable"]
        assert chosen.action == A.BLOCK_SOURCE and decoy["action"] == "DECOY" and decoy["reason"] == UNAVAILABLE_REASONS[A.DECOY]


@needs_table
def test_the_pipeline_passes_the_reasons_through(monkeypatch):
    event = ThreatEvent.from_result(
        source_ip="10.0.0.100", destination_ip="10.0.0.10", attack_type="data_exfiltration", threat_score=0.9, confidence=0.88,
        detection_reason="t", features={"packets_per_second": 4.0, "average_packet_size": 900.0, "packet_count": 40}, detector_name="t",
    )
    context = DecisionAgent().build_context(event, device_criticality="high")
    proposals = exfil_proposals()
    comparison = {name: d.to_dict() for name, d in proposals.items()}
    monkeypatch.setattr("iot_defense.defense.pipeline.compute_proposals", lambda *_a, **_k: (comparison, proposals["rule_based"], proposals["stackelberg"], proposals["ppo"]))
    pipeline = PolicyPipeline("arbiter", supported_actions=SUPPORTED_ACTIONS, arbiter=ArbiterPolicy.from_config(consider_all_supported=True), unavailable_reasons=UNAVAILABLE_REASONS)
    evaluation = pipeline.decide(context)
    assert evaluation.selected.action == A.FORENSIC_CAPTURE
    assert evaluation.selected.context["arbiter_reasoning"]["unavailable"][0]["reason"] == UNAVAILABLE_REASONS[A.QUARANTINE]
    assert evaluation.comparison["arbiter"]["context"]["arbiter_reasoning"]["unavailable"][0]["action"] == "QUARANTINE"
