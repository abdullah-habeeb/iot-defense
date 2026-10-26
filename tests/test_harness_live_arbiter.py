"""harness --live-arbiter-arms: the two extra arms, their measurement, the resume guard, and their analysis. No Mininet."""

from __future__ import annotations

import json

import pytest

from iot_defense.defense.arbiter import ArbiterPolicy
from iot_defense.defense.context import build_security_context
from iot_defense.defense.decision import DefenseAction as A
from iot_defense.defense.decision import DefenseDecision
from iot_defense.defense.objective import Objective
from iot_defense.detection.threat_event import ThreatEvent
from iot_defense.evaluation import arbiter_candidates_eval as ev
from iot_defense.evaluation.outcome import Measurement, OutcomeTable
from iot_defense.evaluation.harness import ARMS_PER_TRIAL, LIVE_ARBITER_ARMS, live_arbiter_decisions, prepare_output, run_fingerprint, run_trial
from iot_defense.defense.ppo_real_env import RealMininetDefenseEnv

OBJECTIVE = Objective.load()
LABEL = "dos_flood"


def threat_event() -> ThreatEvent:
    return ThreatEvent.from_result(
        source_ip="10.0.0.100", destination_ip="10.0.0.10", attack_type=LABEL, threat_score=0.92, confidence=0.9,
        detection_reason="test fixture", features={"packets_per_second": 40.0, "unique_destination_ports": 1, "packet_count": 200},
        detector_name="RuleBasedDosDetector",
    )


def table() -> OutcomeTable:
    """Everything the policies propose contains the attack and kills the service; FORENSIC_CAPTURE verifies evidence."""
    rows = []
    for rep in range(3):
        for action, (residual, loss, intel) in {A.ALLOW: (100, 0.0, False), A.ALERT: (100, 0.0, False), A.BLOCK_SOURCE: (100, 0.1, False),
                                               A.THROTTLE: (90, 0.1, False), A.ISOLATE: (0, 1.0, False), A.QUARANTINE: (0, 1.0, False),
                                               A.FORENSIC_CAPTURE: (100, 0.0, True)}.items():
            rows.append({**Measurement(LABEL, action, "success", 100, residual, loss, intel).to_row(), "rep": rep})
    return OutcomeTable(rows, OBJECTIVE)


def arbiters():
    return {arm: ArbiterPolicy(table(), consider_all_supported=flag) for arm, flag in zip(LIVE_ARBITER_ARMS, (False, True))}


def decision(action: A, policy: str) -> DefenseDecision:
    return DefenseDecision.create(action=action, target_ip="10.0.0.10", source_ip="10.0.0.100", reason="r", confidence=0.9, threat_score=0.9, policy_name=policy, context={})


class FakePPO:
    def decide(self, context):
        return decision(A.QUARANTINE, "PPODefensePolicy")


@pytest.fixture(autouse=True)
def _no_settle_sleep(monkeypatch):
    monkeypatch.setattr("iot_defense.evaluation.harness.SETTLE_SECONDS", 0.0)


class TestLiveArbiterDecisions:
    def proposals(self):
        return {"rule_based": decision(A.ISOLATE, "r"), "stackelberg": decision(A.QUARANTINE, "s"), "ppo": decision(A.QUARANTINE, "p")}

    def test_proposals_only_alerts_when_the_device_can_apply_none_of_them_and_the_new_arbiter_captures_evidence(self):
        context = build_security_context(threat_event(), device_criticality="high")
        chosen = live_arbiter_decisions(context, self.proposals(), arbiters())
        assert chosen["arbiter_live_before"].action == A.ALERT and chosen["arbiter_live_before"].policy_name == "LiveSafeFallback"
        assert chosen["arbiter_live_after"].action == A.FORENSIC_CAPTURE and chosen["arbiter_live_after"].policy_name == "ArbiterPolicy"

    def test_a_supported_proposal_is_executed_by_both(self):
        context = build_security_context(threat_event(), device_criticality="high")
        proposals = {**self.proposals(), "stackelberg": decision(A.BLOCK_SOURCE, "s")}
        chosen = live_arbiter_decisions(context, proposals, arbiters())
        assert chosen["arbiter_live_before"].action == A.BLOCK_SOURCE  # the only proposal the device can apply
        assert chosen["arbiter_live_after"].action == A.FORENSIC_CAPTURE  # better evidence than the proposal in this synthetic table


class TestRunTrial:
    def script(self, env, monkeypatch):
        log = []
        monkeypatch.setattr(env, "_observe_scenario", lambda condition: threat_event())

        def measure(action, event, condition):
            log.append(action)
            is_allow = action == A.ALLOW
            return Measurement(condition, action, "success", 100 if is_allow else 0, 100 if is_allow else 10, 0.0, action == A.FORENSIC_CAPTURE), {"status": "success"}

        monkeypatch.setattr(env, "measure_response", measure)
        return log

    def test_the_two_arms_are_added_and_their_actions_are_measured(self, monkeypatch):
        env = RealMininetDefenseEnv()
        log = self.script(env, monkeypatch)
        rows = run_trial(env, 0, LABEL, FakePPO(), OBJECTIVE, arbiters=arbiters())
        assert [r["arm"] for r in rows][-2:] == list(LIVE_ARBITER_ARMS) and len(rows) == ARMS_PER_TRIAL + 2
        by_arm = {r["arm"]: r for r in rows}
        # the real policies propose ISOLATE (rule-based) and BLOCK_SOURCE (Stackelberg); the fake PPO proposes QUARANTINE
        assert by_arm["arbiter_live_before"]["action"] == "BLOCK_SOURCE" and by_arm["arbiter_live_after"]["action"] == "FORENSIC_CAPTURE"
        assert A.FORENSIC_CAPTURE in log and by_arm["arbiter_live_after"]["intel_verified"] is True

    def test_without_arbiters_the_trial_is_exactly_as_before(self, monkeypatch):
        env = RealMininetDefenseEnv()
        self.script(env, monkeypatch)
        assert len(run_trial(env, 0, LABEL, FakePPO(), OBJECTIVE)) == ARMS_PER_TRIAL


class TestResume:
    def test_a_file_with_the_extra_arms_is_not_resumed_without_them(self, tmp_path):
        (tmp_path / "m.zip").write_bytes(b"model")  # the fingerprint hashes the model file, which is not tracked in git
        assert run_fingerprint(tmp_path / "m", True) != run_fingerprint(tmp_path / "m", False)

    def test_resume_counts_the_extra_arms_when_deciding_which_blocks_are_complete(self, tmp_path):
        out = tmp_path / "r.jsonl"
        prepare_output(out, "fp", resume=True, arms_per_trial=7)
        arms = ["rule_based", "stackelberg", "ppo", "always_allow", "naive_block_all", *LIVE_ARBITER_ARMS]
        out.write_text("".join(json.dumps({"trial": 0, "condition": "normal", "arm": a}) + "\n" for a in arms)
                       + "".join(json.dumps({"trial": 0, "condition": "dos_flood", "arm": a}) + "\n" for a in arms[:5]), encoding="utf-8")
        assert prepare_output(out, "fp", resume=True, arms_per_trial=7) == {(0, "normal")}  # the 5-arm block is incomplete here


class TestFreshComparison:
    def rows(self):
        rows = []
        for trial in range(4):
            for arm, action, intel in (("arbiter_live_before", "ALERT", False), ("arbiter_live_after", "FORENSIC_CAPTURE", True)):
                rows.append({"condition": "c2_beaconing", "trial": trial, "arm": arm, "action": action, "detection_correct": True,
                             "valid_measurement": True, "containment": 0.0, "service_loss": 0.0, "intel_verified": intel})
        return rows

    def test_the_paired_difference_and_the_changed_trials(self, tmp_path):
        path = tmp_path / "fresh.jsonl"
        path.write_text("".join(json.dumps(r) + "\n" for r in self.rows()), encoding="utf-8")
        report = ev.fresh_live_comparison(path)
        assert report["paired_trials"] == 4 and report["trials_with_a_different_action"] == 4
        # ALERT: 3 service - 0.1; FORENSIC_CAPTURE: 3 service + 2 intelligence - 0.3
        assert report["after_minus_before"]["mean_diff"] == pytest.approx((3 + 2 - 0.3) - (3 - 0.1))
        assert "(focus)" in ev.render_fresh_markdown(report)

    def test_a_run_without_the_arms_is_refused(self, tmp_path):
        path = tmp_path / "plain.jsonl"
        path.write_text(json.dumps({"condition": "normal", "trial": 0, "arm": "ppo", "action": "ALLOW", "valid_measurement": True}) + "\n", encoding="utf-8")
        with pytest.raises(ValueError):
            ev.fresh_live_comparison(path)
