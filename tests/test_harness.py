"""Unit tests for evaluation/harness.py's orchestration -- no Mininet.

A real RealMininetDefenseEnv instance (instantiation never touches Mininet)
has its observe/measure seams faked with scripted outcomes; the policies,
the objective, and the row construction are real.
"""

from __future__ import annotations

import itertools
from pathlib import Path

import pytest

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.objective import Objective
from iot_defense.defense.ppo_real_env import RealMininetDefenseEnv
from iot_defense.detection.threat_event import ThreatEvent
from iot_defense.evaluation.harness import (
    ARMS_PER_TRIAL,
    _preferred_action_for,
    _preserve_pcap,
    prepare_output,
    run_fingerprint,
    run_trial,
)
from iot_defense.evaluation.outcome import Measurement, realized_utility

OBJECTIVE = Objective.load()


def _dos_threat_event() -> ThreatEvent:
    return ThreatEvent.from_result(
        source_ip="10.0.0.100", destination_ip="10.0.0.10", attack_type="dos_flood",
        threat_score=0.92, confidence=0.9, detection_reason="test fixture",
        features={"packets_per_second": 40.0, "unique_destination_ports": 1, "packet_count": 200},
        detector_name="RuleBasedDosDetector",
    )


class FakePPO:
    """Stands in for a trained model: always chooses `action`."""

    def __init__(self, action: DefenseAction) -> None:
        self.action = action
        self.calls = 0

    def decide(self, context):
        from iot_defense.defense.decision import DefenseDecision

        self.calls += 1
        return DefenseDecision.create(
            action=self.action, target_ip="10.0.0.10", source_ip="10.0.0.100", reason="fake",
            confidence=0.9, threat_score=0.9, policy_name="PPODefensePolicy", context={},
        )


@pytest.fixture(autouse=True)
def _no_settle_sleep(monkeypatch):
    monkeypatch.setattr("iot_defense.evaluation.harness.SETTLE_SECONDS", 0.0)


@pytest.fixture()
def env():
    e = RealMininetDefenseEnv()
    assert e.net is None
    return e


def _script(env, monkeypatch, *, residual_by_action=None, service_loss_by_action=None, allow_baseline=100):
    """Fake observe/measure; returns the ordered log of measured actions.
    `allow_baseline` may be an int (both ALLOW probes) or a (first, last) pair."""
    residual_by_action = residual_by_action or {}
    service_loss_by_action = service_loss_by_action or {}
    allow_values = itertools.cycle(allow_baseline if isinstance(allow_baseline, tuple) else (allow_baseline, allow_baseline))
    log: list[DefenseAction] = []
    monkeypatch.setattr(env, "_observe_scenario", lambda condition: _dos_threat_event())

    def fake_measure(action, threat_event, condition):
        log.append(action)
        is_allow = action == DefenseAction.ALLOW
        residual = next(allow_values) if is_allow else residual_by_action.get(action, 0)
        return (
            Measurement(
                condition=condition, action=action, status="success",
                baseline_packets=residual if is_allow else 0,
                residual_packets=residual, service_loss=service_loss_by_action.get(action, 0.0),
                intel_verified=False,
            ),
            {"status": "success"},
        )

    monkeypatch.setattr(env, "measure_response", fake_measure)
    return log


class TestRunTrial:
    def test_allow_brackets_the_measurements_and_each_other_action_is_measured_once(self, env, monkeypatch):
        log = _script(env, monkeypatch)
        run_trial(env, 0, "dos_flood", FakePPO(DefenseAction.BLOCK_SOURCE), OBJECTIVE)
        assert log[0] == log[-1] == DefenseAction.ALLOW
        middle = log[1:-1]
        assert DefenseAction.ALLOW not in middle and len(middle) == len(set(middle)), middle

    def test_every_distinct_chosen_action_is_measured(self, env, monkeypatch):
        log = _script(env, monkeypatch)
        rows = run_trial(env, 0, "dos_flood", FakePPO(DefenseAction.FORENSIC_CAPTURE), OBJECTIVE)
        assert set(log) == {DefenseAction(r["action"]) for r in rows} | {DefenseAction.ALLOW}

    def test_the_trial_baseline_is_the_mean_of_the_before_and_after_allow_probes(self, env, monkeypatch):
        _script(env, monkeypatch, residual_by_action={DefenseAction.BLOCK_SOURCE: 22}, allow_baseline=(100, 120))
        rows = run_trial(env, 0, "dos_flood", FakePPO(DefenseAction.BLOCK_SOURCE), OBJECTIVE)
        ppo = next(r for r in rows if r["arm"] == "ppo")
        assert ppo["baseline_packets"] == 110
        assert ppo["containment"] == pytest.approx(1 - 22 / 110)

    def test_one_row_per_arm_with_measured_fields_and_realized_utility(self, env, monkeypatch):
        _script(env, monkeypatch, residual_by_action={DefenseAction.BLOCK_SOURCE: 10}, service_loss_by_action={DefenseAction.BLOCK_SOURCE: 0.2})
        rows = run_trial(env, 3, "dos_flood", FakePPO(DefenseAction.BLOCK_SOURCE), OBJECTIVE)
        assert [r["arm"] for r in rows] == ["rule_based", "stackelberg", "ppo", "always_allow", "naive_block_all"]
        ppo = next(r for r in rows if r["arm"] == "ppo")
        assert ppo["containment"] == pytest.approx(0.9)
        assert ppo["service_loss"] == pytest.approx(0.2)
        expected = realized_utility(
            Measurement("dos_flood", DefenseAction.BLOCK_SOURCE, "success", 100, 10, 0.2, False), OBJECTIVE
        )
        assert ppo["utility"] == pytest.approx(expected)
        assert "response_verified" not in ppo, "the circular preferred-action verification gate must be gone"

    def test_arms_choosing_the_same_action_get_identical_measurements(self, env, monkeypatch):
        _script(env, monkeypatch)
        rows = run_trial(env, 0, "dos_flood", FakePPO(DefenseAction.ALLOW), OBJECTIVE)
        always_allow = next(r for r in rows if r["arm"] == "always_allow")
        ppo = next(r for r in rows if r["arm"] == "ppo")
        assert ppo["action"] == always_allow["action"] == "ALLOW"
        assert ppo["utility"] == always_allow["utility"]
        assert always_allow["containment"] == 0.0

    def test_preferred_action_is_only_a_diagnostic_flag(self, env, monkeypatch):
        _script(env, monkeypatch)
        rows = run_trial(env, 0, "dos_flood", FakePPO(DefenseAction.ISOLATE), OBJECTIVE)
        assert _preferred_action_for("dos_flood") == DefenseAction.ISOLATE
        ppo = next(r for r in rows if r["arm"] == "ppo")
        assert ppo["matches_preferred_action"] is True
        # a worse-measured preferred action must still score worse, not better
        _script(env, monkeypatch, service_loss_by_action={DefenseAction.ISOLATE: 1.0})
        isolate = next(r for r in run_trial(env, 0, "dos_flood", FakePPO(DefenseAction.ISOLATE), OBJECTIVE) if r["arm"] == "ppo")
        block = next(r for r in run_trial(env, 0, "dos_flood", FakePPO(DefenseAction.BLOCK_SOURCE), OBJECTIVE) if r["arm"] == "ppo")
        assert isolate["matches_preferred_action"] and not block["matches_preferred_action"]
        assert block["utility"] > isolate["utility"]

    def test_invalid_measurement_yields_no_utility(self, env, monkeypatch):
        _script(env, monkeypatch, allow_baseline=1)  # below MIN_BASELINE_PACKETS
        rows = run_trial(env, 0, "dos_flood", FakePPO(DefenseAction.BLOCK_SOURCE), OBJECTIVE)
        assert all(r["valid_measurement"] is False and r["utility"] is None for r in rows)

    def test_detection_fields_come_from_the_shared_observation(self, env, monkeypatch):
        _script(env, monkeypatch)
        rows = run_trial(env, 0, "dos_flood", FakePPO(DefenseAction.ISOLATE), OBJECTIVE)
        for row in rows:
            assert row["ground_truth_attack_type"] == row["detected_attack_type"] == "dos_flood"
            assert row["detection_correct"] is True

    def test_ppo_policy_is_called_with_the_context_alone(self, env, monkeypatch):
        _script(env, monkeypatch)
        ppo = FakePPO(DefenseAction.ISOLATE)
        run_trial(env, 0, "dos_flood", ppo, OBJECTIVE)
        assert ppo.calls == 1


class TestPreservePcap:
    def test_returns_none_without_a_pcap_dir(self, env):
        assert _preserve_pcap(env, None, trial=0, condition="dos_flood") is None

    def test_returns_none_when_no_capture_exists_yet(self, env, tmp_path):
        env.monitor.base_dir = tmp_path / "monitor_base"
        assert _preserve_pcap(env, tmp_path / "pcap_out", trial=0, condition="dos_flood") is None

    def test_copies_to_a_collision_free_per_trial_condition_path(self, env, tmp_path):
        env.monitor.base_dir = tmp_path / "monitor_base"
        env.monitor.base_dir.mkdir(parents=True, exist_ok=True)
        out = tmp_path / "pcap_out"
        source = env.monitor.base_dir / "sensor_capture.pcap"
        source.write_bytes(b"fake pcap bytes")
        first = _preserve_pcap(env, out, trial=0, condition="dos_flood")
        source.write_bytes(b"different fake pcap bytes for the second trial")
        second = _preserve_pcap(env, out, trial=1, condition="dos_flood")
        third = _preserve_pcap(env, out, trial=0, condition="reconnaissance_port_scan")
        assert {first, second, third} == {
            str(out / "trial000_dos_flood.pcap"),
            str(out / "trial001_dos_flood.pcap"),
            str(out / "trial000_reconnaissance_port_scan.pcap"),
        }
        assert Path(first).read_bytes() == b"fake pcap bytes"


ARMS = ("rule_based", "stackelberg", "ppo", "always_allow", "naive_block_all")


def _block(trial, condition, arms=ARMS):
    import json

    return "".join(json.dumps({"trial": trial, "condition": condition, "arm": arm}) + "\n" for arm in arms)


class TestResume:
    def test_fresh_start_creates_an_empty_file_and_records_the_fingerprint(self, tmp_path):
        out = tmp_path / "r.jsonl"
        assert prepare_output(out, "fp1", resume=True) == set()
        assert out.read_text() == "" and out.with_suffix(".fingerprint").read_text().strip() == "fp1"

    def test_resume_keeps_complete_blocks_and_drops_a_half_written_one(self, tmp_path):
        out = tmp_path / "r.jsonl"
        prepare_output(out, "fp1", resume=True)
        out.write_text(_block(0, "normal") + _block(0, "dos_flood") + _block(0, "brute_force", ARMS[:3]))
        assert prepare_output(out, "fp1", resume=True) == {(0, "normal"), (0, "dos_flood")}
        kept = out.read_text().splitlines()
        assert len(kept) == 2 * ARMS_PER_TRIAL and not any("brute_force" in line for line in kept)

    def test_a_duplicated_block_is_not_counted_as_complete(self, tmp_path):
        out = tmp_path / "r.jsonl"
        prepare_output(out, "fp1", resume=True)
        out.write_text(_block(0, "normal") + _block(0, "normal"))
        assert prepare_output(out, "fp1", resume=True) == set()

    def test_resuming_under_a_different_model_or_config_is_refused(self, tmp_path):
        out = tmp_path / "r.jsonl"
        prepare_output(out, "fp1", resume=True)
        out.write_text(_block(0, "normal"))
        with pytest.raises(RuntimeError, match="different model/config"):
            prepare_output(out, "fp2", resume=True)
        assert out.read_text() == _block(0, "normal"), "a refused resume must not touch the results"

    def test_a_results_file_with_no_fingerprint_is_refused(self, tmp_path):
        out = tmp_path / "r.jsonl"
        out.write_text(_block(0, "normal"))
        with pytest.raises(RuntimeError):
            prepare_output(out, "fp1", resume=True)

    def test_restart_discards_the_old_results(self, tmp_path):
        out = tmp_path / "r.jsonl"
        prepare_output(out, "fp1", resume=True)
        out.write_text(_block(0, "normal"))
        assert prepare_output(out, "fp2", resume=False) == set()
        assert out.read_text() == "" and out.with_suffix(".fingerprint").read_text().strip() == "fp2"

    def test_fingerprint_changes_with_the_model_file(self, tmp_path):
        model = tmp_path / "m.zip"
        model.write_bytes(b"one")
        first = run_fingerprint(tmp_path / "m")
        model.write_bytes(b"two")
        assert run_fingerprint(tmp_path / "m") != first
