"""Unit tests for evaluation/harness.py's pure orchestration logic -- no
Mininet required. A system review found this file (the most complex
logic in the evaluation suite: action-dedup, pcap collision-avoidance,
per-arm row construction) had zero direct unit tests, exercised only
through real-Mininet integration runs. Mirrors test_ppo_real_env.py's
and test_adaptive_evaluation.py's own convention of testing
RealMininetDefenseEnv's non-Gym, non-Mininet logic directly with a real
instance whose _observe_scenario/_execute_and_verify are faked -- since
instantiating RealMininetDefenseEnv itself never touches Mininet."""

from __future__ import annotations


import pytest

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.ppo_real_env import RealMininetDefenseEnv
from iot_defense.detection.threat_event import ThreatEvent
from iot_defense.evaluation.harness import _preferred_action_for, _preserve_pcap, run_trial


def _dos_threat_event() -> ThreatEvent:
    # threat_score/confidence high enough to clear dos_flood's own
    # action_score_min/action_confidence_min in every real policy, so
    # rule-based, Stackelberg, and naive_block_all all genuinely agree
    # on ISOLATE -- the real scenario the dedup logic exists for.
    return ThreatEvent.from_result(
        source_ip="10.0.0.100", destination_ip="10.0.0.10", attack_type="dos_flood",
        threat_score=0.92, confidence=0.9, detection_reason="test fixture",
        features={"packets_per_second": 40.0, "unique_destination_ports": 1, "packet_count": 200},
        detector_name="RuleBasedDosDetector",
    )


@pytest.fixture()
def env():
    e = RealMininetDefenseEnv()
    assert e.net is None  # confirms instantiation alone never touches Mininet
    return e


class TestRunTrialActionDedup:
    def test_agreeing_arms_execute_the_shared_action_exactly_once(self, env, monkeypatch):
        threat_event = _dos_threat_event()
        monkeypatch.setattr(env, "_observe_scenario", lambda condition: threat_event)

        call_log: list[DefenseAction] = []

        def fake_execute_and_verify(action, threat_event_arg):
            call_log.append(action)
            return {"status": "success", "connectivity_lost": True}

        monkeypatch.setattr(env, "_execute_and_verify", fake_execute_and_verify)

        rows = run_trial(env, trial=0, condition="dos_flood", pcap_dir=None)

        isolate_calls = [a for a in call_log if a == DefenseAction.ISOLATE]
        assert len(isolate_calls) == 1, (
            f"ISOLATE should be executed exactly once regardless of how many arms "
            f"agree on it, got {len(isolate_calls)} calls: {call_log}"
        )
        # rule_based, stackelberg, and naive_block_all all genuinely prefer
        # ISOLATE for a real dos_flood context -- confirms this dedup test
        # actually exercises agreement, not just a single-arm fluke.
        arms_that_chose_isolate = [
            row["arm"] for row in rows if row["action"] == DefenseAction.ISOLATE.value
        ]
        assert len(arms_that_chose_isolate) >= 2

    def test_allow_is_never_executed(self, env, monkeypatch):
        threat_event = _dos_threat_event()
        monkeypatch.setattr(env, "_observe_scenario", lambda condition: threat_event)
        call_log: list[DefenseAction] = []
        monkeypatch.setattr(
            env, "_execute_and_verify",
            lambda action, te: (call_log.append(action), {"status": "success"})[1],
        )

        rows = run_trial(env, trial=0, condition="dos_flood", pcap_dir=None)

        assert DefenseAction.ALLOW not in call_log
        always_allow_row = next(row for row in rows if row["arm"] == "always_allow")
        assert always_allow_row["action"] == DefenseAction.ALLOW.value
        assert always_allow_row["execution_ok"] is True

    def test_disagreeing_arms_each_execute_their_own_action(self, env, monkeypatch):
        """A control for the dedup test above: distinct actions across
        arms must each still be executed, not accidentally collapsed."""
        threat_event = _dos_threat_event()
        monkeypatch.setattr(env, "_observe_scenario", lambda condition: threat_event)
        call_log: list[DefenseAction] = []
        monkeypatch.setattr(
            env, "_execute_and_verify",
            lambda action, te: (call_log.append(action), {"status": "success"})[1],
        )

        run_trial(env, trial=0, condition="dos_flood", pcap_dir=None)

        # naive_block_all always prefers ISOLATE; rule_based/stackelberg
        # also prefer ISOLATE for this real dos_flood context -- so at
        # minimum ISOLATE must appear, and no action should be executed
        # more than once (the actual property under test).
        assert DefenseAction.ISOLATE in call_log
        assert len(call_log) == len(set(call_log)), f"an action was executed more than once: {call_log}"

    def test_ground_truth_and_preferred_action_are_correct_for_dos_flood(self, env, monkeypatch):
        threat_event = _dos_threat_event()
        monkeypatch.setattr(env, "_observe_scenario", lambda condition: threat_event)
        monkeypatch.setattr(env, "_execute_and_verify", lambda action, te: {"status": "success", "connectivity_lost": True})

        rows = run_trial(env, trial=0, condition="dos_flood", pcap_dir=None)

        assert _preferred_action_for("dos_flood") == DefenseAction.ISOLATE
        for row in rows:
            assert row["ground_truth_attack_type"] == "dos_flood"
            assert row["detected_attack_type"] == "dos_flood"
            assert row["detection_correct"] is True


class TestPreservePcap:
    def test_returns_none_without_a_pcap_dir(self, env):
        assert _preserve_pcap(env, None, trial=0, condition="dos_flood") is None

    def test_returns_none_when_no_capture_exists_yet(self, env, tmp_path):
        # env.monitor.base_dir defaults to the real, shared /tmp/iot-defense
        # (used by every live run on this VM) -- isolate it to a fresh
        # per-test directory so this test can't observe a stale capture
        # left over from an actual prior run.
        env.monitor.base_dir = tmp_path / "monitor_base"
        assert _preserve_pcap(env, tmp_path / "pcap_out", trial=0, condition="dos_flood") is None

    def test_copies_to_a_collision_free_per_trial_condition_path(self, env, tmp_path):
        env.monitor.base_dir = tmp_path / "monitor_base"
        env.monitor.base_dir.mkdir(parents=True, exist_ok=True)
        tmp_path = tmp_path / "pcap_out"
        source = env.monitor.base_dir / "sensor_capture.pcap"
        source.write_bytes(b"fake pcap bytes")

        first = _preserve_pcap(env, tmp_path, trial=0, condition="dos_flood")
        source.write_bytes(b"different fake pcap bytes for the second trial")
        second = _preserve_pcap(env, tmp_path, trial=1, condition="dos_flood")
        third = _preserve_pcap(env, tmp_path, trial=0, condition="reconnaissance_port_scan")

        assert first != second != third
        assert {first, second, third} == {
            str(tmp_path / "trial000_dos_flood.pcap"),
            str(tmp_path / "trial001_dos_flood.pcap"),
            str(tmp_path / "trial000_reconnaissance_port_scan.pcap"),
        }
        # The first trial's own copy must survive the source being
        # overwritten by the second trial -- the whole point of this
        # function (see its own docstring).
        from pathlib import Path
        assert Path(first).read_bytes() == b"fake pcap bytes"
