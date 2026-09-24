"""Unit tests for evaluation/adaptive.py's pure orchestration logic -- no
Mininet required. Mirrors test_ppo_real_env.py's own convention of testing
the non-Gym, non-Mininet logic directly with fakes."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from iot_defense.attacks.registry import ATTACK_SCENARIOS
from iot_defense.defense.decision import DefenseAction
from iot_defense.detection.threat_event import ThreatEvent
from iot_defense.evaluation.adaptive import _SOURCE_POOL, _traffic_for_source, run_campaign, run_round


def _threat_event(attack_type: str, source_ip: str = "10.0.0.100", packet_count: int = 12) -> ThreatEvent:
    return ThreatEvent.from_result(
        source_ip=source_ip,
        destination_ip="10.0.0.10",
        attack_type=attack_type,
        threat_score=0.85,
        confidence=0.8,
        detection_reason="test fixture",
        features={"packet_count": packet_count},
        detector_name="RuleBasedReplayAttackDetector",
    )


def _fake_env(threat_event: ThreatEvent, execute_result=None):
    env = MagicMock()
    env._observe_scenario.return_value = threat_event
    env.executor = MagicMock()
    if execute_result is not None:
        env.executor.execute.return_value = execute_result
    return env


class TestTrafficForSource:
    def test_real_attacker_ip_uses_the_registered_generator(self):
        generator = _traffic_for_source("10.0.0.100")
        assert generator == ATTACK_SCENARIOS["replay_attack"].generate_traffic

    def test_spoofed_ip_wraps_the_distributed_generator_with_a_single_source(self):
        with patch("iot_defense.evaluation.adaptive.TrafficGenerator") as MockGen:
            instance = MockGen.return_value
            generator = _traffic_for_source("10.0.0.121")
            net = object()
            generator(net)
            instance.generate_replay_attack_distributed_mininet_traffic.assert_called_once_with(
                net, duration_seconds=20, spoofed_source_ips=("10.0.0.121",)
            )


class TestRunRound:
    def test_detected_replay_attack_executes_block_source(self):
        event = _threat_event("credential_replay")
        env = _fake_env(event, execute_result=MagicMock(status="success", details={}))
        with patch("iot_defense.evaluation.adaptive.StackelbergDefensePolicy") as MockPolicy:
            MockPolicy.return_value.decide.return_value = MagicMock(action=DefenseAction.BLOCK_SOURCE)
            policy = MockPolicy.return_value
            row = run_round(env, round_num=0, source_ip="10.0.0.100", policy=policy)

        assert row["detected"] is True
        assert row["action"] == DefenseAction.BLOCK_SOURCE.value
        assert row["matches_preferred_action"] is True
        assert row["execution_ok"] is True
        env.executor.execute.assert_called_once()
        # The whole point of this module: never restore mid-campaign.
        env.executor.restore.assert_not_called()

    def test_allow_decision_never_calls_execute(self):
        event = _threat_event("normal", packet_count=0)
        env = _fake_env(event)
        policy = MagicMock()
        policy.decide.return_value = MagicMock(action=DefenseAction.ALLOW)
        row = run_round(env, round_num=1, source_ip="10.0.0.121", policy=policy, already_blocked=True)

        assert row["detected"] is False
        env.executor.execute.assert_not_called()

    def test_blocked_source_produces_a_normal_reading_not_a_missed_detection_mislabel(self):
        """When a source is already blocked at the network layer, no
        packets reach the sensor -- _observe_scenario's own empty-capture
        fallback reports "normal", which is the real, honest signal that
        the block held, not a detector failure. already_blocked=True also
        means no retry fires -- a zero-packet reading here is expected,
        not ambiguous."""
        event = _threat_event("normal", packet_count=0)
        env = _fake_env(event)
        policy = MagicMock()
        policy.decide.return_value = MagicMock(action=DefenseAction.ALLOW)
        row = run_round(env, round_num=2, source_ip="10.0.0.100", policy=policy, already_blocked=True)

        assert row["packets_captured"] == 0
        assert row["detected"] is False
        assert row["capture_reliable"] is True
        env._observe_scenario.assert_called_once()

    def test_unblocked_source_with_empty_capture_retries_once(self):
        """A zero-packet capture from a source that was NOT already
        blocked is ambiguous -- it could be a real detection-evasion
        signal or this project's own documented Mininet capture
        flakiness (see monitor.py's read_capture, generate_dataset.py's
        tolerance for the same failure mode). Retrying once, mirroring
        read_capture()'s own established pattern, resolves it here."""
        empty = _threat_event("normal", packet_count=0)
        detected = _threat_event("credential_replay", packet_count=17)
        env = MagicMock()
        env._observe_scenario.side_effect = [empty, detected]
        env.executor = MagicMock()
        env.executor.execute.return_value = MagicMock(status="success", details={})
        policy = MagicMock()
        policy.decide.return_value = MagicMock(action=DefenseAction.BLOCK_SOURCE)

        row = run_round(env, round_num=0, source_ip="10.0.0.121", policy=policy, already_blocked=False)

        assert env._observe_scenario.call_count == 2
        assert row["detected"] is True
        assert row["capture_reliable"] is True

    def test_unblocked_source_with_two_empty_captures_is_flagged_unreliable_not_evaded(self):
        """If the retry *also* comes back empty, this module must not
        quietly report that as "the attacker was contained" -- that would
        misreport measurement noise as a real finding."""
        empty = _threat_event("normal", packet_count=0)
        env = MagicMock()
        env._observe_scenario.side_effect = [empty, empty]
        env.executor = MagicMock()
        policy = MagicMock()
        policy.decide.return_value = MagicMock(action=DefenseAction.ALLOW)

        row = run_round(env, round_num=0, source_ip="10.0.0.121", policy=policy, already_blocked=False)

        assert env._observe_scenario.call_count == 2
        assert row["capture_reliable"] is False
        assert row["packets_captured"] == 0


class TestRunCampaign:
    def test_fixed_mode_reuses_the_same_source_every_round(self):
        event = _threat_event("credential_replay")
        env = _fake_env(event, execute_result=MagicMock(status="success", details={}))
        with patch("iot_defense.evaluation.adaptive.StackelbergDefensePolicy") as MockPolicy:
            MockPolicy.return_value.decide.return_value = MagicMock(action=DefenseAction.BLOCK_SOURCE)
            rows = run_campaign(env, rounds=3, mode="fixed")

        sources = [row["source_ip"] for row in rows]
        assert sources == [_SOURCE_POOL[0]] * 3

    def test_rotate_mode_advances_past_each_blocked_source(self):
        event = _threat_event("credential_replay")
        env = _fake_env(event, execute_result=MagicMock(status="success", details={}))
        with patch("iot_defense.evaluation.adaptive.StackelbergDefensePolicy") as MockPolicy:
            MockPolicy.return_value.decide.return_value = MagicMock(action=DefenseAction.BLOCK_SOURCE)
            rows = run_campaign(env, rounds=3, mode="rotate")

        sources = [row["source_ip"] for row in rows]
        assert sources == list(_SOURCE_POOL[:3])
        assert sources == sorted(set(sources), key=sources.index)  # every round used a fresh source

    def test_rotate_mode_never_restores_mid_campaign(self):
        event = _threat_event("credential_replay")
        env = _fake_env(event, execute_result=MagicMock(status="success", details={}))
        with patch("iot_defense.evaluation.adaptive.StackelbergDefensePolicy") as MockPolicy:
            MockPolicy.return_value.decide.return_value = MagicMock(action=DefenseAction.BLOCK_SOURCE)
            run_campaign(env, rounds=4, mode="rotate")

        env.executor.restore.assert_not_called()

    def test_rotate_mode_skips_a_source_whose_capture_is_unreliable_instead_of_retrying_it_forever(self):
        """Found via a real 30-round Mininet run: the original selection
        picked "first not-yet-blocked" and, when a source's capture came
        back empty on both the initial attempt and the built-in retry,
        kept re-selecting that same unreliable source every round instead
        of moving on -- turning a 30-round rotate campaign into a 2-source
        campaign with 28 wasted rounds. This is the regression test for
        the fix: a source with an empty capture (never detected, so never
        blocked) must not be selected again once it has been tried."""
        empty_event = _threat_event("credential_replay", packet_count=0)
        env = _fake_env(empty_event)
        env.executor.execute.return_value = MagicMock(status="success", details={})
        with patch("iot_defense.evaluation.adaptive.StackelbergDefensePolicy") as MockPolicy:
            MockPolicy.return_value.decide.return_value = MagicMock(action=DefenseAction.ALLOW)
            rows = run_campaign(env, rounds=5, mode="rotate")

        sources = [row["source_ip"] for row in rows]
        assert sources == list(_SOURCE_POOL[:5]), (
            "every round should have moved to the next untried source instead of "
            f"getting stuck retrying one; got {sources}"
        )
        assert all(row["capture_reliable"] is False for row in rows)
