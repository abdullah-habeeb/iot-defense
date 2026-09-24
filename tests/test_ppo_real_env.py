"""Unit tests for RealMininetDefenseEnv's pure logic -- no Mininet required.

The Gym plumbing (reset/step) drives real Mininet and cannot be exercised
in a unit test; calculate_reward() and instantiation, however, are pure
and are covered here.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.ppo_real_env import RealMininetDefenseEnv
from iot_defense.detection.threat_event import ThreatEvent


def _env():
    return RealMininetDefenseEnv(episode_length=4)


def _threat_event(protocol: str, attack_type: str = "icmp_ping_flood") -> ThreatEvent:
    return ThreatEvent.from_result(
        source_ip="10.0.0.100",
        destination_ip="10.0.0.10",
        attack_type=attack_type,
        threat_score=0.9,
        confidence=0.85,
        detection_reason="test fixture",
        features={"packet_count": 40, "protocol": protocol},
        detector_name="RuleBasedIcmpFloodDetector",
    )


def test_instantiation_does_not_touch_mininet():
    env = _env()
    assert env.net is None
    assert env.executor is None


def test_normal_scenario_rewards_allow_and_penalizes_isolate():
    env = _env()
    allow_reward, _ = env.calculate_reward("normal", DefenseAction.ALLOW, {"status": "success"})
    isolate_reward, _ = env.calculate_reward("normal", DefenseAction.ISOLATE, {"status": "success"})
    assert allow_reward > isolate_reward


def test_dos_flood_rewards_verified_isolation_over_unverified():
    env = _env()
    verified, _ = env.calculate_reward("dos_flood", DefenseAction.ISOLATE, {"status": "success", "connectivity_lost": True})
    unverified, _ = env.calculate_reward("dos_flood", DefenseAction.ISOLATE, {"status": "success", "connectivity_lost": False})
    assert verified > unverified


def test_dos_flood_rewards_isolation_over_decoy_and_allow():
    env = _env()
    isolate, _ = env.calculate_reward("dos_flood", DefenseAction.ISOLATE, {"status": "success", "connectivity_lost": True})
    decoy, _ = env.calculate_reward("dos_flood", DefenseAction.DECOY, {"status": "success"})
    allow, _ = env.calculate_reward("dos_flood", DefenseAction.ALLOW, {"status": "success"})
    assert isolate > decoy > allow


def test_reconnaissance_rewards_verified_decoy_interaction_over_unverified():
    env = _env()
    verified, _ = env.calculate_reward(
        "reconnaissance_port_scan", DefenseAction.DECOY, {"status": "success", "interaction_verified": True}
    )
    unverified, _ = env.calculate_reward(
        "reconnaissance_port_scan", DefenseAction.DECOY, {"status": "success", "interaction_verified": False}
    )
    assert verified > unverified


def test_reconnaissance_penalizes_allow():
    env = _env()
    decoy, _ = env.calculate_reward(
        "reconnaissance_port_scan", DefenseAction.DECOY, {"status": "success", "interaction_verified": True}
    )
    allow, _ = env.calculate_reward("reconnaissance_port_scan", DefenseAction.ALLOW, {"status": "success"})
    assert decoy > allow


def test_failed_execution_never_scores_as_well_as_verified_success():
    """A response that reports failure must not be rewarded as if it worked,
    even for the otherwise-correct action."""
    env = _env()
    verified, _ = env.calculate_reward("dos_flood", DefenseAction.ISOLATE, {"status": "success", "connectivity_lost": True})
    failed, _ = env.calculate_reward("dos_flood", DefenseAction.ISOLATE, {"status": "failed", "connectivity_lost": False})
    assert verified > failed


def test_brute_force_rewards_verified_block_source_over_failed():
    """BLOCK_SOURCE has no extra outcome key the way ISOLATE/DECOY/THROTTLE
    do (see _preferred_action_verified's own docstring -- it falls through
    to execution_ok for any preferred action without one), so its real
    verified-vs-failed distinction comes entirely from status: block_source()
    itself already raises (making execute() report "failed") if its own
    live poll of `iptables -L INPUT` never shows the installed rule."""
    env = _env()
    verified, _ = env.calculate_reward("brute_force", DefenseAction.BLOCK_SOURCE, {"status": "success"})
    failed, _ = env.calculate_reward("brute_force", DefenseAction.BLOCK_SOURCE, {"status": "failed"})
    assert verified > failed


def test_brute_force_rewards_block_source_over_throttle_isolate_and_allow():
    """brute_force's registered preferred_action is BLOCK_SOURCE (not
    THROTTLE or ISOLATE) -- the real-Mininet reward must reflect that, not
    just the synthetic training env. Reassigned from THROTTLE this pass:
    this lab's brute-force traffic always comes from one fixed,
    identifiable attacker host, so blocking it outright stops every guess
    rather than merely rate-limiting them, with the same "other sources
    unaffected" property THROTTLE offers."""
    env = _env()
    block_source, _ = env.calculate_reward("brute_force", DefenseAction.BLOCK_SOURCE, {"status": "success"})
    throttle, _ = env.calculate_reward("brute_force", DefenseAction.THROTTLE, {"status": "success", "rule_installed": True})
    isolate, _ = env.calculate_reward("brute_force", DefenseAction.ISOLATE, {"status": "success"})
    allow, _ = env.calculate_reward("brute_force", DefenseAction.ALLOW, {"status": "success"})
    assert block_source > throttle > allow
    assert block_source > isolate > allow


def test_data_exfiltration_rewards_verified_isolation_over_allow():
    env = _env()
    isolate, _ = env.calculate_reward(
        "data_exfiltration", DefenseAction.ISOLATE, {"status": "success", "connectivity_lost": True}
    )
    allow, _ = env.calculate_reward("data_exfiltration", DefenseAction.ALLOW, {"status": "success"})
    assert isolate > allow


def test_execute_and_verify_wires_the_real_detected_protocol_into_throttle():
    """Regression test for a real bug: _execute_and_verify used to build
    its DefenseDecision with an empty context, so executor.execute()'s
    THROTTLE branch (which reads context["beliefs"]["observed_features"]
    ["protocol"]) always fell back to its "TCP" default -- silently
    installing a TCP-only hashlimit rule that can never match ICMP
    traffic, for every real ICMP attack (icmp_ping_flood, the one
    THROTTLE-preferred attack that isn't TCP), while still reporting
    "success". Found via a live Mininet repro showing icmp_ping_flood's
    own verified-response rate stuck at 0% across 15 real trials."""
    env = _env()
    env.net = MagicMock()
    env.executor = MagicMock()
    env.executor.execute.return_value = MagicMock(status="success", details={})
    threat_event = _threat_event(protocol="ICMP")

    env._execute_and_verify(DefenseAction.THROTTLE, threat_event)

    decision = env.executor.execute.call_args[0][0]
    assert decision.context["beliefs"]["observed_features"]["protocol"] == "ICMP"


def test_execute_and_verify_preserves_tcp_protocol_too():
    env = _env()
    env.net = MagicMock()
    env.executor = MagicMock()
    env.executor.execute.return_value = MagicMock(status="success", details={})
    threat_event = _threat_event(protocol="TCP", attack_type="brute_force")

    env._execute_and_verify(DefenseAction.THROTTLE, threat_event)

    decision = env.executor.execute.call_args[0][0]
    assert decision.context["beliefs"]["observed_features"]["protocol"] == "TCP"


def test_unregistered_scenario_raises_instead_of_silently_scoring():
    env = _env()
    try:
        env.calculate_reward("not_a_real_attack", DefenseAction.ALLOW, {"status": "success"})
    except ValueError as error:
        assert "not_a_real_attack" in str(error)
    else:
        raise AssertionError("Unsupported scenario should raise, not silently score")
