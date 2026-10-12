"""Unit tests for RealMininetDefenseEnv's measurement protocol -- no Mininet.

Hosts are faked with a small iptables emulator (install/delete the counter
rule, read its packet count, answer pings) so everything the protocol decides
-- which host counts, ordering relative to the response, the canonical
response target, leaked-rule cleanup, sentinel values for unreadable probes,
restore-always, intel flags -- is exercised for real.
"""

from __future__ import annotations

import json
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from iot_defense.attacks.registry import ATTACK_SCENARIOS
from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.ppo_real_env import (
    ATTACKER_IP,
    CAMERA_IP,
    INVALID_SERVICE_LOSS,
    PROBE_COMMENT,
    TARGET_IP,
    RealMininetDefenseEnv,
)
from iot_defense.detection.threat_event import ThreatEvent
from iot_defense.evaluation.outcome import with_baseline

PING_OK = "5 packets transmitted, 5 received, 20% packet loss"


class FakeHost:
    """Emulates just the iptables/ping behaviour the probe relies on."""

    def __init__(self, name, log, *, counter=0, ping_output=PING_OK, fail_install=False, leaked_rules=0):
        self.name, self.log = name, log
        self.counter, self.ping_output, self.fail_install = counter, ping_output, fail_install
        # one entry per `iptables -A`; like real iptables, a comma-separated -s
        # list becomes one rule (own counter) per source
        self.sets: list[tuple[str, ...]] = [("10.0.0.100",)] * leaked_rules
        self.commands: list[str] = []

    @property
    def installed(self) -> int:
        return len(self.sets)

    def cmd(self, command):
        self.commands.append(command)
        if PROBE_COMMENT in command and " -A INPUT" in command:
            if self.fail_install:
                return "iptables: Permission denied (you must be root)."
            self.sets.append(tuple(command.split(" -s ")[1].split(" ")[0].split(",")))
            self.log.append(f"{self.name}:counter_installed")
            return ""
        if PROBE_COMMENT in command and " -D INPUT" in command:
            if self.sets:
                self.sets.pop()
                self.log.append(f"{self.name}:counter_removed")
                return ""
            return "iptables: Bad rule (does a matching rule exist in that chain?)."
        if command.startswith("iptables -nvxL INPUT"):
            header = "Chain INPUT (policy ACCEPT 0 packets, 0 bytes)\n    pkts      bytes target     prot opt in     out     source               destination\n"
            lines = []
            for index, senders in enumerate(self.sets):
                live = index == len(self.sets) - 1  # only the current set has seen traffic
                for position, sender in enumerate(senders):
                    share = self.counter // len(senders) + (self.counter % len(senders) if position == 0 else 0)
                    count = share if live else 0
                    lines.append(f"{count:>8d}     9999 ACCEPT     all  --  *      *       {sender:<20s} 0.0.0.0/0            /* {PROBE_COMMENT} */\n")
            return header + "".join(lines)
        if command.startswith("ping"):
            return self.ping_output
        return ""


def _threat_event(protocol: str = "TCP", attack_type: str = "dos_flood", source_ip=ATTACKER_IP, destination_ip=TARGET_IP) -> ThreatEvent:
    return ThreatEvent.from_result(
        source_ip=source_ip, destination_ip=destination_ip, attack_type=attack_type,
        threat_score=0.9, confidence=0.85, detection_reason="test fixture",
        features={"packet_count": 40, "protocol": protocol}, detector_name="test",
    )


def _wired_env(*, counter=7, ping_output=PING_OK, fail_install=False, leaked_rules=0, exec_status="success"):
    """An env whose Mininet-facing seams are faked; returns (env, hosts, log)."""
    env = RealMininetDefenseEnv()
    log: list[str] = []
    hosts = {
        "sensor": FakeHost("sensor", log, counter=counter, fail_install=fail_install, leaked_rules=leaked_rules),
        "attacker": FakeHost("attacker", log, counter=counter, fail_install=fail_install, leaked_rules=leaked_rules),
        "camera": FakeHost("camera", log, ping_output=ping_output),
    }
    env.net = MagicMock()
    env.net.get.side_effect = lambda name: hosts[name]
    env.executor = MagicMock()
    env.executor.execute.side_effect = lambda d: (log.append(f"execute:{d.action.value}"), MagicMock(status=exec_status, details={}))[1]
    env.executor.restore.side_effect = lambda ip: log.append("restore")
    env.traffic_gen = MagicMock()
    env.traffic_gen.generate_normal_mininet_traffic.side_effect = lambda net: log.append("traffic:normal")
    return env, hosts, log


def _direction(condition):
    return next(s.traffic_direction for s in ATTACK_SCENARIOS.values() if s.attack_type == condition)


def _senders(condition):
    return next(s.sender_ips for s in ATTACK_SCENARIOS.values() if s.attack_type == condition)


def _patch_attack_traffic(env, monkeypatch, log, raises=None, on_traffic=None):
    def gen(net):
        log.append("traffic:attack")
        if on_traffic:
            on_traffic()
        if raises:
            raise raises

    monkeypatch.setattr(env, "_attack_for", lambda condition: SimpleNamespace(
        generate_traffic=gen, traffic_direction=_direction(condition), sender_ips=_senders(condition)))


class TestRegistryDirections:
    def test_the_five_reversed_direction_attacks_are_outbound_and_the_rest_inbound(self):
        outbound = {s.key for s in ATTACK_SCENARIOS.values() if s.traffic_direction == "outbound"}
        assert outbound == {"exfiltration", "dns_tunneling", "firmware_tampering", "rogue_beacon", "c2_beacon"}
        assert {s.traffic_direction for s in ATTACK_SCENARIOS.values()} == {"inbound", "outbound"}


class TestInstantiation:
    def test_does_not_touch_mininet(self):
        env = RealMininetDefenseEnv()
        assert env.net is None and env.executor is None


class TestExecuteAndVerify:
    def test_wires_the_real_detected_protocol_into_throttle(self):
        env = RealMininetDefenseEnv()
        env.net, env.executor = MagicMock(), MagicMock()
        env.executor.execute.return_value = MagicMock(status="success", details={})
        env._execute_and_verify(DefenseAction.THROTTLE, _threat_event(protocol="ICMP", attack_type="icmp_ping_flood"))
        assert env.executor.execute.call_args[0][0].context["beliefs"]["observed_features"]["protocol"] == "ICMP"

    def test_probe_runs_while_the_response_is_active_then_restore_runs(self):
        env = RealMininetDefenseEnv()
        order: list[str] = []
        env.net, env.executor = MagicMock(), MagicMock()
        env.executor.execute.side_effect = lambda d: (order.append("execute"), MagicMock(status="success", details={}))[1]
        env.executor.restore.side_effect = lambda ip: order.append("restore")
        outcome = env._execute_and_verify(DefenseAction.BLOCK_SOURCE, _threat_event(), probe=lambda: (order.append("probe"), {"x": 1})[1])
        assert order == ["execute", "probe", "restore"] and outcome["probe"] == {"x": 1}

    def test_a_raising_probe_is_recorded_and_restore_still_runs(self):
        env = RealMininetDefenseEnv()
        env.net, env.executor = MagicMock(), MagicMock()
        env.executor.execute.return_value = MagicMock(status="success", details={})

        def boom():
            raise RuntimeError("generator exploded")

        outcome = env._execute_and_verify(DefenseAction.ISOLATE, _threat_event(), probe=boom)
        assert "generator exploded" in outcome["probe_error"] and "probe" not in outcome
        env.executor.restore.assert_called_once()

    def test_forensic_capture_success_is_the_evidence_flag(self):
        env = RealMininetDefenseEnv()
        env.net, env.executor = MagicMock(), MagicMock()
        env.executor.execute.return_value = MagicMock(status="success", details={})
        assert env._execute_and_verify(DefenseAction.FORENSIC_CAPTURE, _threat_event())["evidence_captured"] is True
        env.executor.execute.return_value = MagicMock(status="failed", details={})
        assert env._execute_and_verify(DefenseAction.FORENSIC_CAPTURE, _threat_event())["evidence_captured"] is False


class TestCanonicalResponseTarget:
    def decision_for(self, env):
        return env.executor.execute.call_args[0][0]

    def test_a_missed_detection_with_raw_flow_orientation_still_targets_the_sensor(self, monkeypatch):
        """Regression: when the detector missed an outbound attack the event kept raw
        flow orientation (source=sensor, destination=attacker) and responses landed
        on the attacker's own host."""
        env, _, log = _wired_env()
        _patch_attack_traffic(env, monkeypatch, log)
        raw = _threat_event(attack_type="normal", source_ip=TARGET_IP, destination_ip=ATTACKER_IP)
        env.measure_response(DefenseAction.BLOCK_SOURCE, raw, "data_exfiltration")
        decision = self.decision_for(env)
        assert (decision.target_ip, decision.source_ip) == (TARGET_IP, ATTACKER_IP)

    def test_benign_traffic_is_measured_for_the_camera_to_sensor_pair(self):
        env, _, _ = _wired_env()
        env.measure_response(DefenseAction.BLOCK_SOURCE, _threat_event(attack_type="normal", source_ip="10.0.0.30", destination_ip="10.0.0.20"), "normal")
        decision = self.decision_for(env)
        assert (decision.target_ip, decision.source_ip) == (TARGET_IP, CAMERA_IP)

    def test_protocol_comes_from_the_captured_traffic_not_the_detectors_verdict(self, monkeypatch):
        env, _, log = _wired_env()
        _patch_attack_traffic(env, monkeypatch, log)
        env.last_attack_protocol = "ICMP"
        env.measure_response(DefenseAction.THROTTLE, _threat_event(protocol="TCP"), "icmp_ping_flood")
        assert self.decision_for(env).context["beliefs"]["observed_features"]["protocol"] == "ICMP"

    def test_protocol_falls_back_to_the_event_then_tcp(self, monkeypatch):
        env, _, log = _wired_env()
        _patch_attack_traffic(env, monkeypatch, log)
        env.measure_response(DefenseAction.THROTTLE, _threat_event(protocol="UDP"), "dos_flood")
        assert self.decision_for(env).context["beliefs"]["observed_features"]["protocol"] == "UDP"

    def test_observe_records_the_dominant_attacker_flow_protocol(self, monkeypatch):
        env = RealMininetDefenseEnv()
        env.net = MagicMock()
        env.monitor = MagicMock()
        env.monitor.stop_capture.return_value = "x.pcap"
        env.monitor.read_capture.return_value = []
        flows = [
            SimpleNamespace(source_ip="10.0.0.30", destination_ip="10.0.0.20", protocol="ICMP", packet_count=99),
            SimpleNamespace(source_ip=ATTACKER_IP, destination_ip=TARGET_IP, protocol="UDP", packet_count=5),
            SimpleNamespace(source_ip=ATTACKER_IP, destination_ip=TARGET_IP, protocol="TCP", packet_count=50),
        ]
        env.aggregator = MagicMock(aggregate=MagicMock(return_value=flows))
        env.detector = MagicMock()
        monkeypatch.setattr(env, "_attack_for", lambda c: SimpleNamespace(
            capture_packet_limit=10, capture_completion_timeout=1.0, generate_traffic=lambda net: None))
        env._observe_scenario("dos_flood")
        assert env.last_attack_protocol == "TCP"


class TestMeasureResponse:
    def test_counter_is_installed_after_the_response_and_removed_before_restore(self, monkeypatch):
        env, hosts, log = _wired_env()
        _patch_attack_traffic(env, monkeypatch, log)
        env.measure_response(DefenseAction.BLOCK_SOURCE, _threat_event(), "dos_flood")
        assert log == ["execute:BLOCK_SOURCE", "sensor:counter_installed", "traffic:attack", "sensor:counter_removed", "restore"]
        assert hosts["sensor"].installed == 0

    def test_inbound_attacks_are_counted_at_the_sensor_from_the_attacker(self, monkeypatch):
        env, hosts, log = _wired_env(counter=7)
        _patch_attack_traffic(env, monkeypatch, log)
        m, _ = env.measure_response(DefenseAction.BLOCK_SOURCE, _threat_event(), "dos_flood")
        assert any(f"-s {ATTACKER_IP}" in c and PROBE_COMMENT in c for c in hosts["sensor"].commands)
        assert not any(PROBE_COMMENT in c for c in hosts["attacker"].commands)
        assert m.residual_packets == 7 and m.service_loss == pytest.approx(0.2)
        rebased = with_baseline(m, 100)
        assert rebased.valid and rebased.containment == pytest.approx(0.93)

    def test_distributed_attacks_are_counted_from_every_source_address(self, monkeypatch):
        env, hosts, log = _wired_env(counter=40)
        _patch_attack_traffic(env, monkeypatch, log)
        m, _ = env.measure_response(DefenseAction.BLOCK_SOURCE, _threat_event(attack_type="dos_flood_distributed"), "dos_flood_distributed")
        counter_rule = next(c for c in hosts["sensor"].commands if PROBE_COMMENT in c and " -A INPUT" in c)
        senders = _senders("dos_flood_distributed")
        assert len(senders) >= 4 and f"-s {','.join(senders)} " in counter_rule
        # iptables keeps one counter per source: the reading must be their SUM, not the first line
        assert m.residual_packets == 40
        assert len([c for c in hosts["sensor"].commands if c.startswith("iptables -nvxL")]) == 1

    def test_outbound_attacks_are_counted_at_the_attacker_host_from_the_sensor(self, monkeypatch):
        env, hosts, log = _wired_env(counter=12)
        _patch_attack_traffic(env, monkeypatch, log)
        m, _ = env.measure_response(DefenseAction.BLOCK_SOURCE, _threat_event(attack_type="dns_tunneling_exfiltration"), "dns_tunneling_exfiltration")
        assert any(f"-s {TARGET_IP}" in c and PROBE_COMMENT in c for c in hosts["attacker"].commands)
        assert not any(PROBE_COMMENT in c for c in hosts["sensor"].commands)
        assert m.residual_packets == 12

    def test_allow_is_its_own_baseline(self, monkeypatch):
        env, _, log = _wired_env(counter=60)
        _patch_attack_traffic(env, monkeypatch, log)
        m, _ = env.measure_response(DefenseAction.ALLOW, _threat_event(), "dos_flood")
        assert m.baseline_packets == m.residual_packets == 60 and m.containment == 0.0

    def test_a_non_allow_measurement_is_invalid_until_given_a_baseline(self, monkeypatch):
        """A forgotten baseline must never score as containment."""
        env, _, log = _wired_env(counter=0)
        _patch_attack_traffic(env, monkeypatch, log)
        m, _ = env.measure_response(DefenseAction.ISOLATE, _threat_event(), "dos_flood")
        assert m.baseline_packets == 0 and not m.valid

    def test_a_leaked_counter_rule_from_a_crashed_probe_cannot_poison_the_reading(self, monkeypatch):
        env, hosts, log = _wired_env(counter=5, leaked_rules=2)
        _patch_attack_traffic(env, monkeypatch, log)
        m, _ = env.measure_response(DefenseAction.BLOCK_SOURCE, _threat_event(), "dos_flood")
        assert hosts["sensor"].installed == 0 and with_baseline(m, 100).valid

    def test_counter_install_failure_is_an_invalid_measurement_never_containment(self, monkeypatch):
        env, _, log = _wired_env(fail_install=True)
        _patch_attack_traffic(env, monkeypatch, log)
        m, outcome = env.measure_response(DefenseAction.ISOLATE, _threat_event(), "dos_flood")
        assert not with_baseline(m, 100).valid and m.service_loss == INVALID_SERVICE_LOSS
        assert "could not install probe counter" in outcome["probe_error"]
        assert "traffic:attack" not in log

    def test_a_generator_failure_invalidates_the_measurement_and_still_removes_the_counter(self, monkeypatch):
        env, hosts, log = _wired_env()
        _patch_attack_traffic(env, monkeypatch, log, raises=RuntimeError("generator died"))
        m, outcome = env.measure_response(DefenseAction.ISOLATE, _threat_event(), "dos_flood")
        assert not with_baseline(m, 100).valid and "generator died" in outcome["probe_error"]
        assert hosts["sensor"].installed == 0 and log[-1] == "restore"

    def test_a_missing_counter_rule_at_read_time_is_invalid(self, monkeypatch):
        env, hosts, log = _wired_env()
        _patch_attack_traffic(env, monkeypatch, log)
        original = hosts["sensor"].cmd
        hosts["sensor"].cmd = lambda c: ("" if c.startswith("iptables -nvxL") else original(c))
        m, outcome = env.measure_response(DefenseAction.ISOLATE, _threat_event(), "dos_flood")
        assert not with_baseline(m, 100).valid and "counter rule not found" in outcome["probe_error"]

    def test_unparsable_ping_output_is_invalid(self, monkeypatch):
        env, _, log = _wired_env(ping_output="garbage")
        _patch_attack_traffic(env, monkeypatch, log)
        m, outcome = env.measure_response(DefenseAction.ISOLATE, _threat_event(), "dos_flood")
        assert not with_baseline(m, 100).valid and "could not parse" in outcome["probe_error"]

    def test_a_pinging_host_with_no_interface_is_total_service_loss_not_an_invalid_probe(self, monkeypatch):
        env, _, log = _wired_env(ping_output="ping: connect: Network is unreachable\r\n")
        _patch_attack_traffic(env, monkeypatch, log)
        m, outcome = env.measure_response(DefenseAction.ISOLATE, _threat_event(), "dos_flood")
        assert m.service_loss == 1.0 and with_baseline(m, 100).valid and "probe_error" not in outcome

    def test_failed_execution_is_a_valid_zero_effect_measurement(self, monkeypatch):
        env, _, log = _wired_env(counter=100, ping_output="5 packets transmitted, 5 received, 0% packet loss", exec_status="failed")
        _patch_attack_traffic(env, monkeypatch, log)
        m, _ = env.measure_response(DefenseAction.ISOLATE, _threat_event(), "dos_flood")
        m = with_baseline(m, 100)
        assert m.status == "failed" and m.valid and m.containment == 0.0

    def test_normal_condition_installs_no_counter_and_has_no_containment(self):
        env, hosts, log = _wired_env()
        m, _ = env.measure_response(DefenseAction.ALLOW, _threat_event(attack_type="normal"), "normal")
        assert "traffic:normal" in log
        assert not any(PROBE_COMMENT in c for h in hosts.values() for c in h.commands)
        assert m.containment is None and m.valid


class TestIntel:
    def decoy_env(self, tmp_path, monkeypatch, records_during_traffic):
        env, _, log = _wired_env()
        decoy_log = tmp_path / "decoy.jsonl"
        # an older entry (the executor's own verification connection) predates the replay
        decoy_log.write_text(json.dumps({"timestamp": 0.0, "source_ip": ATTACKER_IP, "destination_port": 22}) + "\n", encoding="utf-8")
        env.executor.decoy.log_path = decoy_log

        def write_records():
            with decoy_log.open("a", encoding="utf-8") as fh:
                for source_ip in records_during_traffic:
                    fh.write(json.dumps({"timestamp": time.time() + 0.01, "source_ip": source_ip, "destination_port": 22}) + "\n")

        _patch_attack_traffic(env, monkeypatch, log, on_traffic=write_records)
        monkeypatch.setattr("iot_defense.defense.ppo_real_env.time.sleep", lambda s: None)
        return env

    def test_decoy_intel_requires_the_attacks_own_traffic_to_reach_the_decoy(self, tmp_path, monkeypatch):
        env = self.decoy_env(tmp_path, monkeypatch, [ATTACKER_IP])
        m, _ = env.measure_response(DefenseAction.DECOY, _threat_event(), "reconnaissance_port_scan")
        assert m.intel_verified is True

    def test_a_decoy_that_works_but_never_sees_the_attack_earns_no_intel(self, tmp_path, monkeypatch):
        env = self.decoy_env(tmp_path, monkeypatch, [])
        m, _ = env.measure_response(DefenseAction.DECOY, _threat_event(), "brute_force")
        assert m.intel_verified is False, "the executor's own pre-probe verification connection must not count"

    def test_other_sources_hitting_the_decoy_do_not_count(self, tmp_path, monkeypatch):
        env = self.decoy_env(tmp_path, monkeypatch, ["10.0.0.20"])
        m, _ = env.measure_response(DefenseAction.DECOY, _threat_event(), "brute_force")
        assert m.intel_verified is False

    def test_forensic_intel_is_the_evidence_flag_and_other_actions_earn_none(self, monkeypatch):
        env, _, log = _wired_env()
        _patch_attack_traffic(env, monkeypatch, log)
        assert env.measure_response(DefenseAction.FORENSIC_CAPTURE, _threat_event(), "dos_flood")[0].intel_verified is True
        assert env.measure_response(DefenseAction.BLOCK_SOURCE, _threat_event(), "dos_flood")[0].intel_verified is False
