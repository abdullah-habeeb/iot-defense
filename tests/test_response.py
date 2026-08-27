import json

import pytest

from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.executor import DecoyService, MininetResponseExecutor, MininetSafetyError


class FakeProcess:
    def __init__(self):
        self.running = True

    def poll(self):
        return None if self.running else 0

    def terminate(self):
        self.running = False

    def wait(self, timeout=None):
        return 0


class FakeInterface:
    name = "sensor-eth0"


class FakeHost:
    def __init__(self, name, ip):
        self.name = name
        self._ip = ip
        self.commands = []
        self.process = FakeProcess()

    def IP(self):
        return self._ip

    def defaultIntf(self):
        return FakeInterface()

    def cmd(self, command):
        self.commands.append(command)
        if command.startswith("ss -ltn"):
            return ":2222"
        return ""

    def popen(self, *args, **kwargs):
        return self.process


class FakeNetwork:
    def __init__(self):
        self.hosts = [
            FakeHost("sensor", "10.0.0.10"),
            FakeHost("attacker", "10.0.0.100"),
            FakeHost("decoy", "10.0.0.200"),
        ]


def decision(action):
    return DefenseDecision.create(
        action=action,
        target_ip="10.0.0.10",
        source_ip="10.0.0.100",
        reason="test decision",
        confidence=0.9,
        threat_score=0.5,
        policy_name="test",
        context={},
    )


def test_response_result_creation_and_serialization(tmp_path):
    result = MininetResponseExecutor(FakeNetwork(), log_path=tmp_path / "responses.jsonl").execute(decision(DefenseAction.ALLOW))
    serialized = result.to_dict()
    assert result.status == "success"
    assert result.latency_ms >= 0
    assert serialized["action"] == "ALLOW"
    assert serialized["started_at"]
    assert serialized["completed_at"]


def test_allow_and_alert_do_not_change_network_state(tmp_path):
    network = FakeNetwork()
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl")

    allow = executor.execute(decision(DefenseAction.ALLOW))
    alert = executor.execute(decision(DefenseAction.ALERT))

    assert allow.status == "success"
    assert alert.status == "success"
    assert all(not host.commands for host in network.hosts)
    records = [json.loads(line) for line in (tmp_path / "responses.jsonl").read_text().splitlines()]
    assert [record["action"] for record in records] == ["ALLOW", "ALERT"]


def test_isolation_request_validates_known_mininet_ip(tmp_path):
    executor = MininetResponseExecutor(FakeNetwork(), log_path=tmp_path / "responses.jsonl")
    result = executor.execute(decision(DefenseAction.ISOLATE))
    sensor = executor.net.hosts[0]

    assert result.status == "success"
    assert sensor.commands == ["ip link set dev sensor-eth0 down"]
    assert executor.restore("10.0.0.10")["state"] == "up"
    assert sensor.commands[-1] == "ip link set dev sensor-eth0 up"

    unsafe = decision(DefenseAction.ISOLATE)
    unsafe.target_ip = "127.0.0.1"
    failed = executor.execute(unsafe)
    assert failed.status == "failed"
    assert "Refusing" in failed.message


def test_decoy_lifecycle_and_executor_mapping(tmp_path):
    network = FakeNetwork()
    decoy = DecoyService(log_path=tmp_path / "decoy.jsonl", ports=(2222,))
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl", decoy=decoy)

    result = executor.execute(decision(DefenseAction.DECOY))

    assert result.status == "success"
    assert result.details["decoy_ip"] == "10.0.0.200"
    assert decoy.process is not None
    assert decoy.stop()["status"] == "stopped"


def test_missing_or_external_targets_fail_safely(tmp_path):
    executor = MininetResponseExecutor(FakeNetwork(), log_path=tmp_path / "responses.jsonl")
    unknown = decision(DefenseAction.ISOLATE)
    unknown.target_ip = "192.0.2.1"
    result = executor.execute(unknown)
    assert result.status == "failed"

    with pytest.raises(MininetSafetyError):
        executor._host_for_ip("10.0.2.15")