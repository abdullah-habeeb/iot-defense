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
    def __init__(self, name):
        self.name = name


class FakeHost:
    def __init__(self, name, ip):
        self.name = name
        self._ip = ip
        self.commands = []
        self._interface_up = True

    def IP(self):
        return self._ip

    def defaultIntf(self):
        return FakeInterface(f"{self.name}-eth0")

    def cmd(self, command):
        self.commands.append(command)
        if command.startswith("ss -ltn"):
            return ":2222"
        if command.startswith("ip link set"):
            self._interface_up = command.rstrip().endswith("up")
            return ""
        if command.startswith("ip link show"):
            state = "UP" if self._interface_up else "DOWN"
            return f"2: {self.name}-eth0: <BROADCAST,MULTICAST> mtu 1500 qdisc noqueue state {state} mode DEFAULT\r\n"
        return ""

    def popen(self, *args, **kwargs):
        # A fresh FakeProcess per call, matching real subprocess.Popen()
        # semantics -- a shared, single instance would carry a prior call's
        # "terminated" state into a later, genuinely-fresh process, which
        # is exactly what real Mininet's own host.popen() never does.
        return FakeProcess()


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
    assert sensor.commands == ["ip link set dev sensor-eth0 down", "ip link show dev sensor-eth0"]
    assert executor.restore("10.0.0.10")["state"] == "up"
    assert sensor.commands[-1] == "ip link set dev sensor-eth0 up"

    unsafe = decision(DefenseAction.ISOLATE)
    unsafe.target_ip = "127.0.0.1"
    failed = executor.execute(unsafe)
    assert failed.status == "failed"
    assert "Refusing" in failed.message


def test_isolate_raises_when_the_interface_never_actually_goes_down(tmp_path):
    """Regression test: isolate() used to fire `ip link set ... down` and
    unconditionally report success, even if the command silently failed
    (a stale interface name, a permission issue, or leaked-shell-output
    pty corruption) -- host.cmd() never raises on a failed command, so
    nothing would have surfaced that. It must now verify the real effect,
    the same way throttle() and DecoyService.start() already do."""

    class StubbornHost(FakeHost):
        def cmd(self, command):
            self.commands.append(command)
            if command.startswith("ip link show"):
                return f"2: {self.name}-eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> state UP\r\n"
            return ""

    network = FakeNetwork()
    network.hosts[0] = StubbornHost("sensor", "10.0.0.10")
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl")

    result = executor.execute(decision(DefenseAction.ISOLATE))

    assert result.status == "failed"
    assert "10.0.0.10" not in executor._isolated


def test_decoy_stop_clears_process_even_when_terminate_times_out(tmp_path):
    """Regression test: a stuck terminate() used to leave self.process
    pointing at a process this instance still believed was running -- the
    next start() call would see poll() is None and report
    "already_running" without actually starting a fresh decoy."""
    import subprocess

    class StuckProcess(FakeProcess):
        def wait(self, timeout=None):
            if self.running:
                raise subprocess.TimeoutExpired(cmd="decoy", timeout=timeout)
            return 0

        def kill(self):
            self.running = False

    decoy = DecoyService(log_path=tmp_path / "decoy.jsonl", ports=(2222,))
    decoy.process = StuckProcess()
    decoy.host = FakeHost("decoy", "10.0.0.200")

    result = decoy.stop()

    assert result["status"] == "stopped"
    assert decoy.process is None


def test_throttle_installs_tc_qdisc_and_restore_removes_it(tmp_path):
    executor = MininetResponseExecutor(FakeNetwork(), log_path=tmp_path / "responses.jsonl")
    result = executor.execute(decision(DefenseAction.THROTTLE))
    sensor = executor.net.hosts[0]
    expected_add_rule = (
        "iptables -A INPUT -p tcp --syn -d 10.0.0.10 -m hashlimit "
        "--hashlimit-above 3/sec --hashlimit-burst 3 --hashlimit-mode dstip "
        "--hashlimit-name throttle_sensor -j DROP"
    )
    expected_delete_rule = expected_add_rule.replace("-A INPUT", "-D INPUT", 1)

    assert result.status == "success"
    assert result.details["operation"] == "throttle"
    assert sensor.commands == [expected_add_rule]

    restored = executor.restore("10.0.0.10")
    assert restored["state"] == "up"
    assert restored["throttle_removed"] is True
    assert sensor.commands[-2:] == [
        "ip link set dev sensor-eth0 up",
        expected_delete_rule,
    ]


def test_throttle_is_idempotent_when_already_throttled(tmp_path):
    executor = MininetResponseExecutor(FakeNetwork(), log_path=tmp_path / "responses.jsonl")
    sensor = executor.net.hosts[0]

    first = executor.throttle("10.0.0.10")
    second = executor.throttle("10.0.0.10")

    assert first["operation"] == "throttle"
    assert second["status"] == "already_throttled"
    assert sum(1 for cmd in sensor.commands if cmd.startswith("iptables -A INPUT")) == 1


def test_restore_without_prior_throttle_or_isolate_does_not_remove_a_rule(tmp_path):
    """restore() must stay a safe no-op-ish call when nothing was actually
    throttled or isolated -- it should still bring the interface up (the
    existing isolate-focused safety net), but never issue an iptables
    delete for a target that was never throttled."""
    executor = MininetResponseExecutor(FakeNetwork(), log_path=tmp_path / "responses.jsonl")
    sensor = executor.net.hosts[0]

    result = executor.restore("10.0.0.10")

    assert result["throttle_removed"] is False
    assert sensor.commands == ["ip link set dev sensor-eth0 up"]


def test_cleanup_restores_both_isolated_and_throttled_hosts(tmp_path):
    network = FakeNetwork()
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl")
    sensor, attacker = network.hosts[0], network.hosts[1]

    executor.isolate("10.0.0.10")
    executor.throttle("10.0.0.100")
    executor.cleanup()

    assert "ip link set dev sensor-eth0 up" in sensor.commands
    assert any(cmd.startswith("iptables -D INPUT") for cmd in attacker.commands)
    assert executor._isolated == {}
    assert executor._throttled == {}


def test_decoy_lifecycle_and_executor_mapping(tmp_path):
    network = FakeNetwork()
    decoy = DecoyService(log_path=tmp_path / "decoy.jsonl", ports=(2222,))
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl", decoy=decoy)

    result = executor.execute(decision(DefenseAction.DECOY))

    assert result.status == "success"
    assert result.details["decoy_ip"] == "10.0.0.200"
    assert decoy.process is not None
    assert decoy.stop()["status"] == "stopped"


def test_restore_removes_decoy_redirect_and_stops_the_service(tmp_path):
    """Regression test: restore() used to only clear _isolated/_throttled --
    a decoy redirect installed by execute(DECOY) was left in place, and the
    decoy service kept running, until cleanup() ran at the very end of a
    network's whole lifetime. Confirmed via a real evaluation-harness run
    that called DECOY repeatedly on one long-lived network: redirect rules
    from an earlier call were still installed when a later call tried to
    add new ones, and the decoy service's already-bound ports made its
    next start() attempt fail. restore() must tear both down per-target,
    the same way it already does for isolate/throttle."""
    network = FakeNetwork()
    decoy = DecoyService(log_path=tmp_path / "decoy.jsonl", ports=(2222,))
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl", decoy=decoy)
    source_host = executor.net.hosts[1]  # attacker, the decision's source_ip

    executor.execute(decision(DefenseAction.DECOY))
    assert executor._redirect_rules["10.0.0.10"]
    assert decoy.process is not None
    added_rules = [c for c in source_host.commands if c.startswith("iptables -t nat -A")]
    assert added_rules

    restored = executor.restore("10.0.0.10")

    assert restored["decoy_removed"] is True
    assert executor._redirect_rules == {}
    assert decoy.process is None  # the service was stopped, not left running
    removed_rules = [c for c in source_host.commands if c.startswith("iptables -t nat -D")]
    assert len(removed_rules) == len(added_rules)


def test_repeated_decoy_calls_on_the_same_target_do_not_accumulate_rules(tmp_path):
    """A second DECOY execution against the same target, after a proper
    restore() in between, must not find leftover rules from the first --
    this is the exact scenario the evaluation harness hit for real."""
    network = FakeNetwork()
    decoy = DecoyService(log_path=tmp_path / "decoy.jsonl", ports=(2222,))
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl", decoy=decoy)

    first = executor.execute(decision(DefenseAction.DECOY))
    executor.restore("10.0.0.10")
    second = executor.execute(decision(DefenseAction.DECOY))

    assert first.status == "success"
    assert second.status == "success"
    assert len(executor._redirect_rules["10.0.0.10"]) == len(decoy.ports)


def test_missing_or_external_targets_fail_safely(tmp_path):
    executor = MininetResponseExecutor(FakeNetwork(), log_path=tmp_path / "responses.jsonl")
    unknown = decision(DefenseAction.ISOLATE)
    unknown.target_ip = "192.0.2.1"
    result = executor.execute(unknown)
    assert result.status == "failed"

    with pytest.raises(MininetSafetyError):
        executor._host_for_ip("10.0.2.15")


class _StrayOutputHost(FakeHost):
    """A host whose cmd() returns canned text for the iptables add-rule
    command specifically, standing in for the real leaked shell output a
    live run produced (see executor.py's throttle() comment)."""

    def __init__(self, name, ip, add_rule_output):
        super().__init__(name, ip)
        self._add_rule_output = add_rule_output

    def cmd(self, command):
        self.commands.append(command)
        if command.startswith("iptables -A INPUT"):
            return self._add_rule_output
        if command.startswith("ss -ltn"):
            return ":2222"
        return ""


def test_throttle_ignores_leaked_non_iptables_output(tmp_path):
    """Regression test: a real live run once raised "Unable to install
    traffic-control rate limit: 98 packets captured" -- tcpdump's own exit
    summary, leaked into the shell channel by a prior SIGTERM'd capture,
    misread as an iptables failure even though the rule installed fine.
    Non-iptables stray text must not be treated as a real failure."""
    network = FakeNetwork()
    network.hosts[0] = _StrayOutputHost("sensor", "10.0.0.10", "98 packets captured")
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl")

    result = executor.execute(decision(DefenseAction.THROTTLE))

    assert result.status == "success"
    assert result.details["operation"] == "throttle"


def test_throttle_still_raises_on_a_real_iptables_error(tmp_path):
    """The discriminating check in the test above must not swallow a
    genuine failure -- real iptables errors are always prefixed
    "iptables"."""
    network = FakeNetwork()
    network.hosts[0] = _StrayOutputHost(
        "sensor", "10.0.0.10", "iptables: No chain/target/match by that name."
    )
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl")

    result = executor.execute(decision(DefenseAction.THROTTLE))

    assert result.status == "failed"
    assert "iptables" in result.message.lower()