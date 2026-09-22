import json
from pathlib import Path

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
    def __init__(self, name, ip, session_killable=True):
        self.name = name
        self._ip = ip
        self.commands = []
        self._interface_up = True
        self._input_rules = []
        self._output_rules = []
        self._session_established = True
        # Real live-Mininet behavior: ss -K genuinely destroys the socket
        # (confirmed directly against a real connection) -- this flag lets
        # one specific regression test simulate the opposite, to prove the
        # RuntimeError path still fires for a real unrecovered failure.
        self._session_killable = session_killable
        self._qdisc_installed = False

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
        if command.startswith("iptables -A INPUT"):
            self._input_rules.append(command)
            return ""
        if command.startswith("iptables -D INPUT"):
            add_form = command.replace("-D INPUT", "-A INPUT", 1)
            if add_form in self._input_rules:
                self._input_rules.remove(add_form)
            return ""
        if command.startswith("iptables -A OUTPUT"):
            self._output_rules.append(command)
            return ""
        if command.startswith("iptables -D OUTPUT"):
            add_form = command.replace("-D OUTPUT", "-A OUTPUT", 1)
            if add_form in self._output_rules:
                self._output_rules.remove(add_form)
            return ""
        if command.startswith("iptables -L INPUT"):
            return "Chain INPUT (policy ACCEPT)\n" + "\n".join(self._input_rules)
        if command.startswith("iptables -L OUTPUT"):
            return "Chain OUTPUT (policy ACCEPT)\n" + "\n".join(self._output_rules)
        if command.startswith("ss -K"):
            if self._session_killable:
                self._session_established = False
            return "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\ntcp   ESTAB  0      0          10.0.0.10:7100    10.0.0.100:54321\n"
        if command.startswith("ss -tn"):
            header = "Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"
            if self._session_established:
                return header + "0      0          10.0.0.10:7100    10.0.0.100:54321\n"
            return header
        if command.startswith("tc qdisc add"):
            self._qdisc_installed = True
            return ""
        if command.startswith("tc qdisc del"):
            self._qdisc_installed = False
            return ""
        if command.startswith("tc qdisc show"):
            return "qdisc tbf 8001: root refcnt 2 rate 50Kbit burst 5Kb lat 400ms\n" if self._qdisc_installed else "qdisc noqueue 0: root refcnt 2\n"
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


class _PcapWritingHost(FakeHost):
    """Stands in for a real tcpdump backgrounded via host.cmd() -- writes
    bytes past the real libpcap header size to the -w target path
    immediately, since nothing in this fake actually runs tcpdump to
    produce them. Must write strictly more than _PCAP_HEADER_SIZE (24)
    to represent a capture that actually saw traffic, not an empty one --
    see forensic_capture()'s own docstring for the real bug a 24-byte
    "non-empty" pcap caused."""

    def cmd(self, command):
        self.commands.append(command)
        if "tcpdump" in command and " -w " in command:
            path = command.split(" -w ", 1)[1].split(" ", 1)[0]
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_bytes(b"\x00" * 48)
            return ""
        if command.startswith("ss -tapn") or command.startswith("ip neigh"):
            return ""
        return ""


class _EmptyPcapWritingHost(FakeHost):
    """Stands in for a real tcpdump that opens and closes having captured
    nothing -- writes exactly a real libpcap global header's worth of
    bytes (24), matching what a real live run actually produced when the
    attack's own traffic had already finished by the time the capture
    started."""

    def cmd(self, command):
        self.commands.append(command)
        if "tcpdump" in command and " -w " in command:
            path = command.split(" -w ", 1)[1].split(" ", 1)[0]
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_bytes(b"\x00" * 24)
            return ""
        if command.startswith("ss -tapn") or command.startswith("ip neigh"):
            return ""
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


def test_block_source_installs_a_drop_rule_and_restore_removes_it(tmp_path):
    network = FakeNetwork()
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl")

    result = executor.execute(decision(DefenseAction.BLOCK_SOURCE))

    assert result.status == "success"
    assert result.details["source_ip"] == "10.0.0.100"
    sensor = network.hosts[0]
    assert any("10.0.0.100" in rule and "DROP" in rule for rule in sensor._input_rules)

    executor.restore("10.0.0.10")
    assert sensor._input_rules == []


def test_block_source_is_idempotent_for_the_same_source(tmp_path):
    executor = MininetResponseExecutor(FakeNetwork(), log_path=tmp_path / "responses.jsonl")
    executor.execute(decision(DefenseAction.BLOCK_SOURCE))
    second = executor.execute(decision(DefenseAction.BLOCK_SOURCE))
    assert second.status == "success"
    assert second.details["status"] == "already_blocked"


def test_block_source_handles_multiple_distinct_sources_against_one_target(tmp_path):
    """block_source() has always kept a per-target *list*, not a single
    slot, specifically so a distributed/multi-source attack against one
    target gets every real source blocked, not just the first one seen --
    see simulation/traffic.py's generate_replay_attack_distributed_
    mininet_traffic for the real spoofed-multi-source traffic this is
    meant to eventually face. Real detection currently reports one source
    per detected flow (FeatureAggregator groups by (src, dst, protocol)),
    so a distributed attack would call block_source() once per distinct
    source it sees, not once with a list -- this proves that repeated
    calling pattern already accumulates correctly rather than overwriting
    the previous source's block."""
    network = FakeNetwork()
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl")
    sensor = network.hosts[0]
    spoofed_sources = ["10.0.0.121", "10.0.0.122", "10.0.0.123", "10.0.0.124"]

    for source_ip in spoofed_sources:
        details = executor.block_source("10.0.0.10", source_ip)
        assert details.get("status") != "already_blocked"

    for source_ip in spoofed_sources:
        assert any(source_ip in rule and "DROP" in rule for rule in sensor._input_rules)
    assert len(sensor._input_rules) == len(spoofed_sources)

    # A source already blocked doesn't get a duplicate rule.
    repeat = executor.block_source("10.0.0.10", spoofed_sources[0])
    assert repeat["status"] == "already_blocked"
    assert len(sensor._input_rules) == len(spoofed_sources)

    executor.restore("10.0.0.10")
    assert sensor._input_rules == []


def test_quarantine_installs_default_deny_with_allowlist_and_restore_removes_it(tmp_path):
    network = FakeNetwork()
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl")

    result = executor.execute(decision(DefenseAction.QUARANTINE))

    assert result.status == "success"
    sensor = network.hosts[0]
    # The attacker (denied) must not appear in the allowlist; the decoy
    # host (neither target nor attacker) must.
    assert "10.0.0.100" not in result.details["allowed_ips"]
    assert "10.0.0.200" in result.details["allowed_ips"]
    assert any(rule.endswith("-j DROP") for rule in sensor._input_rules)
    assert any(rule.endswith("-j DROP") for rule in sensor._output_rules)

    executor.restore("10.0.0.10")
    assert sensor._input_rules == []
    assert sensor._output_rules == []


def test_reset_sessions_clears_a_real_established_connection(tmp_path):
    """Regression coverage for a real bug found via a live Mininet run:
    the verification poll assumed ss -tn's header line started with
    "State", which a real run showed was never true (the real header is
    "Recv-Q Send-Q Local Address:Port ..."), so the header always
    survived filtering and every call reported "still established" even
    though ss -K had genuinely cleared the connection (confirmed
    separately against a real socket)."""
    network = FakeNetwork()
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl")

    result = executor.execute(decision(DefenseAction.RESET_SESSIONS))

    assert result.status == "success"
    assert result.details["source_ip"] == "10.0.0.100"


def test_reset_sessions_raises_when_the_connection_never_clears(tmp_path):
    network = FakeNetwork()
    network.hosts[0] = FakeHost("sensor", "10.0.0.10", session_killable=False)
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl")

    result = executor.execute(decision(DefenseAction.RESET_SESSIONS))

    assert result.status == "failed"
    assert "still established" in result.message.lower()


def test_forensic_capture_falls_back_to_a_live_capture_with_real_content(tmp_path):
    """No prior detection capture exists at detection_capture_dir, so this
    exercises the live-capture fallback path. Called directly with a
    short duration (not through execute(), which always uses the real 5s
    default) to keep the test fast."""
    network = FakeNetwork()
    network.hosts[0] = _PcapWritingHost("sensor", "10.0.0.10")
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl")

    details = executor.forensic_capture(
        "10.0.0.10",
        "10.0.0.100",
        duration_seconds=0.05,
        evidence_dir=tmp_path / "forensics",
        detection_capture_dir=tmp_path / "no_detection_capture_here",
    )

    assert details["operation"] == "forensic_capture"
    assert details["preserved_from_detection"] is False
    assert Path(details["pcap_path"]).exists()
    assert Path(details["pcap_path"]).stat().st_size > 24


def test_forensic_capture_preserves_the_real_detection_capture_when_available(tmp_path):
    """Regression test for a real bug found via a live Mininet run: this
    method originally always opened a FRESH live capture, but by the time
    a response executes, detection has already run against the attack's
    *complete* capture -- the attack's own traffic generation has already
    finished, so a fresh capture opens onto a quiet network. Confirmed
    live: several real rogue_config_beacon responses each produced an
    exact 24-byte pcap (a valid but empty capture), and the original
    `size > 0` check couldn't tell that apart from real evidence. The fix
    preserves PacketMonitor's own already-captured, real-traffic pcap
    (sitting at a fixed, predictable path) instead of trying to capture
    traffic that's already gone."""
    network = FakeNetwork()
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl")
    detection_dir = tmp_path / "detection"
    detection_dir.mkdir()
    (detection_dir / "sensor_capture.pcap").write_bytes(b"\x00" * 200)

    details = executor.forensic_capture(
        "10.0.0.10",
        "10.0.0.100",
        duration_seconds=0.05,
        evidence_dir=tmp_path / "forensics",
        detection_capture_dir=detection_dir,
    )

    assert details["preserved_from_detection"] is True
    assert Path(details["pcap_path"]).stat().st_size == 200
    # No live-capture command should have been issued at all -- the real
    # detection capture was already sufficient.
    sensor = network.hosts[0]
    assert not any("tcpdump" in cmd for cmd in sensor.commands)


def test_forensic_capture_raises_when_no_real_evidence_exists_anywhere(tmp_path):
    """The exact bug scenario, end to end: no usable prior detection
    capture (empty, 24-byte header only) AND a live capture that also
    sees no traffic. Must raise, not silently report success on an empty
    file the way the original size > 0 check did."""
    network = FakeNetwork()
    network.hosts[0] = _EmptyPcapWritingHost("sensor", "10.0.0.10")
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl")
    detection_dir = tmp_path / "detection"
    detection_dir.mkdir()
    (detection_dir / "sensor_capture.pcap").write_bytes(b"\x00" * 24)

    with pytest.raises(RuntimeError, match="no real evidence"):
        executor.forensic_capture(
            "10.0.0.10",
            "10.0.0.100",
            duration_seconds=0.05,
            evidence_dir=tmp_path / "forensics",
            detection_capture_dir=detection_dir,
        )


def test_bandwidth_cap_installs_tbf_on_the_attacker_and_restore_removes_it(tmp_path):
    network = FakeNetwork()
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl")

    result = executor.execute(decision(DefenseAction.BANDWIDTH_CAP))

    assert result.status == "success"
    attacker = network.hosts[1]
    assert attacker.name == "attacker"
    assert attacker._qdisc_installed is True

    executor.restore("10.0.0.10")
    assert attacker._qdisc_installed is False

def test_quarantine_revokes_a_second_distinct_sources_earlier_accept_rule(tmp_path):
    """Regression test for a real, confirmed leak: a second quarantine()
    call for a target already quarantined against a *different* source
    used to silently no-op, leaving that new source's own earlier ACCEPT
    rule (baked in when it still looked like a legitimate peer) active."""
    network = FakeNetwork()
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl")
    sensor = network.hosts[0]

    first = executor.quarantine("10.0.0.10", "10.0.0.100")
    assert "10.0.0.200" in first["allowed_ips"]
    assert any("10.0.0.200" in rule and "ACCEPT" in rule for rule in sensor._input_rules)

    second = executor.quarantine("10.0.0.10", "10.0.0.200")
    assert second["status"] == "success"
    assert not any("10.0.0.200" in rule and "ACCEPT" in rule for rule in sensor._input_rules)
    assert not any("10.0.0.200" in rule and "ACCEPT" in rule for rule in sensor._output_rules)

    third = executor.quarantine("10.0.0.10", "10.0.0.200")
    assert third["status"] == "already_quarantined"

    executor.restore("10.0.0.10")
    assert sensor._input_rules == []
    assert sensor._output_rules == []


def test_bandwidth_cap_installs_a_qdisc_for_a_second_distinct_source(tmp_path):
    """Regression test for a real, confirmed gap: a second bandwidth_cap()
    call for an already-capped target used to silently skip installing a
    qdisc for a genuinely different attacker source."""
    network = FakeNetwork()
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl")
    attacker = network.hosts[1]
    decoy = network.hosts[2]

    first = executor.bandwidth_cap("10.0.0.10", "10.0.0.100")
    assert first["host"] == "attacker"
    assert attacker._qdisc_installed is True
    assert decoy._qdisc_installed is False

    second = executor.bandwidth_cap("10.0.0.10", "10.0.0.200")
    assert second.get("status") != "already_capped"
    assert decoy._qdisc_installed is True

    repeat = executor.bandwidth_cap("10.0.0.10", "10.0.0.100")
    assert repeat["status"] == "already_capped"

    executor.restore("10.0.0.10")
    assert attacker._qdisc_installed is False
    assert decoy._qdisc_installed is False


def test_block_source_rejects_a_malformed_source_ip_before_reaching_the_shell(tmp_path):
    """Regression test: source_ip used to reach host.cmd() as a raw
    f-string with no format validation, an injection-shaped primitive."""
    network = FakeNetwork()
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl")
    with pytest.raises(MininetSafetyError):
        executor.block_source("10.0.0.10", "10.0.0.100; touch /tmp/pwned")
    sensor = network.hosts[0]
    assert not any("pwned" in c for c in sensor.commands)


def test_reset_sessions_rejects_a_malformed_source_ip_before_reaching_the_shell(tmp_path):
    network = FakeNetwork()
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl")
    with pytest.raises(MininetSafetyError):
        executor.reset_sessions("10.0.0.10", "10.0.0.100; touch /tmp/pwned")
    sensor = network.hosts[0]
    assert not any("pwned" in c for c in sensor.commands)


def test_quarantine_rejects_a_malformed_source_ip_on_the_repeat_source_path(tmp_path):
    network = FakeNetwork()
    executor = MininetResponseExecutor(network, log_path=tmp_path / "responses.jsonl")
    executor.quarantine("10.0.0.10", "10.0.0.100")
    with pytest.raises(MininetSafetyError):
        executor.quarantine("10.0.0.10", "10.0.0.200; touch /tmp/pwned")
