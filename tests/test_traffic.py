from iot_defense.simulation.traffic import (
    TrafficGenerator,
    start_multi_connection_listener,
    stop_multi_connection_listener,
)


class FakeHost:
    def __init__(self, name: str, ip: str, listen_after_calls: int = 1):
        self.name = name
        self._ip = ip
        self.commands: list[str] = []
        self._ss_calls = 0
        self._listen_after_calls = listen_after_calls

    def IP(self) -> str:
        return self._ip

    def cmd(self, command: str) -> str:
        self.commands.append(command)
        if "ss -ltn" in command:
            self._ss_calls += 1
            return "LISTEN 0 128 *:2222" if self._ss_calls >= self._listen_after_calls else ""
        if command.startswith("kill "):
            return ""
        return "12345"  # simulated backgrounded PID


class FakeNetwork:
    def __init__(self):
        self.hosts = {
            "attacker": FakeHost("attacker", "10.0.0.100"),
            "sensor": FakeHost("sensor", "10.0.0.10"),
        }

    def get(self, name: str) -> FakeHost:
        return self.hosts[name]


def test_start_multi_connection_listener_backgrounds_and_disowns():
    host = FakeHost("sensor", "10.0.0.10")
    pid = start_multi_connection_listener(host, 2222)

    assert pid == "12345"
    start_cmd = host.commands[0]
    assert "disown" in start_cmd
    assert "while True" in start_cmd  # accepts repeatedly, not just once
    assert "s.listen(" in start_cmd


def test_start_multi_connection_listener_extracts_real_pid_from_noisy_heredoc_output():
    """Regression coverage for a real bug found via a live Mininet repro:
    sending a multi-line heredoc through host.cmd() makes bash echo a "> "
    continuation prompt for every script line, and backgrounding with "&"
    prints its own "[1] <pid>" notification -- both land ahead of the real
    `echo $!` output in host.cmd()'s captured text. The observed raw output
    was literally "> > > > ... [1] 162191\\r\\n162191" -- naively
    .strip()-ing that (the previous implementation) produced a garbage
    multi-line "pid" that stop_multi_connection_listener() then passed
    straight to `kill`, silently never signaling the real process."""

    class NoisyHost(FakeHost):
        def cmd(self, command: str) -> str:
            self.commands.append(command)
            if "ss -ltn" in command:
                return "LISTEN 0 128 *:2222"
            if command.startswith("kill "):
                return ""
            # Realistic noisy heredoc + backgrounding output, real PID last.
            return "> " * 25 + "[1] 162191\r\n162191"

    host = NoisyHost("sensor", "10.0.0.10")
    pid = start_multi_connection_listener(host, 2222)

    assert pid == "162191"


def test_start_multi_connection_listener_retries_once_on_a_genuinely_empty_first_read():
    """Regression coverage for a real bug found via a live Mininet repro
    against the evaluation harness: under real repeated long-lived-session
    load (16 sequential conditions reusing one host session), `echo $!`
    came back completely empty on its first read, not just noisy --
    something the noisy-output fix above narrowed but didn't eliminate.
    `$!` is already set correctly by this point (only the *read* raced),
    so a second call on the same host session must recover it rather than
    raising immediately."""

    class EmptyOnceHost(FakeHost):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._pid_reads = 0

        def cmd(self, command: str) -> str:
            self.commands.append(command)
            if "ss -ltn" in command:
                return "LISTEN 0 128 *:2222"
            if command.startswith("kill "):
                return ""
            if command == "echo $!":
                self._pid_reads += 1
                return "" if self._pid_reads == 1 else "162191"
            return ""

    host = EmptyOnceHost("sensor", "10.0.0.10")
    pid = start_multi_connection_listener(host, 2222)

    assert pid == "162191"
    assert host.commands.count("echo $!") == 2


def test_start_multi_connection_listener_still_raises_if_both_reads_are_empty():
    class AlwaysEmptyHost(FakeHost):
        def cmd(self, command: str) -> str:
            self.commands.append(command)
            if "ss -ltn" in command:
                return "LISTEN 0 128 *:2222"
            if command.startswith("kill "):
                return ""
            if command == "echo $!":
                return ""
            return ""

    host = AlwaysEmptyHost("sensor", "10.0.0.10")
    try:
        start_multi_connection_listener(host, 2222)
        assert False, "expected a RuntimeError when both PID reads come back empty"
    except RuntimeError:
        pass


def test_start_multi_connection_listener_waits_for_readiness():
    """Regression coverage for the same readiness race this project has
    hit before (_start_tcp_listener in generate_dataset.py): traffic sent
    before the listener has actually bound is refused exactly like the
    bug this whole listener exists to fix."""
    host = FakeHost("sensor", "10.0.0.10", listen_after_calls=3)
    start_multi_connection_listener(host, 2222)
    ss_calls = sum(1 for c in host.commands if "ss -ltn" in c)
    assert ss_calls >= 3, "must keep polling until the listener reports it is actually listening"


def test_stop_multi_connection_listener_kills_the_pid():
    host = FakeHost("sensor", "10.0.0.10")
    stop_multi_connection_listener(host, "12345")
    assert host.commands == ["kill 12345 2>/dev/null || true"]


def test_generate_brute_force_traffic_starts_and_stops_a_real_listener():
    """Regression test: a real evaluation run found connect() was refused
    every time (nothing listened on the sensor's simulated login port),
    so sendall() never ran and a captured brute-force flow never actually
    contained its own "USER admin" payload -- shape-based detection never
    needed the payload, so this went unnoticed until a content-matching
    Suricata signature needed it to genuinely be present."""
    net = FakeNetwork()
    sensor = net.get("sensor")

    TrafficGenerator().generate_brute_force_mininet_traffic(net, duration_seconds=1)

    listener_start_calls = [c for c in sensor.commands if "disown" in c]
    listener_stop_calls = [c for c in sensor.commands if c.startswith("kill ")]
    assert len(listener_start_calls) == 1
    assert len(listener_stop_calls) == 1


def test_generate_brute_force_traffic_stops_listener_even_if_attack_command_raises():
    class RaisingAttacker(FakeHost):
        def cmd(self, command: str) -> str:
            if "USER admin" in command:
                raise RuntimeError("simulated Mininet failure")
            return super().cmd(command)

    net = FakeNetwork()
    net.hosts["attacker"] = RaisingAttacker("attacker", "10.0.0.100")
    sensor = net.get("sensor")

    try:
        TrafficGenerator().generate_brute_force_mininet_traffic(net, duration_seconds=1)
    except RuntimeError:
        pass

    assert any(c.startswith("kill ") for c in sensor.commands), "listener must be stopped even on failure"


def test_syn_flood_targets_the_real_detection_window_not_the_wrong_2x_theory():
    """Regression test for two real bugs found in this pacing (see the
    generator's own docstring): a fixed post-connect() sleep let real,
    variable connect() overhead silently drag the achieved rate around,
    and an earlier theory (SYN+RST per attempt means the target rate
    should be halved) was live-verified and falsified -- packets_per_second
    is 1:1 with attempts/sec for this one-directional flow, not 2:1.
    Live-verified separately (6/6 real Mininet trials measured
    17.58-17.61 packets/sec, all correctly detected as tcp_syn_flood);
    this test guards the constants a future edit could silently break
    without needing Mininet for every change."""
    net = FakeNetwork()
    result = TrafficGenerator().generate_syn_flood_mininet_traffic(net, duration_seconds=14)
    attacker = net.get("attacker")
    command = attacker.commands[-1]

    assert "interval = 0.05714285714285714" in command, (
        "interval must target 17.5 attempts/sec (1/17.5), the real detection "
        "window's center -- not a value derived from the falsified SYN+RST "
        "2x-packet theory"
    )
    assert "range(245)" in command, "14s / (1/17.5) attempts must be scheduled up front, not open-ended"
    assert "deadline = start + (i + 1) * interval" in command, (
        "must use a deadline-based scheduler (absorbs connect() overhead into "
        "the interval) rather than a fixed post-connect() sleep"
    )
    assert result["target"] == "10.0.0.10"
