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
