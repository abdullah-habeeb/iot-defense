"""Unit tests for PacketMonitor.start_capture()'s watchdog_seconds --
no real Mininet required."""
from __future__ import annotations

from iot_defense.monitoring.monitor import PacketMonitor


class FakeInterface:
    def __init__(self, name):
        self.name = name


class FakeHost:
    def __init__(self, name):
        self.name = name
        self.commands = []

    def defaultIntf(self):
        return FakeInterface(f"{self.name}-eth0")

    def cmd(self, command):
        self.commands.append(command)
        if command.startswith("grep"):
            return "listening on eth0\n"  # immediately satisfy the marker poll
        return "12345\n"


class FakeNetwork:
    def __init__(self):
        self.host = FakeHost("sensor")

    def get(self, name):
        return self.host


def test_start_capture_wraps_tcpdump_in_timeout_when_watchdog_given(tmp_path):
    monitor = PacketMonitor(base_dir=tmp_path)
    net = FakeNetwork()
    monitor.start_capture(net, "sensor", packet_limit=30, watchdog_seconds=95.0)
    launch_commands = [c for c in net.host.commands if "-i sensor-eth0" in c]
    assert len(launch_commands) == 1
    assert "timeout 95.0s tcpdump" in launch_commands[0]


def test_start_capture_omits_timeout_wrapper_when_no_watchdog_given(tmp_path):
    monitor = PacketMonitor(base_dir=tmp_path)
    net = FakeNetwork()
    monitor.start_capture(net, "sensor", packet_limit=30)
    launch_commands = [c for c in net.host.commands if "-i sensor-eth0" in c]
    assert len(launch_commands) == 1
    assert "timeout" not in launch_commands[0]
    assert launch_commands[0].startswith("tcpdump")
