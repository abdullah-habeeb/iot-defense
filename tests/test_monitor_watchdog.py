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


def test_start_capture_uses_packet_buffered_mode(tmp_path):
    """Regression test for a real bug: without -U, tcpdump only flushes
    its write buffer once it fills or the process exits cleanly. A
    sparse, low-rate capture (confirmed via a real repro: c2_beaconing's
    own traffic, ~20-40 packets over 28s) can sit on its last packet(s)
    in memory until force-terminated, and a SIGKILL fallback then loses
    them -- producing a truncated pcap. -U flushes after every packet,
    so even a SIGKILL can only ever lose a packet that hadn't arrived
    yet."""
    monitor = PacketMonitor(base_dir=tmp_path)
    net = FakeNetwork()
    monitor.start_capture(net, "sensor", packet_limit=30)
    launch_commands = [c for c in net.host.commands if "-i sensor-eth0" in c]
    assert len(launch_commands) == 1
    assert "tcpdump -U " in launch_commands[0]
