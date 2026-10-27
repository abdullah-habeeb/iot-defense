"""The two new attacks' traffic generators and their in-process registration. No Mininet: the generator scripts are run against
local sockets, so the traffic shape (sizes, ports, rate, alternation) is checked for real."""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
import time

import pytest

from iot_defense.attacks import registry
from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.ppo_env import TRAINING_SCENARIOS
from iot_defense.experiments.new_attacks import scenarios as na


def run_script(script: str, timeout: float = 20.0) -> str:
    done = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=timeout, check=True)
    return done.stdout


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestScripts:
    def test_placeholders_are_all_filled_and_both_scripts_compile(self):
        for script in (na.ssdp_script(), na.telnet_script()):
            assert "__" not in script
            compile(script, "<generator>", "exec")

    def test_an_unfilled_placeholder_is_refused(self):
        with pytest.raises(ValueError):
            na.render("x = __MISSING__", OTHER=1)

    def test_ssdp_sends_340_byte_search_responses_from_source_port_1900(self):
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(0.5)
        port = receiver.getsockname()[1]
        packets: list[tuple[bytes, tuple[str, int]]] = []

        def collect() -> None:
            deadline = time.time() + 5
            while time.time() < deadline:
                try:
                    packets.append(receiver.recvfrom(4096))
                except socket.timeout:
                    if packets:
                        return

        thread = threading.Thread(target=collect)
        thread.start()
        output = run_script(na.ssdp_script(src_ip="127.0.0.1", dst_ip="127.0.0.1", duration=0.9, dst_port=port))
        thread.join()
        receiver.close()
        assert "ssdp_reflection_done" in output
        assert len(packets) >= 5
        assert {len(data) for data, _ in packets} == {na.SSDP_PAYLOAD_BYTES}
        assert {addr[1] for _, addr in packets} == {na.SSDP_SOURCE_PORT}
        text = packets[0][0].decode()
        assert text.startswith("HTTP/1.1 200 OK\r\n") and "ST: upnp:rootdevice" in text

    def test_ssdp_never_exceeds_the_packet_cap(self):
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind(("127.0.0.1", 0))
        port = receiver.getsockname()[1]
        output = run_script(na.ssdp_script(src_ip="127.0.0.1", dst_ip="127.0.0.1", duration=30, dst_port=port).replace("0.12", "0.001"))
        receiver.close()
        assert f"ssdp_reflection_done {na.SSDP_MAX_PACKETS}" in output

    def test_telnet_scan_alternates_between_the_two_ports(self):
        ports = (free_port(), free_port())
        accepted: list[int] = []
        listeners = []
        for index, port in enumerate(ports):
            sock = socket.socket()
            sock.bind(("127.0.0.1", port))
            sock.listen(128)
            sock.settimeout(0.2)
            listeners.append(sock)
        stop = threading.Event()

        def accept(sock: socket.socket, port: int) -> None:
            while not stop.is_set():
                try:
                    conn, _ = sock.accept()
                    conn.close()
                    accepted.append(port)
                except (socket.timeout, OSError):
                    continue

        threads = [threading.Thread(target=accept, args=(s, p)) for s, p in zip(listeners, ports)]
        for t in threads:
            t.start()
        output = run_script(na.telnet_script(dst_ip="127.0.0.1", duration=1.0, ports=ports))
        time.sleep(0.4)
        stop.set()
        for t in threads:
            t.join()
        for s in listeners:
            s.close()
        assert "telnet_scan_done" in output
        assert len(accepted) >= 8
        assert abs(accepted.count(ports[0]) - accepted.count(ports[1])) <= 2

    def test_telnet_scan_also_runs_against_refused_ports(self):
        closed = (free_port(), free_port())
        output = run_script(na.telnet_script(dst_ip="127.0.0.1", duration=1.0, ports=closed))
        attempts = int(output.split()[-1])
        assert attempts >= 6  # about 15 a second when the machine is idle; a loose floor so a busy machine does not fail it


class TestScenarios:
    def test_the_two_scenarios_have_the_right_shape(self):
        scenarios = na.build_scenarios()
        assert set(scenarios) == set(na.NEW_ATTACK_KEYS)
        assert scenarios[na.SSDP_KEY].traffic_direction == "inbound"
        assert scenarios[na.TELNET_KEY].traffic_direction == "outbound"
        for key, scenario in scenarios.items():
            assert scenario.attack_type == key
            assert scenario.capture_duration_seconds < scenario.capture_completion_timeout
            assert scenario.preferred_action == DefenseAction.ALERT  # until the pre-registration supplies the playbook

    def test_the_playbook_response_is_taken_from_the_pre_registration(self):
        scenarios = na.build_scenarios({na.SSDP_KEY: DefenseAction.BANDWIDTH_CAP})
        assert scenarios[na.SSDP_KEY].preferred_action == DefenseAction.BANDWIDTH_CAP
        assert scenarios[na.TELNET_KEY].preferred_action == DefenseAction.ALERT

    def test_the_passive_detector_never_flags(self):
        event = na.PassiveDetector().detect({"source_ip": "10.0.0.100", "destination_ip": "10.0.0.10", "packets_per_second": 999})
        assert event.attack_type == "normal"

    def test_registration_is_temporary_and_leaves_the_benchmark_untouched(self):
        before = list(registry.ATTACK_SCENARIOS)
        with na.registered(na.build_scenarios()):
            assert na.SSDP_KEY in registry.ATTACK_SCENARIOS and na.TELNET_KEY in TRAINING_SCENARIOS()
            assert len(registry.ATTACK_SCENARIOS) == 22
        assert list(registry.ATTACK_SCENARIOS) == before and len(TRAINING_SCENARIOS()) == 21

    def test_registration_is_undone_even_when_the_block_raises(self):
        with pytest.raises(RuntimeError):
            with na.registered(na.build_scenarios()):
                raise RuntimeError("boom")
        assert na.SSDP_KEY not in registry.ATTACK_SCENARIOS

    def test_registering_twice_is_refused(self):
        with na.registered(na.build_scenarios()):
            with pytest.raises(ValueError):
                with na.registered(na.build_scenarios()):
                    pass
        assert len(registry.ATTACK_SCENARIOS) == 20
