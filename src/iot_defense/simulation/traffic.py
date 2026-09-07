"""Synthetic and live traffic generation for the Mininet lab."""

from __future__ import annotations

import time
from typing import Any


class TrafficGenerator:
    """Generate a small set of benign and malicious traffic events for testing."""

    def __init__(self) -> None:
        self._normal_event = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.3",
            "protocol": "TCP",
            "packet_length": 140,
            "ttl": 64,
            "src_port": 5000,
            "dst_port": 80,
            "timestamp": 1.0,
            "direction": "outbound",
        }

        self._malicious_event = {
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.2",
            "protocol": "ICMP",
            "packet_length": 2500,
            "ttl": 32,
            "src_port": 0,
            "dst_port": 22,
            "timestamp": 2.0,
            "direction": "inbound",
        }

    def generate(self) -> dict[str, list[dict[str, Any]]]:
        """Return a batch of normal and malicious traffic events."""
        return {
            "normal": [self._normal_event],
            "malicious": [self._malicious_event],
        }

    def generate_normal_mininet_traffic(self, net: Any) -> dict[str, Any]:
        """Create real, bounded normal traffic inside the Mininet network."""
        sensor = net.get("sensor")
        camera = net.get("camera")
        plug = net.get("smart_plug")

        results: dict[str, Any] = {}
        results["sensor_to_camera"] = sensor.cmd("ping -c 2 10.0.0.20")
        results["sensor_to_plug"] = sensor.cmd("ping -c 2 10.0.0.30")
        results["camera_to_sensor"] = camera.cmd("ping -c 2 10.0.0.10")
        results["plug_udp_heartbeat"] = plug.cmd(
            "python3 - <<'PY'\n"
            "import socket\n"
            "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "for _ in range(5):\n"
            "    sock.sendto(b'iot-heartbeat', ('10.0.0.10', 5683))\n"
            "sock.close()\n"
            "print('udp_heartbeat_done')\n"
            "PY"
        )
        results["smart_plug_heartbeat"] = plug.cmd("python3 - <<'PY'\nimport socket\nfor host, port in [('10.0.0.20', 80), ('10.0.0.10', 8080)]:\n    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n    s.settimeout(1)\n    try:\n        s.connect((host, port))\n    except OSError:\n        pass\n    finally:\n        s.close()\nprint('tcp_heartbeat_done')\nPY")
        return results

    def generate_malicious_mininet_traffic(self, net: Any, duration_seconds: int = 6) -> dict[str, Any]:
        """Generate a bounded TCP port-scan attack over the simulated IoT network."""
        attacker = net.get("attacker")
        target_ip = "10.0.0.10"
        command = f"python3 - <<'PY'\nimport socket, time\nstart = time.time()\nports = [22, 80, 8080, 443]\nwhile time.time() - start < {duration_seconds}:\n    for port in ports:\n        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n        s.settimeout(0.25)\n        try:\n            s.connect(('10.0.0.10', port))\n        except OSError:\n            pass\n        finally:\n            s.close()\n    time.sleep(0.1)\nprint('attack_done')\nPY"
        return {"attacker": attacker.name, "target": target_ip, "output": attacker.cmd(command)}

    def generate_brute_force_mininet_traffic(self, net: Any, duration_seconds: int = 6) -> dict[str, Any]:
        """Generate a bounded credential-stuffing / brute-force attack.

        Repeated real TCP connect attempts against a single fixed "login"
        port -- unlike the port-scan above (many destination ports at a
        moderate rate) and unlike the flood below (one port at a raw,
        undifferentiated packet-rate burst), this holds to one port *and*
        a moderate, sustained connect-attempt rate: each attempt is a real
        connect/close cycle with a pause in between, not a tight loop, so
        the resulting packets_per_second stays well under the flood
        detector's threshold even though total packet_count over the
        window is much higher than a brief reconnaissance probe.

        The connect timeout (0.15s) and inter-attempt pause (0.1s) are
        deliberately short: a live run measured a real, unloaded RST
        turnaround close to the *worst case* timeout when this used a 0.3s
        timeout + 0.3s pause, which produced barely enough packets to clear
        RuleBasedBruteForceDetector's min_packet_count and misclassified
        the run as normal. These tighter values give real margin above
        that threshold even under similar latency. Entirely confined to
        the Mininet lab and bounded by duration_seconds.
        """
        attacker = net.get("attacker")
        target_ip = "10.0.0.10"
        target_port = 2222  # simulated device login/management service
        command = (
            "python3 - <<'PY'\n"
            "import socket, time\n"
            "start = time.time()\n"
            f"while time.time() - start < {duration_seconds}:\n"
            "    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "    sock.settimeout(0.15)\n"
            "    try:\n"
            f"        sock.connect(('{target_ip}', {target_port}))\n"
            "        sock.sendall(b'USER admin\\r\\nPASS wrong\\r\\n')\n"
            "    except OSError:\n"
            "        pass\n"
            "    finally:\n"
            "        sock.close()\n"
            "    time.sleep(0.1)\n"
            "print('brute_force_done')\n"
            "PY"
        )
        return {"attacker": attacker.name, "target": target_ip, "output": attacker.cmd(command)}

    def generate_dos_mininet_traffic(self, net: Any, duration_seconds: int = 5) -> dict[str, Any]:
        """Generate a bounded UDP flood attack over the simulated IoT network.

        Unlike the port-scan attack above (many destination ports, moderate
        rate), this sends a tight-loop burst of UDP packets to a single fixed
        port for the whole window -- the signature detectors use to tell a
        flood from reconnaissance is high packets_per_second combined with
        low unique_destination_ports, the opposite profile of a port scan.
        Entirely confined to the Mininet lab and bounded by duration_seconds.
        """
        attacker = net.get("attacker")
        target_ip = "10.0.0.10"
        target_port = 5683
        command = (
            "python3 - <<'PY'\n"
            "import socket, time\n"
            "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "payload = b'x' * 64\n"
            "start = time.time()\n"
            f"while time.time() - start < {duration_seconds}:\n"
            f"    sock.sendto(payload, ('{target_ip}', {target_port}))\n"
            "sock.close()\n"
            "print('dos_flood_done')\n"
            "PY"
        )
        return {"attacker": attacker.name, "target": target_ip, "output": attacker.cmd(command)}
