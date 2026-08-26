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
        results["smart_plug_heartbeat"] = plug.cmd("python3 - <<'PY'\nimport socket\nfor host, port in [('10.0.0.20', 80), ('10.0.0.10', 8080)]:\n    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n    s.settimeout(1)\n    try:\n        s.connect((host, port))\n    except OSError:\n        pass\n    finally:\n        s.close()\nprint('tcp_heartbeat_done')\nPY")
        return results

    def generate_malicious_mininet_traffic(self, net: Any, duration_seconds: int = 6) -> dict[str, Any]:
        """Generate a bounded TCP port-scan attack over the simulated IoT network."""
        attacker = net.get("attacker")
        target_ip = "10.0.0.10"
        command = f"python3 - <<'PY'\nimport socket, time\nstart = time.time()\nports = [22, 80, 8080, 443]\nwhile time.time() - start < {duration_seconds}:\n    for port in ports:\n        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n        s.settimeout(0.25)\n        try:\n            s.connect(('10.0.0.10', port))\n        except OSError:\n            pass\n        finally:\n            s.close()\n    time.sleep(0.1)\nprint('attack_done')\nPY"
        return {"attacker": attacker.name, "target": target_ip, "output": attacker.cmd(command)}
