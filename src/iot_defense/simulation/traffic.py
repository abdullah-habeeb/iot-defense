"""Synthetic and live traffic generation for the Mininet lab."""

from __future__ import annotations

import time
from typing import Any


def start_multi_connection_listener(host: Any, port: int) -> str:
    """Start a background TCP listener that accepts and discards every
    connection it receives, not just one -- makes a real login/service
    port genuinely reachable for a traffic generator that attempts
    several connections in a row (brute-force), so its connect()+
    sendall() calls actually succeed and actually deliver their payload
    instead of being refused before any data is ever sent.

    Found via a real evaluation: generate_brute_force_mininet_traffic's
    connect() to the sensor's simulated login port was refused every
    time (nothing listens there outside an active DECOY response), so
    sendall() never ran -- a real captured brute-force flow never
    actually contained its documented "USER admin" payload. Invisible to
    this project's own RuleBasedBruteForceDetector (shape-based: rate,
    port, packet count, never payload content), only surfaced when a
    content-matching Suricata signature needed the payload to genuinely
    be there.

    Mirrors ml/generate_dataset.py's own _start_tcp_listener (identical
    disown + heredoc-terminator fixes -- see that function's docstring
    for why both matter on a Mininet host.cmd() channel), extended to
    keep accepting connections in a loop rather than exit after the
    first one.
    """
    script = (
        "import socket\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        f"s.bind(('0.0.0.0', {port}))\n"
        "s.listen(16)\n"
        "while True:\n"
        "    conn, _ = s.accept()\n"
        "    try:\n"
        "        conn.recv(1024)\n"
        "    except OSError:\n"
        "        pass\n"
        "    conn.close()\n"
    )
    log_path = f"/tmp/multi_listener_{port}.log"
    cmd = (
        f"python3 - <<'PY' >{log_path} 2>&1 & disown\n"
        f"{script}\n"
        "PY\n"
        "echo $!"
    )
    pid = host.cmd(cmd).strip()
    # Block until the listener has actually bound, not a fixed guess --
    # traffic sent before that races the listener's own socket.bind()/
    # listen() and is refused exactly like the bug this function fixes.
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        listening = host.cmd(f"ss -ltn 'sport = :{port}' 2>/dev/null")
        if f":{port}" in listening:
            break
        time.sleep(0.05)
    return pid


def stop_multi_connection_listener(host: Any, pid: str) -> None:
    host.cmd(f"kill {pid} 2>/dev/null || true")


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

        A real listener now runs on the target port for the duration of
        this call (see start_multi_connection_listener) -- without it,
        every connect() here was refused before sendall() ever ran, so a
        real captured brute-force flow never actually contained its own
        "USER admin" payload, even though packet-count/rate detection
        (which never needed the payload) was unaffected. Found via a
        Suricata comparison whose content-matching signature needed the
        payload to genuinely be present to fire.

        The 0.8s inter-attempt pause is tuned for *successful* connections,
        not refused ones: a real, listener-accepted connect+send+close
        cycle produces a full TCP handshake and teardown (5-7 packets),
        not just a SYN+immediate-RST pair -- a live run at the old 0.1s
        pause (tuned back when every connection was refused) measured
        packets_per_second around 47, well past RuleBasedDosDetector's own
        floor, misclassifying the run as a flood. 0.8s brings a live run
        back to real margin inside RuleBasedBruteForceDetector's
        [1.0, 15.0] packets_per_second window while keeping packet_count
        (~35-45 over this method's 6s default) comfortably above its
        min_packet_count floor. The connect timeout (0.15s) only matters
        if the listener is ever unreachable, and is kept short for the
        same reason it always was. Entirely confined to the Mininet lab
        and bounded by duration_seconds.
        """
        attacker = net.get("attacker")
        sensor = net.get("sensor")
        target_ip = "10.0.0.10"
        target_port = 2222  # simulated device login/management service
        listener_pid = start_multi_connection_listener(sensor, target_port)
        try:
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
                "    time.sleep(0.8)\n"
                "print('brute_force_done')\n"
                "PY"
            )
            output = attacker.cmd(command)
        finally:
            stop_multi_connection_listener(sensor, listener_pid)
        return {"attacker": attacker.name, "target": target_ip, "output": output}

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

    def generate_exfiltration_mininet_traffic(self, net: Any, duration_seconds: int = 5) -> dict[str, Any]:
        """Generate a bounded data-exfiltration run.

        Direction is reversed from every other attack in this file: the
        compromised device (sensor) is the traffic *source*, sending data
        out to an attacker-controlled sink, not an external attacker
        probing in. The signature is also distinct on every other axis --
        few packets, one destination port, but an unusually large payload
        per packet (~1200 bytes, safely under typical MTU to avoid IP
        fragmentation) -- unlike anything else this system generates,
        where payloads are small heartbeats or empty probe connects.
        Entirely confined to the Mininet lab and bounded by duration_seconds.
        """
        sensor = net.get("sensor")
        attacker_ip = "10.0.0.100"
        exfil_port = 4444
        command = (
            "python3 - <<'PY'\n"
            "import socket, time\n"
            "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "payload = b'x' * 1200\n"
            "start = time.time()\n"
            f"while time.time() - start < {duration_seconds}:\n"
            f"    sock.sendto(payload, ('{attacker_ip}', {exfil_port}))\n"
            "    time.sleep(1.0)\n"
            "sock.close()\n"
            "print('exfiltration_done')\n"
            "PY"
        )
        return {"source": sensor.name, "target": attacker_ip, "output": sensor.cmd(command)}

    def generate_exploit_mininet_traffic(self, net: Any, duration_seconds: int = 4) -> dict[str, Any]:
        """Generate a bounded exploit-payload-injection attempt.

        A small number of real TCP connections (at most 4) against the
        device's management port, each carrying one oversized payload --
        unlike every other attack here, this one's defining signature is
        payload *size*, not packet count or rate: brute-force is many
        small attempts, a flood is a raw high-rate burst, reconnaissance
        spreads across ports. This is the opposite of all three -- one
        port, very few connections, each unusually large, modelling a
        single-shot exploit/injection attempt rather than a sustained
        campaign.

        UDP, not TCP -- a real live run showed why: nothing listens on the
        sensor's management port outside of an active DECOY response, so a
        TCP connect() is refused before sendall() ever runs and only bare
        ~74-byte SYN/RST packets get captured, never the actual payload.
        UDP's sendto() puts the full packet on the wire regardless of
        whether anything is listening, exactly like generate_dos_mininet_
        traffic and generate_exfiltration_mininet_traffic already rely on.
        Entirely confined to the Mininet lab and bounded by
        duration_seconds.
        """
        attacker = net.get("attacker")
        target_ip = "10.0.0.10"
        target_port = 9200
        command = (
            "python3 - <<'PY'\n"
            "import socket, time\n"
            "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "payload = b'A' * 400\n"
            "start = time.time()\n"
            "attempts = 0\n"
            f"while time.time() - start < {duration_seconds} and attempts < 4:\n"
            f"    sock.sendto(payload, ('{target_ip}', {target_port}))\n"
            "    attempts += 1\n"
            "    time.sleep(0.8)\n"
            "sock.close()\n"
            "print('exploit_done')\n"
            "PY"
        )
        return {"attacker": attacker.name, "target": target_ip, "output": attacker.cmd(command)}
