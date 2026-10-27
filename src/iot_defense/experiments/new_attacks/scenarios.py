"""The two new attacks of the pre-registered Stackelberg transfer experiment.

Neither attack is added to the real registry (attacks/registry.py). Adding one there would resize PPO's observation vector,
invalidate the trained model and change every count the 20-attack benchmark and its tests depend on. They are registered only
inside the experiment's own process, through `registered()`, for as long as a measurement or an analysis runs.

The traffic generators below are frozen with the pre-registration (their source file is hashed in FREEZE.json), so the attacks
cannot be changed after the priors are written. Both are bounded, run only between Mininet hosts, and imitate the traffic
shape of a real attack:

* `ssdp_reflection`: unsolicited SSDP/UPnP search responses (UDP, source port 1900, about 340 bytes) arriving at the protected
  sensor, the shape a victim of an SSDP reflection-amplification attack sees. Inbound.
* `telnet_scan_outbound`: the protected sensor, assumed compromised, opens many short TCP connections to ports 23 and 2323 of
  another host, the shape of Mirai-style Telnet scanning. Outbound (the traffic leaves the device).

Neither has a rule-based detector of its own: the policy comparison uses the true attack label, as the table-graded evaluation of
the 20 known attacks does. Detection of the new attacks is outside this experiment.
"""

from __future__ import annotations

import contextlib
import re
from typing import Any, Iterator

from iot_defense.detection.detector import Detector
from iot_defense.detection.threat_event import ThreatEvent

SSDP_KEY = "ssdp_reflection"
TELNET_KEY = "telnet_scan_outbound"
NEW_ATTACK_KEYS = (SSDP_KEY, TELNET_KEY)

SSDP_DURATION_SECONDS = 9
SSDP_MAX_PACKETS = 60
SSDP_PAYLOAD_BYTES = 340
SSDP_SOURCE_PORT = 1900
SSDP_VICTIM_PORT = 53000
TELNET_DURATION_SECONDS = 6
TELNET_PORTS = (23, 2323)

ATTACKER_IP = "10.0.0.100"
SENSOR_IP = "10.0.0.10"

# Remote scripts run inside a Mininet host through `host.cmd("python3 - <<'PY' ...")`. The placeholders are replaced by plain
# string substitution (no str.format, so the braces in the script are never interpreted).
SSDP_SCRIPT = r'''
import socket, time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("__SRC_IP__", __SRC_PORT__))
payload = (
    "HTTP/1.1 200 OK\r\n"
    "CACHE-CONTROL: max-age=1800\r\n"
    "EXT:\r\n"
    "LOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n"
    "SERVER: Linux/3.10 UPnP/1.0 MiniUPnPd/2.1\r\n"
    "ST: upnp:rootdevice\r\n"
    "USN: uuid:3f0c2b7e-0000-4000-8000-000000000001::upnp:rootdevice\r\n"
    "\r\n"
).encode().ljust(__PAYLOAD_BYTES__, b" ")
start = time.time()
sent = 0
while time.time() - start < __DURATION__ and sent < __MAX_PACKETS__:
    sock.sendto(payload, ("__DST_IP__", __DST_PORT__))
    sent += 1
    time.sleep(0.12)
sock.close()
print("ssdp_reflection_done", sent)
'''

TELNET_SCRIPT = r'''
import socket, time
ports = (__PORT_A__, __PORT_B__)
start = time.time()
attempts = 0
while time.time() - start < __DURATION__:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.25)
    try:
        s.connect(("__DST_IP__", ports[attempts % 2]))
    except OSError:
        pass
    finally:
        s.close()
    attempts += 1
    time.sleep(0.06)
print("telnet_scan_done", attempts)
'''


def render(template: str, **values: object) -> str:
    """Substitute __NAME__ placeholders; refuses to leave one behind."""
    text = template
    for name, value in values.items():
        text = text.replace(f"__{name}__", str(value))
    leftover = re.findall(r"__[A-Z][A-Z_]*__", text)
    if leftover:
        raise ValueError(f"unfilled placeholders: {sorted(set(leftover))}")
    return text


def ssdp_script(*, src_ip: str = ATTACKER_IP, dst_ip: str = SENSOR_IP, duration: float = SSDP_DURATION_SECONDS,
                dst_port: int = SSDP_VICTIM_PORT) -> str:
    return render(SSDP_SCRIPT, SRC_IP=src_ip, SRC_PORT=SSDP_SOURCE_PORT, DST_IP=dst_ip, DST_PORT=dst_port,
                  DURATION=duration, MAX_PACKETS=SSDP_MAX_PACKETS, PAYLOAD_BYTES=SSDP_PAYLOAD_BYTES)


def telnet_script(*, dst_ip: str = ATTACKER_IP, duration: float = TELNET_DURATION_SECONDS,
                  ports: tuple[int, int] = TELNET_PORTS) -> str:
    return render(TELNET_SCRIPT, DST_IP=dst_ip, DURATION=duration, PORT_A=ports[0], PORT_B=ports[1])


def _run_on(net: Any, host: str, script: str, done_marker: str) -> dict[str, Any]:
    node = net.get(host)
    command = "python3 - <<'PY'\n" + script.strip("\n") + "\nPY"
    output = node.cmd(command)
    return {"host": node.name, "output": output, "completed": done_marker in output}


def generate_ssdp_reflection(net: Any) -> dict[str, Any]:
    return _run_on(net, "attacker", ssdp_script(), "ssdp_reflection_done")


def generate_telnet_scan_outbound(net: Any) -> dict[str, Any]:
    return _run_on(net, "sensor", telnet_script(), "telnet_scan_done")


class PassiveDetector(Detector):
    """Never flags anything. The new attacks have no detector: the experiment grades policies on the true label."""

    def detect(self, features: dict[str, Any]) -> ThreatEvent:
        return ThreatEvent.from_result(
            source_ip=str(features.get("source_ip", "unknown")),
            destination_ip=str(features.get("destination_ip", "unknown")),
            attack_type="normal",
            threat_score=0.05,
            confidence=0.9,
            detection_reason="no rule-based detector exists for the experiment's new attacks",
            features=features,
            detector_name="PassiveDetector",
        )


def build_scenarios(playbook: dict[str, Any] | None = None) -> dict[str, Any]:
    """The two AttackScenario objects. `playbook` maps attack key -> DefenseAction (the rule-based arm's pre-registered
    response); measurement does not use it, so it defaults to ALERT for the pre-freeze smoke test."""
    from iot_defense.attacks.registry import AttackScenario
    from iot_defense.defense.decision import DefenseAction

    playbook = playbook or {}
    return {
        SSDP_KEY: AttackScenario(
            key=SSDP_KEY,
            label="SSDP/UPnP reflection amplification",
            attack_type=SSDP_KEY,
            observed_threat_key="SSDP_REFLECTION",
            build_detector=PassiveDetector,
            generate_traffic=generate_ssdp_reflection,
            capture_packet_limit=200,
            capture_duration_seconds=float(SSDP_DURATION_SECONDS),
            capture_completion_timeout=11.0,
            preferred_action=playbook.get(SSDP_KEY, DefenseAction.ALERT),
            action_score_min=0.7,
            action_confidence_min=0.7,
            intention="contain_malicious_activity",
            ppo_example_features={"packets_per_second": 7.0, "unique_destination_ports": 1},
            ppo_threat_score=0.87,
            ppo_confidence=0.82,
            traffic_direction="inbound",
        ),
        TELNET_KEY: AttackScenario(
            key=TELNET_KEY,
            label="Outbound Telnet scanning (compromised device)",
            attack_type=TELNET_KEY,
            observed_threat_key="TELNET_SCAN_OUTBOUND",
            build_detector=PassiveDetector,
            generate_traffic=generate_telnet_scan_outbound,
            capture_packet_limit=150,
            capture_duration_seconds=float(TELNET_DURATION_SECONDS),
            capture_completion_timeout=8.0,
            preferred_action=playbook.get(TELNET_KEY, DefenseAction.ALERT),
            action_score_min=0.7,
            action_confidence_min=0.7,
            intention="contain_malicious_activity",
            ppo_example_features={"packets_per_second": 15.0, "unique_destination_ports": 2},
            ppo_threat_score=0.88,
            ppo_confidence=0.84,
            traffic_direction="outbound",
        ),
    }


@contextlib.contextmanager
def registered(scenarios: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Add the scenarios to the live registry for the duration of the block and remove them afterwards, so nothing else in
    the process (or any test) ever sees a 22-attack registry."""
    from iot_defense.attacks import registry

    clash = sorted(key for key in scenarios if key in registry.ATTACK_SCENARIOS)
    if clash:
        raise ValueError(f"already registered: {clash}")
    registry.ATTACK_SCENARIOS.update(scenarios)
    try:
        yield scenarios
    finally:
        for key in scenarios:
            registry.ATTACK_SCENARIOS.pop(key, None)
