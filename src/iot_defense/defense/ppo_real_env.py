"""Live Mininet lab driver: observe real attack traffic, execute a response
for real, and MEASURE what it actually did.

Used by the evaluation harness, the outcome-table builder and the adaptive
evaluation. Despite the historical class name it is not a Gym environment:
PPO trains from the measured outcome table (defense/ppo_env.py), not from
this class.

measure_response() is the measurement protocol. It applies the response,
appends an iptables counter rule AFTER it on the host that receives the
attack flow, replays the same condition's traffic generator against the
now-defended network, and records (1) how many attack packets survived to
that counter, (2) what fraction of legitimate pings from the camera to the
sensor were lost, and (3) whether the response yielded verified
intelligence. Containment is later computed relative to the un-responded
(ALLOW) probe of the same trial -- never from a registered preferred_action.

Why an iptables counter and not a packet capture: tcpdump sees packets
before the firewall acts, so a capture reads zero containment for
BLOCK_SOURCE/THROTTLE/QUARANTINE (all iptables rules). A counter appended
after the response only counts packets no earlier rule dropped; a response
that diverts or stops the flow upstream (ISOLATE, DECOY's NAT redirect,
BANDWIDTH_CAP's egress qdisc) leaves it at zero for the same reason. The
receiving host is the sensor for inbound attacks and the attacker host for
the outbound (exfiltration-style) ones -- see AttackScenario.traffic_direction.

The response is always applied to the canonical pair (protected device =
sensor, adversary = attacker host; for benign traffic, camera -> sensor), never
to whatever IPs the detector's event happens to carry: when detection misses
an attack the event keeps raw flow orientation and a response would land on
the attacker's own host. What a response physically does against an attack
must not depend on whether the detector caught it.

Requires root (Mininet).
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Callable

from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.executor import MininetResponseExecutor
from iot_defense.detection.detector import UnifiedRuleBasedDetector
from iot_defense.detection.flow_features import FeatureAggregator
from iot_defense.detection.threat_event import ThreatEvent
from iot_defense.evaluation.outcome import Measurement
from iot_defense.monitoring.monitor import PacketMonitor
from iot_defense.network.topology import create_mininet_network
from iot_defense.simulation.traffic import TrafficGenerator

TARGET_IP = "10.0.0.10"
ATTACKER_IP = "10.0.0.100"
CAMERA_IP = "10.0.0.20"

LEGIT_PING_COUNT = 5
INVALID_SERVICE_LOSS = -1.0
PROBE_COMMENT = "iot_probe_count"

_PACKET_LOSS_RE = re.compile(r"(\d+(?:\.\d+)?)% packet loss")


class RealMininetDefenseEnv:
    """Live-Mininet lab driver. The network is created once (first
    _ensure_network()) and reused; every response is restored before the
    next one so consecutive measurements never interfere."""

    def __init__(self) -> None:
        self.net: Any = None
        self.executor: MininetResponseExecutor | None = None
        self.traffic_gen = TrafficGenerator()
        self.monitor = PacketMonitor()
        self.aggregator = FeatureAggregator()
        self.detector = UnifiedRuleBasedDetector()
        # Protocol of the dominant attacker flow in the latest observation,
        # taken from the captured traffic itself (not the detector's verdict).
        self.last_attack_protocol: str | None = None

    # ─── Mininet lifecycle ──────────────────────────────────────────────────

    def _ensure_network(self) -> None:
        if self.net is not None:
            return
        self.net = create_mininet_network()
        self.net.start()
        self.executor = MininetResponseExecutor(self.net)

    def close(self) -> None:
        if self.executor is not None:
            try:
                self.executor.cleanup()
            except Exception as exc:  # noqa: BLE001
                print(f"[RealMininetDefenseEnv] executor cleanup error: {exc}")
        if self.net is not None:
            try:
                self.net.stop()
            except Exception as exc:  # noqa: BLE001
                print(f"[RealMininetDefenseEnv] mininet stop error: {exc}")
        self.executor = None
        self.net = None

    # ─── Real observation for one scenario ─────────────────────────────────

    @staticmethod
    def _attack_for(condition: str) -> Any:
        from iot_defense.attacks.registry import ATTACK_SCENARIOS

        attack = next((s for s in ATTACK_SCENARIOS.values() if s.attack_type == condition), None)
        if attack is None:
            raise ValueError(f"No registered attack scenario for condition: {condition!r}")
        return attack

    def _observe_scenario(
        self, scenario: str, traffic_override: Callable[[Any], Any] | None = None
    ) -> ThreatEvent:
        """Generate real traffic for one scenario, capture it, and classify
        it with the same attack-type-agnostic detector the live demo uses.

        traffic_override, when given, replaces the registry's own
        `generate_traffic` call for this one observation (capture sizing
        still comes from the matched attack's own registry entry) -- used
        by evaluation/adaptive.py to send the same attack's traffic from a
        different source per round without duplicating this method's
        capture/aggregate/detect logic.
        """
        if scenario == "normal":
            session = self.monitor.start_capture(self.net, "sensor", 20, watchdog_seconds=63.0)
            (traffic_override or self.traffic_gen.generate_normal_mininet_traffic)(self.net)
            cap_path = self.monitor.stop_capture(self.net, session, 3.0)
        else:
            attack = self._attack_for(scenario)
            session = self.monitor.start_capture(
                self.net, "sensor", attack.capture_packet_limit,
                watchdog_seconds=attack.capture_completion_timeout + 60.0,
            )
            (traffic_override or attack.generate_traffic)(self.net)
            cap_path = self.monitor.stop_capture(self.net, session, attack.capture_completion_timeout)

        try:
            packets = self.monitor.read_capture(self.net, "sensor", cap_path)
        except Exception:  # noqa: BLE001
            # A capture can genuinely come back empty/corrupt under real
            # timing; read_capture() already retries once, so a second
            # failure is a real dry observation, not a transient race. A
            # single bad capture must degrade to "no signal", not crash a
            # multi-hour run.
            packets = []
        flows = self.aggregator.aggregate(packets)
        attacker_flows = [f for f in flows if ATTACKER_IP in (f.source_ip, f.destination_ip)]
        self.last_attack_protocol = (
            max(attacker_flows, key=lambda f: f.packet_count).protocol if attacker_flows else None
        )
        if flows:
            return self.detector.detect_flows(flows)
        return self.detector.detect(
            {"source_ip": ATTACKER_IP, "destination_ip": TARGET_IP,
             "unique_destination_ports": 0, "packet_count": 0, "packets_per_second": 0.0}
        )

    # ─── Real action execution + verification ──────────────────────────────

    def _execute_and_verify(
        self,
        action: DefenseAction,
        threat_event: ThreatEvent,
        probe: Callable[[], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Perform the chosen action for real and verify its mechanism. When
        `probe` is given it runs while the response is still active (before
        restore) and its result is returned under outcome["probe"]; a probe
        failure is recorded under outcome["probe_error"], never raised, so
        restore() always runs."""
        decision = DefenseDecision.create(
            action=action,
            target_ip=threat_event.destination_ip if threat_event.destination_ip != "unknown" else TARGET_IP,
            source_ip=threat_event.source_ip if threat_event.source_ip != "unknown" else ATTACKER_IP,
            reason="live-Mininet response measurement",
            confidence=threat_event.confidence,
            threat_score=threat_event.threat_score,
            policy_name="RealMininetDefenseEnv",
            # The executor's THROTTLE branch reads the real detected
            # protocol from this context to pick a protocol-aware rule;
            # an empty context silently falls back to TCP and installs a
            # rule that can never match ICMP traffic.
            context={"beliefs": {"observed_features": {"protocol": threat_event.features.get("protocol", "TCP")}}},
        )
        result = self.executor.execute(decision)
        outcome: dict[str, Any] = {"status": result.status}

        if action == DefenseAction.ISOLATE and result.status == "success":
            camera = self.net.get("camera")
            after = camera.cmd(f"ping -c 1 -W 1 {decision.target_ip}")
            outcome["connectivity_lost"] = "100% packet loss" in after
        elif action == DefenseAction.DECOY and result.status == "success":
            try:
                attacker = self.net.get("attacker")
                decoy_ports = result.details.get("decoy_ports") or [22]
                probe_output = attacker.cmd(
                    "python3 - <<'PY'\n"
                    "import socket\n"
                    "try:\n"
                    f"    sock = socket.create_connection(('{decision.target_ip}', {decoy_ports[0]}), timeout=2)\n"
                    "    sock.sendall(b'GET /status')\n"
                    "    print('INTERACTION_OK:' + sock.recv(128).decode(errors='replace').strip())\n"
                    "    sock.close()\n"
                    "except Exception as exc:\n"
                    "    print(f'INTERACTION_FAILED:{exc}')\n"
                    "PY"
                ).strip()
                outcome["interaction_verified"] = "INTERACTION_OK" in probe_output
            except Exception:  # noqa: BLE001
                outcome["interaction_verified"] = False
        elif action == DefenseAction.THROTTLE and result.status == "success":
            try:
                target_host = self.executor._host_for_ip(decision.target_ip)
                rule_check = target_host.cmd(f"iptables -L INPUT -n | grep -c {decision.target_ip}")
                outcome["rule_installed"] = rule_check.strip() not in ("", "0")
            except Exception:  # noqa: BLE001
                outcome["rule_installed"] = False
        elif action == DefenseAction.FORENSIC_CAPTURE:
            # forensic_capture() raises (status "failed") unless real
            # captured bytes exist, so success IS the verification.
            outcome["evidence_captured"] = result.status == "success"

        if probe is not None:
            try:
                outcome["probe"] = probe()
            except Exception as exc:  # noqa: BLE001
                outcome["probe_error"] = f"{type(exc).__name__}: {exc}"

        try:
            self.executor.restore(decision.target_ip)
        except Exception:  # noqa: BLE001
            pass
        return outcome

    # ─── Measurement protocol ───────────────────────────────────────────────

    def _legit_service_loss(self) -> float:
        camera = self.net.get("camera")
        output = camera.cmd(f"ping -c {LEGIT_PING_COUNT} -i 0.2 -W 1 {TARGET_IP}")
        match = _PACKET_LOSS_RE.search(output)
        if match is not None:
            return float(match.group(1)) / 100.0
        if "network is unreachable" in output.lower():
            # The pinging host itself has no usable interface (e.g. the
            # response isolated it): no packet can leave, i.e. total loss.
            return 1.0
        raise RuntimeError(f"could not parse legitimate-service ping output: {output!r}")

    def _flow_endpoints(self, condition: str) -> tuple[Any, tuple[str, ...]] | None:
        """(receiving host, sender IPs) of the condition's attack flow, or None
        for benign traffic. Inbound attacks are received by the sensor;
        outbound (exfiltration-style) ones by the attacker-controlled host. A
        distributed attack lists every address its sender uses."""
        if condition == "normal":
            return None
        attack = self._attack_for(condition)
        if attack.traffic_direction == "outbound":
            return self.net.get("attacker"), (TARGET_IP,)
        return self.net.get("sensor"), tuple(attack.sender_ips) or (ATTACKER_IP,)

    @staticmethod
    def _counter_rule(op: str, senders: tuple[str, ...]) -> str:
        return f"iptables -{op} INPUT -s {','.join(senders)} -m comment --comment {PROBE_COMMENT} -j ACCEPT"

    def _clear_counter(self, receiver: Any, senders: tuple[str, ...]) -> None:
        for _ in range(5):
            if receiver.cmd(self._counter_rule("D", senders)).strip():  # iptables prints only on error: none left
                return

    @staticmethod
    def _read_counter(receiver: Any) -> int:
        """Total packets over every probe counter rule: iptables expands a
        comma-separated `-s` list into one rule (and one counter) per source."""
        counts = [
            int(line.split()[0])
            for line in receiver.cmd("iptables -nvxL INPUT").splitlines()
            if PROBE_COMMENT in line
        ]
        if not counts:
            raise RuntimeError("probe counter rule not found in iptables INPUT")
        return sum(counts)

    def _canonical_event(self, condition: str, observed: ThreatEvent) -> ThreatEvent:
        """The event a response is applied for: protected device as target,
        adversary (or, for benign traffic, the camera peer) as source, and
        the protocol seen in the captured traffic."""
        features = dict(observed.features)
        if condition == "normal":
            source_ip = CAMERA_IP
        else:
            source_ip = ATTACKER_IP
            features["protocol"] = self.last_attack_protocol or features.get("protocol", "TCP")
        return ThreatEvent.from_result(
            source_ip=source_ip, destination_ip=TARGET_IP, attack_type=condition,
            threat_score=observed.threat_score, confidence=observed.confidence,
            detection_reason="canonical response target for measurement",
            features=features, detector_name="canonical",
        )

    def _decoy_hits_since(self, started_at: float) -> int:
        """Connections from the attacker that the decoy logged at or after
        `started_at` -- i.e. the attack's own replayed traffic, not the
        executor's earlier verification connection."""
        path = self.executor.decoy.log_path
        if not path.exists():
            return 0
        hits = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if record.get("source_ip") == ATTACKER_IP and record.get("timestamp", 0.0) >= started_at:
                hits += 1
        return hits

    def measure_response(
        self, action: DefenseAction, threat_event: ThreatEvent, condition: str
    ) -> tuple[Measurement, dict[str, Any]]:
        """Apply `action` (to the canonical pair, see module docstring), then
        measure how much of the attack flow survives to the receiving host's
        firewall counter and how much legitimate service survives.

        The returned Measurement's baseline_packets is only meaningful for
        ALLOW (its own residual). For every other action it is 0, which
        Measurement.valid rejects for attacks until the caller supplies the
        trial's un-responded baseline via outcome.with_baseline() -- so a
        forgotten baseline can never score as containment.

        A probe that could not be read (counter rule not installed or found,
        unparsable ping output, generator failure) yields service_loss = -1.0,
        which Measurement.valid rejects."""
        event = self._canonical_event(condition, threat_event)

        def probe() -> dict[str, Any]:
            endpoints = self._flow_endpoints(condition)
            residual = 0
            decoy_hits = 0
            if endpoints is None:
                self.traffic_gen.generate_normal_mininet_traffic(self.net)
            else:
                receiver, senders = endpoints
                self._clear_counter(receiver, senders)  # a leaked rule from a crashed probe would be read first
                installed = receiver.cmd(self._counter_rule("A", senders)).strip()
                if "iptables" in installed.lower():
                    raise RuntimeError(f"could not install probe counter: {installed}")
                started_at = time.time()
                try:
                    self._attack_for(condition).generate_traffic(self.net)
                    residual = self._read_counter(receiver)
                    if action == DefenseAction.DECOY:
                        time.sleep(0.3)  # the decoy logs after it accepts
                        decoy_hits = self._decoy_hits_since(started_at)
                finally:
                    self._clear_counter(receiver, senders)
            return {"residual_packets": residual, "service_loss": self._legit_service_loss(), "decoy_hits": decoy_hits}

        outcome = self._execute_and_verify(action, event, probe=probe)
        probed = outcome.pop("probe", None)
        residual = probed["residual_packets"] if probed else 0
        measurement = Measurement(
            condition=condition,
            action=action,
            status=outcome["status"],
            baseline_packets=residual if action == DefenseAction.ALLOW else 0,
            residual_packets=residual,
            service_loss=probed["service_loss"] if probed else INVALID_SERVICE_LOSS,
            intel_verified=bool((probed and probed["decoy_hits"] > 0) or outcome.get("evidence_captured")),
        )
        return measurement, outcome
