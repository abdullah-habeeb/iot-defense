"""Real Mininet traffic simulation for the IoT lab foundation."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from iot_defense.agents.decision_agent import DecisionAgent
from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.executor import MininetResponseExecutor
from iot_defense.defense.policy import StackelbergDefensePolicy, compare_policies
from iot_defense.detection.detector import RuleBasedReconDetector
from iot_defense.detection.flow_features import FeatureAggregator
from iot_defense.detection.threat_event import ThreatEvent
from iot_defense.network.topology import create_mininet_network
from iot_defense.monitoring.monitor import PacketMonitor
from iot_defense.simulation.traffic import TrafficGenerator


class SimulationRunner:
    """Create a real Mininet lab, generate traffic, capture packets, and evaluate features."""

    def __init__(self, config_path: str | Path | None = None) -> None:
        self.config_path = config_path
        self.net = None
        self.traffic_generator = TrafficGenerator()
        self.packet_monitor = PacketMonitor()
        self.aggregator = FeatureAggregator(window_seconds=3.0)
        self.detector = RuleBasedReconDetector()
        self.decision_agent = DecisionAgent()
        self.stackelberg_policy = StackelbergDefensePolicy()
        self.response_executor: MininetResponseExecutor | None = None

    def create_and_start(self) -> Any:
        """Create and start the Mininet network."""
        self.net = create_mininet_network(self.config_path)
        self.net.start()
        return self.net

    def verify_connectivity(self) -> dict[str, str]:
        """Check basic reachability within the simulated network."""
        sensor = self.net.get("sensor")
        camera = self.net.get("camera")
        smart_plug = self.net.get("smart_plug")
        results = {
            "sensor_to_camera": sensor.cmd("ping -c 2 10.0.0.20"),
            "sensor_to_plug": sensor.cmd("ping -c 2 10.0.0.30"),
            "camera_to_sensor": camera.cmd("ping -c 2 10.0.0.10"),
            "plug_to_camera": smart_plug.cmd("ping -c 2 10.0.0.20"),
        }
        return results

    def run(self) -> dict[str, Any]:
        """Execute the full Mininet simulation pipeline."""
        if self.net is None:
            self.create_and_start()

        connectivity = self.verify_connectivity()
        sensor_capture = self.packet_monitor.capture_host_packets(self.net, "sensor", packet_limit=80, capture_seconds=8)
        normal_traffic = self.traffic_generator.generate_normal_mininet_traffic(self.net)
        time.sleep(1)
        malicious_traffic = self.traffic_generator.generate_malicious_mininet_traffic(self.net, duration_seconds=6)
        time.sleep(1)
        observed_events = self.packet_monitor.read_capture(self.net, "sensor", sensor_capture)
        feature_records = self.aggregator.aggregate(observed_events)

        threat_events: list[ThreatEvent] = []
        policy_comparisons: list[dict[str, Any]] = []
        for record in feature_records:
            event = self.detector.detect(record.to_dict())
            threat_events.append(event)
            context = self.decision_agent.build_context(event)
            policy_comparisons.append(
                compare_policies(
                    context,
                    rule_policy=self.decision_agent.policy,
                    stackelberg_policy=self.stackelberg_policy,
                )
            )

        decisions = [self.decision_agent.decide(event) for event in threat_events]
        detections = [event.to_dict() for event in threat_events]
        decision_records = [decision.to_dict() for decision in decisions]

        self.response_executor = MininetResponseExecutor(self.net)
        response_results = [self.response_executor.execute(decision) for decision in decisions]
        response_records = [result.to_dict() for result in response_results]

        decoy_interaction = None
        if any(decision.action == DefenseAction.DECOY for decision in decisions):
            attacker = self.net.get("attacker")
            decoy_interaction = attacker.cmd(
                "python3 - <<'PY'\n"
                "import socket\n"
                "sock = socket.create_connection(('10.0.0.10', 22), timeout=2)\n"
                "sock.sendall(b'GET /status')\n"
                "print(sock.recv(128).decode(errors='replace').strip())\n"
                "sock.close()\n"
                "PY"
            )

        isolation_event = threat_events[0] if threat_events else self.detector.detect(
            {
                "source_ip": "10.0.0.20",
                "destination_ip": "10.0.0.10",
                "protocol": "ICMP",
                "packet_count": 1,
                "packets_per_second": 0.1,
                "unique_destination_ports": 0,
            }
        )
        isolation_decision = DefenseDecision.create(
            action=DefenseAction.ISOLATE,
            target_ip="10.0.0.10",
            source_ip=isolation_event.source_ip,
            reason="Explicit reversible isolation validation for the simulated sensor.",
            confidence=isolation_event.confidence,
            threat_score=isolation_event.threat_score,
            policy_name="Phase4IsolationValidation",
            context={"validation": "simulated_sensor_isolation"},
        )
        sensor = self.net.get("sensor")
        camera = self.net.get("camera")
        isolation_before = camera.cmd("ping -c 1 -W 1 10.0.0.10")
        isolation_result = self.response_executor.execute(isolation_decision)
        isolation_after = camera.cmd("ping -c 1 -W 1 10.0.0.10")
        restore_details = self.response_executor.restore("10.0.0.10")
        isolation_cleanup = camera.cmd("ping -c 1 -W 1 10.0.0.10")

        normal_detected = next((item for item in detections if item["attack_type"] == "normal"), None)
        suspicious_detected = next((item for item in detections if item["attack_type"] == "reconnaissance_port_scan"), None)
        normal_decision = next(
            (item for item in decision_records if item["context"]["beliefs"]["threat_type"] == "normal"),
            None,
        )
        scan_decision = next(
            (item for item in decision_records if item["context"]["beliefs"]["threat_type"] == "reconnaissance_port_scan"),
            None,
        )

        summary = {
            "hosts": sorted(host.name for host in self.net.hosts),
            "connectivity": connectivity,
            "normal_traffic": normal_traffic,
            "malicious_traffic": malicious_traffic,
            "observed_events": observed_events,
            "feature_records": [record.to_dict() for record in feature_records],
            "threat_events": detections,
            "detections": detections,
            "defense_decisions": decision_records,
            "normal_detection": normal_detected,
            "scan_detection": suspicious_detected,
            "normal_decision": normal_decision,
            "scan_decision": scan_decision,
            "policy_comparisons": policy_comparisons,
            "response_results": response_records,
            "decoy_interaction": decoy_interaction,
            "isolation_validation": {
                "target_host": sensor.name,
                "before": isolation_before,
                "isolation_result": isolation_result.to_dict(),
                "after": isolation_after,
                "restore": restore_details,
                "after_restore": isolation_cleanup,
            },
        }
        return summary

    def stop(self) -> None:
        """Stop Mininet cleanly."""
        if self.net is not None:
            if self.response_executor is not None:
                self.response_executor.cleanup()
                self.response_executor = None
            self.net.stop()
            self.net = None


def main() -> None:
    """Run the live Mininet simulation from the command line."""
    runner = SimulationRunner()
    try:
        result = runner.run()
        print(json.dumps(result, indent=2))
    finally:
        runner.stop()


if __name__ == "__main__":
    main()
