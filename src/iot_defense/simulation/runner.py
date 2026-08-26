"""Real Mininet traffic simulation for the IoT lab foundation."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from iot_defense.agents.decision_agent import DecisionAgent
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
        for record in feature_records:
            threat_events.append(self.detector.detect(record.to_dict()))

        decisions = [self.decision_agent.decide(event) for event in threat_events]
        detections = [event.to_dict() for event in threat_events]
        decision_records = [decision.to_dict() for decision in decisions]

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
        }
        return summary

    def stop(self) -> None:
        """Stop Mininet cleanly."""
        if self.net is not None:
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
