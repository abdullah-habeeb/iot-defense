"""Real Mininet traffic simulation for the IoT lab foundation."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from iot_defense.network.topology import create_mininet_network
from iot_defense.monitoring.monitor import PacketMonitor
from iot_defense.simulation.traffic import TrafficGenerator


class SimulationRunner:
    """Create a real Mininet lab, generate traffic, and capture packet events."""

    def __init__(self, config_path: str | Path | None = None) -> None:
        self.config_path = config_path
        self.net = None
        self.traffic_generator = TrafficGenerator()
        self.packet_monitor = PacketMonitor()

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
        normal_traffic = self.traffic_generator.generate_normal_mininet_traffic(self.net)

        sensor_capture = self.packet_monitor.capture_host_packets(self.net, "sensor", packet_limit=25, capture_seconds=8)
        time.sleep(1)
        malicious_traffic = self.traffic_generator.generate_malicious_mininet_traffic(self.net, duration_seconds=6)
        time.sleep(1)
        observed_events = self.packet_monitor.read_capture(self.net, "sensor", sensor_capture)

        summary = {
            "hosts": sorted(host.name for host in self.net.hosts),
            "connectivity": connectivity,
            "normal_traffic": normal_traffic,
            "malicious_traffic": malicious_traffic,
            "observed_events": observed_events,
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
