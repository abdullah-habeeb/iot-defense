"""Minimal end-to-end simulation runner for the foundation vertical slice."""

from __future__ import annotations

from typing import Any

from iot_defense.agents.decision_agent import DecisionAgent
from iot_defense.agents.detection_agent import DetectionAgent
from iot_defense.agents.monitoring_agent import MonitoringAgent
from iot_defense.defense.response import ResponseHandler
from iot_defense.detection.features import FeatureExtractor
from iot_defense.observability.logger import StructuredLogger
from iot_defense.observability.metrics import MetricsCollector
from iot_defense.simulation.traffic import TrafficGenerator


class SimulationRunner:
    """Run a simple end-to-end traffic analysis cycle."""

    def __init__(self) -> None:
        self.monitoring_agent = MonitoringAgent()
        self.feature_extractor = FeatureExtractor()
        self.detection_agent = DetectionAgent()
        self.decision_agent = DecisionAgent()
        self.response_handler = ResponseHandler()
        self.logger = StructuredLogger()
        self.metrics = MetricsCollector()
        self.traffic_generator = TrafficGenerator()

    def run_once(self, event: dict[str, Any] | None = None) -> dict[str, Any]:
        """Execute a single observation and response cycle."""
        event = event or self.traffic_generator.generate()["malicious"][0]
        observation = self.monitoring_agent.observe(event)
        features = self.feature_extractor.extract(observation)
        detection = self.detection_agent.analyze(features)
        response_action = self.decision_agent.decide(detection)
        response = self.response_handler.apply(response_action, observation)

        result = {
            "event": observation,
            "features": features,
            "detection": detection,
            "action": response_action,
            "response": response,
            "suspicious": detection.get("suspicious", False),
        }

        self.logger.log(result)
        self.metrics.record(result)
        return result
