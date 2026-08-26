"""Detector contract and baseline rule-based implementation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import yaml

from iot_defense.detection.threat_event import ThreatEvent


def _load_detection_policy() -> dict[str, Any]:
    config_path = Path(__file__).resolve().parents[2] / "config" / "policies.yaml"
    if not config_path.exists():
        return {}
    with config_path.open("r", encoding="utf-8") as fh:
        loaded = yaml.safe_load(fh) or {}
    return loaded.get("policy", {}).get("detection", {})


class Detector(ABC):
    """Abstract detector interface for traffic assessment."""

    @abstractmethod
    def detect(self, features: dict[str, Any]) -> ThreatEvent:
        """Accept a feature record and return a structured threat event."""


class RuleBasedReconDetector(Detector):
    """A simple detector for reconnaissance / port-scanning behavior."""

    def __init__(self, min_unique_ports: int | None = None, min_packet_count: int | None = None, min_packets_per_second: float | None = None) -> None:
        config = _load_detection_policy()
        self.min_unique_ports = int(config.get("min_unique_destination_ports", min_unique_ports if min_unique_ports is not None else 4))
        self.min_packet_count = int(config.get("min_packet_count", min_packet_count if min_packet_count is not None else 5))
        self.min_packets_per_second = float(config.get("min_packets_per_second", min_packets_per_second if min_packets_per_second is not None else 0.5))

    def detect(self, features: dict[str, Any]) -> ThreatEvent:
        unique_ports = int(features.get("unique_destination_ports", 0))
        packet_count = int(features.get("packet_count", 0))
        packets_per_second = float(features.get("packets_per_second", 0.0))

        is_threat = (
            unique_ports >= self.min_unique_ports
            and packet_count >= self.min_packet_count
            and packets_per_second >= self.min_packets_per_second
        )

        if is_threat:
            attack_type = "reconnaissance_port_scan"
            threat_score = 0.9
            confidence = 0.88
            reason = "high unique destination port count and elevated packet rate"
        else:
            attack_type = "normal"
            threat_score = 0.05
            confidence = 0.9
            reason = "traffic pattern does not meet scan criteria"

        return ThreatEvent.from_result(
            source_ip=str(features.get("source_ip", "unknown")),
            destination_ip=str(features.get("destination_ip", "unknown")),
            attack_type=attack_type,
            threat_score=threat_score,
            confidence=confidence,
            detection_reason=reason,
            features=features,
            detector_name="RuleBasedReconDetector",
        )
