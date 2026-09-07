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


class RuleBasedDosDetector(Detector):
    """A simple detector for denial-of-service / flood behavior.

    Distinguishes a flood from a port scan by the opposite feature profile:
    a flood hits very few distinct destination ports (often just one) at a
    very high packet rate, whereas a scan spreads a moderate rate across
    many ports.
    """

    def __init__(self, min_packets_per_second: float | None = None, max_unique_ports: int | None = None, min_packet_count: int | None = None) -> None:
        config = _load_detection_policy()
        self.min_packets_per_second = float(config.get("dos_min_packets_per_second", min_packets_per_second if min_packets_per_second is not None else 20.0))
        self.max_unique_ports = int(config.get("dos_max_unique_destination_ports", max_unique_ports if max_unique_ports is not None else 2))
        self.min_packet_count = int(config.get("dos_min_packet_count", min_packet_count if min_packet_count is not None else 20))

    def detect(self, features: dict[str, Any]) -> ThreatEvent:
        unique_ports = int(features.get("unique_destination_ports", 0))
        packet_count = int(features.get("packet_count", 0))
        packets_per_second = float(features.get("packets_per_second", 0.0))

        is_threat = (
            packets_per_second >= self.min_packets_per_second
            and unique_ports <= self.max_unique_ports
            and packet_count >= self.min_packet_count
        )

        if is_threat:
            attack_type = "dos_flood"
            threat_score = 0.92
            confidence = 0.9
            reason = "very high packet rate concentrated on very few destination ports"
        else:
            attack_type = "normal"
            threat_score = 0.05
            confidence = 0.9
            reason = "traffic pattern does not meet flood criteria"

        return ThreatEvent.from_result(
            source_ip=str(features.get("source_ip", "unknown")),
            destination_ip=str(features.get("destination_ip", "unknown")),
            attack_type=attack_type,
            threat_score=threat_score,
            confidence=confidence,
            detection_reason=reason,
            features=features,
            detector_name="RuleBasedDosDetector",
        )


class UnifiedRuleBasedDetector(Detector):
    """Classify captured flow features without being told which attack (if
    any) is actually happening.

    Each registered attack's rule-based detector is given a deliberately
    non-overlapping signature (a flood needs very high rate and very few
    ports; a scan needs many ports at a moderate rate), so every detector
    can safely run against every capture and at most one should ever fire.
    This is the detector the live demo controller actually calls,
    regardless of which attack scenario the operator selected -- the
    operator's choice only controls which traffic gets generated, never
    which detector gets consulted.

    By default this runs one detector per entry in
    iot_defense.attacks.registry.ATTACK_SCENARIOS, in registry order --
    adding a new attack there is enough to make it recognized here too,
    with no code change in this class.
    """

    def __init__(self, detectors: dict[str, Detector] | None = None) -> None:
        if detectors is None:
            # Imported here, not at module level, to avoid a circular
            # import: the registry itself imports this module to build its
            # detector factories.
            from iot_defense.attacks.registry import ATTACK_SCENARIOS

            detectors = {key: scenario.build_detector() for key, scenario in ATTACK_SCENARIOS.items()}
        self.detectors = detectors

    def detect(self, features: dict[str, Any]) -> ThreatEvent:
        fallback_normal_event: ThreatEvent | None = None
        for detector in self.detectors.values():
            event = detector.detect(features)
            if event.attack_type != "normal":
                return event
            fallback_normal_event = fallback_normal_event or event

        if fallback_normal_event is None:
            raise ValueError("UnifiedRuleBasedDetector requires at least one detector")
        return fallback_normal_event  # every rule set agrees: normal traffic
