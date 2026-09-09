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


class RuleBasedBruteForceDetector(Detector):
    """A simple detector for credential-stuffing / brute-force behavior.

    Sits between a scan and a flood on every axis: like a flood, traffic
    concentrates on very few destination ports (repeated attempts against
    one login service); unlike a flood, the rate is bounded to a moderate,
    sustained band rather than a raw packet-rate burst, and the total
    packet_count is much higher than a brief reconnaissance probe. The
    upper rate bound is what keeps a real brute-force run from ever also
    tripping RuleBasedDosDetector's much higher rate threshold.

    max_average_packet_size exists specifically to keep this detector out
    of RuleBasedExfiltrationDetector's territory: both restrict
    unique_destination_ports to a single port, and their packet_count
    windows overlap ([12, inf) vs [3, 25]), so without an upper bound on
    payload size, a real exfiltration flow whose packet_count happened to
    land in that overlap would be silently misclassified as brute-force --
    this detector runs first in registry order, so it would win regardless
    of exfiltration's much larger payloads. A real login attempt's payload
    is tens of bytes; exfiltration's is 1200+; 200 sits with real margin on
    both sides of that gap.
    """

    def __init__(
        self,
        max_unique_ports: int | None = None,
        min_packet_count: int | None = None,
        min_packets_per_second: float | None = None,
        max_packets_per_second: float | None = None,
        max_average_packet_size: float | None = None,
    ) -> None:
        config = _load_detection_policy()
        self.max_unique_ports = int(
            config.get("brute_force_max_unique_destination_ports", max_unique_ports if max_unique_ports is not None else 2)
        )
        self.min_packet_count = int(
            config.get("brute_force_min_packet_count", min_packet_count if min_packet_count is not None else 12)
        )
        self.min_packets_per_second = float(
            config.get("brute_force_min_packets_per_second", min_packets_per_second if min_packets_per_second is not None else 1.0)
        )
        self.max_packets_per_second = float(
            config.get("brute_force_max_packets_per_second", max_packets_per_second if max_packets_per_second is not None else 15.0)
        )
        self.max_average_packet_size = float(
            config.get("brute_force_max_average_packet_size", max_average_packet_size if max_average_packet_size is not None else 200.0)
        )

    def detect(self, features: dict[str, Any]) -> ThreatEvent:
        unique_ports = int(features.get("unique_destination_ports", 0))
        packet_count = int(features.get("packet_count", 0))
        packets_per_second = float(features.get("packets_per_second", 0.0))
        average_packet_size = float(features.get("average_packet_size", 0.0))

        is_threat = (
            unique_ports <= self.max_unique_ports
            and packet_count >= self.min_packet_count
            and self.min_packets_per_second <= packets_per_second <= self.max_packets_per_second
            and average_packet_size <= self.max_average_packet_size
        )

        if is_threat:
            attack_type = "brute_force"
            threat_score = 0.75
            confidence = 0.75
            reason = "many repeated connection attempts concentrated on a single service port"
        else:
            attack_type = "normal"
            threat_score = 0.05
            confidence = 0.9
            reason = "traffic pattern does not meet brute-force criteria"

        return ThreatEvent.from_result(
            source_ip=str(features.get("source_ip", "unknown")),
            destination_ip=str(features.get("destination_ip", "unknown")),
            attack_type=attack_type,
            threat_score=threat_score,
            confidence=confidence,
            detection_reason=reason,
            features=features,
            detector_name="RuleBasedBruteForceDetector",
        )


class RuleBasedExfiltrationDetector(Detector):
    """A simple detector for data-exfiltration behavior.

    The direction is reversed from every other detector here: the
    compromised device is the packet *source*, and the attacker-controlled
    sink is the packet *destination* -- so a flow's own source_ip/
    destination_ip, taken from the raw capture, are the OPPOSITE of "device
    under attack" / "external attacker" for this one attack type. The
    signature itself is also distinct: low packet_count and low port
    diversity (like brute-force), but with average_packet_size well above
    anything else this system generates (small heartbeats/probes), which
    is what actually flags a leak rather than some other low-volume flow.
    """

    def __init__(
        self,
        max_unique_ports: int | None = None,
        min_packet_count: int | None = None,
        max_packet_count: int | None = None,
        min_average_packet_size: float | None = None,
    ) -> None:
        config = _load_detection_policy()
        self.max_unique_ports = int(
            config.get("exfiltration_max_unique_destination_ports", max_unique_ports if max_unique_ports is not None else 2)
        )
        self.min_packet_count = int(
            config.get("exfiltration_min_packet_count", min_packet_count if min_packet_count is not None else 3)
        )
        self.max_packet_count = int(
            config.get("exfiltration_max_packet_count", max_packet_count if max_packet_count is not None else 25)
        )
        self.min_average_packet_size = float(
            config.get("exfiltration_min_average_packet_size", min_average_packet_size if min_average_packet_size is not None else 600.0)
        )

    def detect(self, features: dict[str, Any]) -> ThreatEvent:
        unique_ports = int(features.get("unique_destination_ports", 0))
        packet_count = int(features.get("packet_count", 0))
        average_packet_size = float(features.get("average_packet_size", 0.0))

        is_threat = (
            unique_ports <= self.max_unique_ports
            and self.min_packet_count <= packet_count <= self.max_packet_count
            and average_packet_size >= self.min_average_packet_size
        )

        if is_threat:
            # Swap source/destination relative to the raw captured packet
            # direction: every downstream consumer (SecurityContext,
            # policies, the response executor) treats
            # ThreatEvent.destination_ip as "the device to act on" -- for
            # exfiltration that's the flow's own source_ip (the
            # compromised device), not its destination_ip (the attacker's
            # sink). Swapping here keeps that contract true for this one
            # attack type without changing any shared downstream code.
            source_ip = str(features.get("destination_ip", "unknown"))
            destination_ip = str(features.get("source_ip", "unknown"))
            attack_type = "data_exfiltration"
            threat_score = 0.85
            confidence = 0.8
            reason = "few large outbound transfers to a single destination, consistent with data exfiltration"
        else:
            source_ip = str(features.get("source_ip", "unknown"))
            destination_ip = str(features.get("destination_ip", "unknown"))
            attack_type = "normal"
            threat_score = 0.05
            confidence = 0.9
            reason = "traffic pattern does not meet exfiltration criteria"

        return ThreatEvent.from_result(
            source_ip=source_ip,
            destination_ip=destination_ip,
            attack_type=attack_type,
            threat_score=threat_score,
            confidence=confidence,
            detection_reason=reason,
            features=features,
            detector_name="RuleBasedExfiltrationDetector",
        )


class RuleBasedExploitDetector(Detector):
    """A simple detector for a single-port, few-shot exploit/injection
    attempt -- an oversized or malformed request sent to the device's
    management port, as opposed to brute-force's many small attempts.

    Sits in the traffic-shape territory every other detector's rate/count
    thresholds leave open: packet_count and unique_destination_ports here
    overlap heavily with ordinary low-volume traffic (a single heartbeat
    connect looks much the same on those two axes alone), so this detector
    leans on average_packet_size as the real discriminator, not volume.
    Real observed values from data/ml/controlled_flows_5class.csv put
    normal traffic's average_packet_size at 68-119 bytes and exfiltration's
    at 1200+; min/max_average_packet_size (250/550 by default) sit with
    real margin inside that gap -- above anything normal traffic actually
    produces and below exfiltration's own floor -- rather than picked
    without reference to observed data.
    """

    def __init__(
        self,
        max_unique_ports: int | None = None,
        min_packet_count: int | None = None,
        max_packet_count: int | None = None,
        min_average_packet_size: float | None = None,
        max_average_packet_size: float | None = None,
    ) -> None:
        config = _load_detection_policy()
        self.max_unique_ports = int(
            config.get("exploit_max_unique_destination_ports", max_unique_ports if max_unique_ports is not None else 1)
        )
        self.min_packet_count = int(
            config.get("exploit_min_packet_count", min_packet_count if min_packet_count is not None else 2)
        )
        self.max_packet_count = int(
            config.get("exploit_max_packet_count", max_packet_count if max_packet_count is not None else 8)
        )
        self.min_average_packet_size = float(
            config.get("exploit_min_average_packet_size", min_average_packet_size if min_average_packet_size is not None else 250.0)
        )
        self.max_average_packet_size = float(
            config.get("exploit_max_average_packet_size", max_average_packet_size if max_average_packet_size is not None else 550.0)
        )

    def detect(self, features: dict[str, Any]) -> ThreatEvent:
        unique_ports = int(features.get("unique_destination_ports", 0))
        packet_count = int(features.get("packet_count", 0))
        average_packet_size = float(features.get("average_packet_size", 0.0))

        is_threat = (
            unique_ports <= self.max_unique_ports
            and self.min_packet_count <= packet_count <= self.max_packet_count
            and self.min_average_packet_size <= average_packet_size <= self.max_average_packet_size
        )

        if is_threat:
            attack_type = "exploit_payload_injection"
            threat_score = 0.8
            confidence = 0.78
            reason = "a small number of oversized requests to a single service port, consistent with an exploit or command-injection attempt"
        else:
            attack_type = "normal"
            threat_score = 0.05
            confidence = 0.9
            reason = "traffic pattern does not meet exploit-payload criteria"

        return ThreatEvent.from_result(
            source_ip=str(features.get("source_ip", "unknown")),
            destination_ip=str(features.get("destination_ip", "unknown")),
            attack_type=attack_type,
            threat_score=threat_score,
            confidence=confidence,
            detection_reason=reason,
            features=features,
            detector_name="RuleBasedExploitDetector",
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
