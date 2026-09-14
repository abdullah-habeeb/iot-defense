"""Detector contract and baseline rule-based implementation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import yaml

from iot_defense.detection.threat_event import ThreatEvent


def _load_detection_policy() -> dict[str, Any]:
    # parents[2] from src/iot_defense/detection/detector.py is src/, not
    # the repo root -- the same off-by-one bug found and fixed in
    # defense/policy.py's own _load_decision_policy_config(). config_path
    # never existed, so this always silently returned {} and every
    # detector below always used its hardcoded fallback default instead of
    # the YAML's own -- behaviorally invisible only because every default
    # here had been kept numerically in sync with config/policies.yaml's
    # policy.detection section by hand.
    config_path = Path(__file__).resolve().parents[3] / "config" / "policies.yaml"
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


class RuleBasedSynFloodDetector(Detector):
    """A TCP SYN-flood detector: many refused connects to one port at a
    rate strictly between RuleBasedBruteForceDetector's own ceiling
    (15.0 packets_per_second) and RuleBasedDosDetector's own floor
    (20.0) -- a real, unclaimed gap between the two, not a guess.
    tcp_ack_count staying near zero is what actually separates this from
    RuleBasedMqttFloodDetector, which shares the same rate gap but with
    real, completed handshakes.
    """

    def __init__(
        self,
        max_unique_ports: int | None = None,
        min_tcp_syn_count: int | None = None,
        max_tcp_ack_count: int | None = None,
        min_packets_per_second: float | None = None,
        max_packets_per_second: float | None = None,
    ) -> None:
        config = _load_detection_policy()
        self.max_unique_ports = int(config.get("syn_flood_max_unique_destination_ports", max_unique_ports if max_unique_ports is not None else 2))
        self.min_tcp_syn_count = int(config.get("syn_flood_min_tcp_syn_count", min_tcp_syn_count if min_tcp_syn_count is not None else 10))
        self.max_tcp_ack_count = int(config.get("syn_flood_max_tcp_ack_count", max_tcp_ack_count if max_tcp_ack_count is not None else 3))
        self.min_packets_per_second = float(config.get("syn_flood_min_packets_per_second", min_packets_per_second if min_packets_per_second is not None else 15.0))
        self.max_packets_per_second = float(config.get("syn_flood_max_packets_per_second", max_packets_per_second if max_packets_per_second is not None else 20.0))

    def detect(self, features: dict[str, Any]) -> ThreatEvent:
        protocol = str(features.get("protocol", "")).upper()
        unique_ports = int(features.get("unique_destination_ports", 0))
        tcp_syn_count = int(features.get("tcp_syn_count", 0))
        tcp_ack_count = int(features.get("tcp_ack_count", 0))
        packets_per_second = float(features.get("packets_per_second", 0.0))

        is_threat = (
            protocol == "TCP"
            and unique_ports <= self.max_unique_ports
            and tcp_syn_count >= self.min_tcp_syn_count
            and tcp_ack_count <= self.max_tcp_ack_count
            and self.min_packets_per_second < packets_per_second < self.max_packets_per_second
        )

        if is_threat:
            attack_type = "tcp_syn_flood"
            threat_score = 0.88
            confidence = 0.85
            reason = "sustained high-rate refused TCP connects to a single port, with no completed handshakes"
        else:
            attack_type = "normal"
            threat_score = 0.05
            confidence = 0.9
            reason = "traffic pattern does not meet SYN-flood criteria"

        return ThreatEvent.from_result(
            source_ip=str(features.get("source_ip", "unknown")),
            destination_ip=str(features.get("destination_ip", "unknown")),
            attack_type=attack_type,
            threat_score=threat_score,
            confidence=confidence,
            detection_reason=reason,
            features=features,
            detector_name="RuleBasedSynFloodDetector",
        )


class RuleBasedIcmpFloodDetector(Detector):
    """An ICMP ping-flood detector. ICMP carries no ports at all, so
    every other detector's port-count check is trivially satisfied by
    ICMP traffic -- protocol=="ICMP" plus a real packet-count floor is
    what actually keeps this specific to a genuine flood rather than
    ordinary ICMP echo traffic (e.g. the two-packet pings
    generate_normal_mininet_traffic already sends). average_packet_size
    is required above 200 bytes specifically because this attack's real
    rate (~9/s) otherwise sits inside RuleBasedBruteForceDetector's own
    [1, 15] packets_per_second window -- padding the ping payload is
    what keeps it out. The window's upper bound (300 bytes) is not a
    tight "gap" the way some other detectors' are: a real live capture
    of a 220-byte ping payload measured average_packet_size=262 (the
    220-byte payload plus real Ethernet+IP+ICMP framing overhead, ~42
    bytes, not accounted for in the original design estimate) --
    RuleBasedExploitDetector's own packet_count<=8 ceiling, not this
    upper bound, is what actually keeps a real flood (packet_count in
    the dozens) out of that detector's territory regardless of size.
    """

    def __init__(
        self,
        min_icmp_packet_count: int | None = None,
        min_packets_per_second: float | None = None,
        min_average_packet_size: float | None = None,
        max_average_packet_size: float | None = None,
    ) -> None:
        config = _load_detection_policy()
        self.min_icmp_packet_count = int(config.get("icmp_flood_min_icmp_packet_count", min_icmp_packet_count if min_icmp_packet_count is not None else 20))
        self.min_packets_per_second = float(config.get("icmp_flood_min_packets_per_second", min_packets_per_second if min_packets_per_second is not None else 5.0))
        self.min_average_packet_size = float(config.get("icmp_flood_min_average_packet_size", min_average_packet_size if min_average_packet_size is not None else 200.0))
        self.max_average_packet_size = float(config.get("icmp_flood_max_average_packet_size", max_average_packet_size if max_average_packet_size is not None else 300.0))

    def detect(self, features: dict[str, Any]) -> ThreatEvent:
        protocol = str(features.get("protocol", "")).upper()
        icmp_packet_count = int(features.get("icmp_packet_count", 0))
        packets_per_second = float(features.get("packets_per_second", 0.0))
        average_packet_size = float(features.get("average_packet_size", 0.0))

        is_threat = (
            protocol == "ICMP"
            and icmp_packet_count >= self.min_icmp_packet_count
            and packets_per_second >= self.min_packets_per_second
            and self.min_average_packet_size < average_packet_size < self.max_average_packet_size
        )

        if is_threat:
            attack_type = "icmp_ping_flood"
            threat_score = 0.82
            confidence = 0.8
            reason = "sustained high-volume padded ICMP echo traffic, consistent with a ping flood"
        else:
            attack_type = "normal"
            threat_score = 0.05
            confidence = 0.9
            reason = "traffic pattern does not meet ICMP-flood criteria"

        return ThreatEvent.from_result(
            source_ip=str(features.get("source_ip", "unknown")),
            destination_ip=str(features.get("destination_ip", "unknown")),
            attack_type=attack_type,
            threat_score=threat_score,
            confidence=confidence,
            detection_reason=reason,
            features=features,
            detector_name="RuleBasedIcmpFloodDetector",
        )


class RuleBasedSlowLorisDetector(Detector):
    """A Slowloris-style connection-exhaustion detector.
    unique_source_ports is the real, previously-unused signal this
    relies on: many concurrent held-open connections each claim their
    own fresh ephemeral source port, something no other registered
    attack produces in volume (brute-force's own sequential attempts
    accumulate a handful too, an order of magnitude fewer over the same
    window -- a real live capture measured 14 for this attack's own
    generator against brute-force's own single-digit count over the
    same window, so the floor here is set at 12, not the higher number
    an idealized "20 concurrent connections" design would suggest,
    since not every attempted connection reliably completes within a
    real, bounded capture window). average_packet_size is required
    above RuleBasedBruteForceDetector's 200-byte ceiling; the upper
    bound is wide (280) because RuleBasedExploitDetector's own
    packet_count<=8 ceiling, not a tight size gap, is what actually
    keeps this detector's real traffic (packet_count in the dozens) out
    of that one's territory.
    """

    def __init__(
        self,
        max_unique_destination_ports: int | None = None,
        min_unique_source_ports: int | None = None,
        min_tcp_ack_count: int | None = None,
        min_average_packet_size: float | None = None,
        max_average_packet_size: float | None = None,
    ) -> None:
        config = _load_detection_policy()
        self.max_unique_destination_ports = int(config.get("slow_loris_max_unique_destination_ports", max_unique_destination_ports if max_unique_destination_ports is not None else 2))
        self.min_unique_source_ports = int(config.get("slow_loris_min_unique_source_ports", min_unique_source_ports if min_unique_source_ports is not None else 12))
        self.min_tcp_ack_count = int(config.get("slow_loris_min_tcp_ack_count", min_tcp_ack_count if min_tcp_ack_count is not None else 15))
        self.min_average_packet_size = float(config.get("slow_loris_min_average_packet_size", min_average_packet_size if min_average_packet_size is not None else 200.0))
        self.max_average_packet_size = float(config.get("slow_loris_max_average_packet_size", max_average_packet_size if max_average_packet_size is not None else 280.0))

    def detect(self, features: dict[str, Any]) -> ThreatEvent:
        protocol = str(features.get("protocol", "")).upper()
        unique_destination_ports = int(features.get("unique_destination_ports", 0))
        unique_source_ports = int(features.get("unique_source_ports", 0))
        tcp_ack_count = int(features.get("tcp_ack_count", 0))
        average_packet_size = float(features.get("average_packet_size", 0.0))

        is_threat = (
            protocol == "TCP"
            and unique_destination_ports <= self.max_unique_destination_ports
            and unique_source_ports >= self.min_unique_source_ports
            and tcp_ack_count >= self.min_tcp_ack_count
            and self.min_average_packet_size < average_packet_size < self.max_average_packet_size
        )

        if is_threat:
            attack_type = "slow_loris_exhaustion"
            threat_score = 0.78
            confidence = 0.75
            reason = "many concurrent connections held open from distinct source ports, consistent with connection-exhaustion"
        else:
            attack_type = "normal"
            threat_score = 0.05
            confidence = 0.9
            reason = "traffic pattern does not meet connection-exhaustion criteria"

        return ThreatEvent.from_result(
            source_ip=str(features.get("source_ip", "unknown")),
            destination_ip=str(features.get("destination_ip", "unknown")),
            attack_type=attack_type,
            threat_score=threat_score,
            confidence=confidence,
            detection_reason=reason,
            features=features,
            detector_name="RuleBasedSlowLorisDetector",
        )


class RuleBasedDnsAmplificationDetector(Detector):
    """A DNS-amplification/reflection detector: oversized inbound UDP
    responses. packet_count>=26 is what keeps this out of both
    RuleBasedExfiltrationDetector's window (capped at 25) and
    RuleBasedExploitDetector's (capped at 8) even though all three sit
    in similar payload-size territory -- packet_count, not
    average_packet_size, is the real guard against both, which is why
    this detector's own upper size bound (650) is wide rather than a
    tight gap: a real live capture of a 570-byte payload measured
    average_packet_size=612 (real Ethernet+IP+UDP framing overhead, not
    accounted for in the original design estimate). packets_per_second
    >= 4.0 is what separates this from RuleBasedFirmwareTamperingDetector,
    which shares the same size range at a slower, less bursty rate.
    """

    def __init__(
        self,
        max_unique_ports: int | None = None,
        min_packet_count: int | None = None,
        min_average_packet_size: float | None = None,
        max_average_packet_size: float | None = None,
        min_packets_per_second: float | None = None,
    ) -> None:
        config = _load_detection_policy()
        self.max_unique_ports = int(config.get("dns_amplification_max_unique_destination_ports", max_unique_ports if max_unique_ports is not None else 2))
        self.min_packet_count = int(config.get("dns_amplification_min_packet_count", min_packet_count if min_packet_count is not None else 26))
        self.min_average_packet_size = float(config.get("dns_amplification_min_average_packet_size", min_average_packet_size if min_average_packet_size is not None else 550.0))
        self.max_average_packet_size = float(config.get("dns_amplification_max_average_packet_size", max_average_packet_size if max_average_packet_size is not None else 650.0))
        self.min_packets_per_second = float(config.get("dns_amplification_min_packets_per_second", min_packets_per_second if min_packets_per_second is not None else 4.0))

    def detect(self, features: dict[str, Any]) -> ThreatEvent:
        protocol = str(features.get("protocol", "")).upper()
        unique_ports = int(features.get("unique_destination_ports", 0))
        packet_count = int(features.get("packet_count", 0))
        average_packet_size = float(features.get("average_packet_size", 0.0))
        packets_per_second = float(features.get("packets_per_second", 0.0))

        is_threat = (
            protocol == "UDP"
            and unique_ports <= self.max_unique_ports
            and packet_count >= self.min_packet_count
            and self.min_average_packet_size <= average_packet_size < self.max_average_packet_size
            and packets_per_second >= self.min_packets_per_second
        )

        if is_threat:
            attack_type = "dns_amplification"
            threat_score = 0.87
            confidence = 0.82
            reason = "a burst of oversized inbound UDP responses, consistent with a reflection/amplification attack"
        else:
            attack_type = "normal"
            threat_score = 0.05
            confidence = 0.9
            reason = "traffic pattern does not meet amplification criteria"

        return ThreatEvent.from_result(
            source_ip=str(features.get("source_ip", "unknown")),
            destination_ip=str(features.get("destination_ip", "unknown")),
            attack_type=attack_type,
            threat_score=threat_score,
            confidence=confidence,
            detection_reason=reason,
            features=features,
            detector_name="RuleBasedDnsAmplificationDetector",
        )


class RuleBasedDnsTunnelingDetector(Detector):
    """A DNS-tunneling covert-channel exfiltration detector -- direction
    reversed, like RuleBasedExfiltrationDetector, but a genuinely
    different mechanism: many small, frequent queries rather than a few
    large transfers, the shape a naive payload-size-only exfiltration
    detector would miss entirely. average_packet_size shares the same
    real range RuleBasedSlowLorisDetector's own padding targets;
    packets_per_second < 5.5 is what separates this from
    RuleBasedRogueBeaconDetector, which shares the same size range at a
    higher, more continuous frequency.
    """

    def __init__(
        self,
        max_unique_ports: int | None = None,
        min_packet_count: int | None = None,
        min_average_packet_size: float | None = None,
        max_average_packet_size: float | None = None,
        max_packets_per_second: float | None = None,
    ) -> None:
        config = _load_detection_policy()
        self.max_unique_ports = int(config.get("dns_tunneling_max_unique_destination_ports", max_unique_ports if max_unique_ports is not None else 2))
        self.min_packet_count = int(config.get("dns_tunneling_min_packet_count", min_packet_count if min_packet_count is not None else 22))
        self.min_average_packet_size = float(config.get("dns_tunneling_min_average_packet_size", min_average_packet_size if min_average_packet_size is not None else 200.0))
        self.max_average_packet_size = float(config.get("dns_tunneling_max_average_packet_size", max_average_packet_size if max_average_packet_size is not None else 280.0))
        self.max_packets_per_second = float(config.get("dns_tunneling_max_packets_per_second", max_packets_per_second if max_packets_per_second is not None else 5.5))

    def detect(self, features: dict[str, Any]) -> ThreatEvent:
        protocol = str(features.get("protocol", "")).upper()
        unique_ports = int(features.get("unique_destination_ports", 0))
        packet_count = int(features.get("packet_count", 0))
        average_packet_size = float(features.get("average_packet_size", 0.0))
        packets_per_second = float(features.get("packets_per_second", 0.0))

        is_threat = (
            protocol == "UDP"
            and unique_ports <= self.max_unique_ports
            and packet_count >= self.min_packet_count
            and self.min_average_packet_size < average_packet_size < self.max_average_packet_size
            and packets_per_second < self.max_packets_per_second
        )

        if is_threat:
            # Direction reversed, like RuleBasedExfiltrationDetector: the
            # flow's own source_ip is the compromised device, not the
            # external attacker.
            source_ip = str(features.get("destination_ip", "unknown"))
            destination_ip = str(features.get("source_ip", "unknown"))
            attack_type = "dns_tunneling_exfiltration"
            threat_score = 0.8
            confidence = 0.72
            reason = "many small, frequent outbound queries over a sustained window, consistent with a DNS-tunneling covert channel"
        else:
            source_ip = str(features.get("source_ip", "unknown"))
            destination_ip = str(features.get("destination_ip", "unknown"))
            attack_type = "normal"
            threat_score = 0.05
            confidence = 0.9
            reason = "traffic pattern does not meet DNS-tunneling criteria"

        return ThreatEvent.from_result(
            source_ip=source_ip,
            destination_ip=destination_ip,
            attack_type=attack_type,
            threat_score=threat_score,
            confidence=confidence,
            detection_reason=reason,
            features=features,
            detector_name="RuleBasedDnsTunnelingDetector",
        )


class RuleBasedMqttFloodDetector(Detector):
    """An MQTT publish-flood detector: many real, completed TCP
    connections against the device's message-broker port, deliberately
    paced slow (packets_per_second below 1.0) -- a real, wide-margin gap
    clear of every other registered detector's own floor on this axis
    (RuleBasedBruteForceDetector's own 1.0/s included), rather than the
    narrow 15-20/s gap RuleBasedSynFloodDetector's own traffic shares.
    That gap was tried here first and abandoned: even retargeted to its
    real middle with a longer capture window to average out timing
    noise, live runs still occasionally measured a dip into the
    low-teens (13.7/s, 14.1/s across two separate runs) and were claimed
    by RuleBasedBruteForceDetector's own <=15.0 ceiling instead -- a
    full TCP handshake per attempt carries more real scheduling-level
    variance than a bare refused connect, and that variance proved too
    much for a 5-unit gap on this VM. tcp_ack_count staying high here
    (real completed handshakes) vs. RuleBasedSynFloodDetector's own
    near-zero (refused connects) is what actually disambiguates the two,
    independent of rate.
    """

    def __init__(
        self,
        max_unique_ports: int | None = None,
        min_tcp_ack_count: int | None = None,
        max_packets_per_second: float | None = None,
        max_average_packet_size: float | None = None,
    ) -> None:
        config = _load_detection_policy()
        self.max_unique_ports = int(config.get("mqtt_flood_max_unique_destination_ports", max_unique_ports if max_unique_ports is not None else 2))
        self.min_tcp_ack_count = int(config.get("mqtt_flood_min_tcp_ack_count", min_tcp_ack_count if min_tcp_ack_count is not None else 15))
        self.max_packets_per_second = float(config.get("mqtt_flood_max_packets_per_second", max_packets_per_second if max_packets_per_second is not None else 1.0))
        self.max_average_packet_size = float(config.get("mqtt_flood_max_average_packet_size", max_average_packet_size if max_average_packet_size is not None else 200.0))

    def detect(self, features: dict[str, Any]) -> ThreatEvent:
        protocol = str(features.get("protocol", "")).upper()
        unique_ports = int(features.get("unique_destination_ports", 0))
        tcp_ack_count = int(features.get("tcp_ack_count", 0))
        packets_per_second = float(features.get("packets_per_second", 0.0))
        average_packet_size = float(features.get("average_packet_size", 0.0))

        is_threat = (
            protocol == "TCP"
            and unique_ports <= self.max_unique_ports
            and tcp_ack_count >= self.min_tcp_ack_count
            and packets_per_second < self.max_packets_per_second
            and average_packet_size <= self.max_average_packet_size
        )

        if is_threat:
            attack_type = "mqtt_message_flood"
            threat_score = 0.75
            confidence = 0.72
            reason = "a sustained high-rate burst of small, real completed connections to the message-broker port"
        else:
            attack_type = "normal"
            threat_score = 0.05
            confidence = 0.9
            reason = "traffic pattern does not meet MQTT-flood criteria"

        return ThreatEvent.from_result(
            source_ip=str(features.get("source_ip", "unknown")),
            destination_ip=str(features.get("destination_ip", "unknown")),
            attack_type=attack_type,
            threat_score=threat_score,
            confidence=confidence,
            detection_reason=reason,
            features=features,
            detector_name="RuleBasedMqttFloodDetector",
        )


class RuleBasedFirmwareTamperingDetector(Detector):
    """A firmware/configuration-tampering detector -- direction
    reversed, like RuleBasedExfiltrationDetector and
    RuleBasedDnsTunnelingDetector: an already-compromised device pushing
    unauthorized config/firmware blobs outward. Shares
    RuleBasedDnsAmplificationDetector's own average_packet_size range but
    at a meaningfully slower, less bursty rate (< 5.0/s here vs. that
    detector's own >= 4.0/s floor) -- the two are disambiguated purely
    on packets_per_second, not size.
    """

    def __init__(
        self,
        max_unique_ports: int | None = None,
        min_packet_count: int | None = None,
        min_average_packet_size: float | None = None,
        max_average_packet_size: float | None = None,
        max_packets_per_second: float | None = None,
    ) -> None:
        config = _load_detection_policy()
        self.max_unique_ports = int(config.get("firmware_tampering_max_unique_destination_ports", max_unique_ports if max_unique_ports is not None else 2))
        self.min_packet_count = int(config.get("firmware_tampering_min_packet_count", min_packet_count if min_packet_count is not None else 26))
        self.min_average_packet_size = float(config.get("firmware_tampering_min_average_packet_size", min_average_packet_size if min_average_packet_size is not None else 550.0))
        self.max_average_packet_size = float(config.get("firmware_tampering_max_average_packet_size", max_average_packet_size if max_average_packet_size is not None else 650.0))
        self.max_packets_per_second = float(config.get("firmware_tampering_max_packets_per_second", max_packets_per_second if max_packets_per_second is not None else 5.0))

    def detect(self, features: dict[str, Any]) -> ThreatEvent:
        protocol = str(features.get("protocol", "")).upper()
        unique_ports = int(features.get("unique_destination_ports", 0))
        packet_count = int(features.get("packet_count", 0))
        average_packet_size = float(features.get("average_packet_size", 0.0))
        packets_per_second = float(features.get("packets_per_second", 0.0))

        is_threat = (
            protocol == "UDP"
            and unique_ports <= self.max_unique_ports
            and packet_count >= self.min_packet_count
            and self.min_average_packet_size <= average_packet_size < self.max_average_packet_size
            and packets_per_second < self.max_packets_per_second
        )

        if is_threat:
            source_ip = str(features.get("destination_ip", "unknown"))
            destination_ip = str(features.get("source_ip", "unknown"))
            attack_type = "firmware_tampering"
            threat_score = 0.83
            confidence = 0.78
            reason = "periodic, oversized outbound configuration/firmware pushes, consistent with an already-compromised device"
        else:
            source_ip = str(features.get("source_ip", "unknown"))
            destination_ip = str(features.get("destination_ip", "unknown"))
            attack_type = "normal"
            threat_score = 0.05
            confidence = 0.9
            reason = "traffic pattern does not meet firmware-tampering criteria"

        return ThreatEvent.from_result(
            source_ip=source_ip,
            destination_ip=destination_ip,
            attack_type=attack_type,
            threat_score=threat_score,
            confidence=confidence,
            detection_reason=reason,
            features=features,
            detector_name="RuleBasedFirmwareTamperingDetector",
        )


class RuleBasedBufferOverflowDetector(Detector):
    """A sustained buffer-overflow/fuzzing-probe detector: many real
    oversized TCP requests sent on one persistent connection. Unlike
    RuleBasedExploitDetector's deliberately single-shot signature
    (capped at 8 attempts, modelling one uncertain injection try),
    packet_count>=26 here models a sustained campaign -- which is what
    keeps this out of RuleBasedExploitDetector's own window even though
    both sit in similar payload-size territory (this detector's own
    upper size bound, 700, is wide rather than a tight gap, for the same
    reason -- packet_count, not size, is the real guard). The generator's
    own docstring explains why the real ceiling is far stricter than
    this class's own max_packets_per_second suggests: a persistent
    connection's data segments and their TCP ACKs are grouped into two
    *separate* flows by direction, so both the payload flow and its
    paired ACK-only flow need to clear every other registered detector's
    own thresholds independently -- in practice that means well below
    1.0/s, not just below DoS's 20.0/s floor.
    """

    def __init__(
        self,
        max_unique_ports: int | None = None,
        min_packet_count: int | None = None,
        min_average_packet_size: float | None = None,
        max_average_packet_size: float | None = None,
        max_packets_per_second: float | None = None,
    ) -> None:
        config = _load_detection_policy()
        self.max_unique_ports = int(config.get("buffer_overflow_max_unique_destination_ports", max_unique_ports if max_unique_ports is not None else 2))
        self.min_packet_count = int(config.get("buffer_overflow_min_packet_count", min_packet_count if min_packet_count is not None else 26))
        self.min_average_packet_size = float(config.get("buffer_overflow_min_average_packet_size", min_average_packet_size if min_average_packet_size is not None else 550.0))
        self.max_average_packet_size = float(config.get("buffer_overflow_max_average_packet_size", max_average_packet_size if max_average_packet_size is not None else 700.0))
        self.max_packets_per_second = float(config.get("buffer_overflow_max_packets_per_second", max_packets_per_second if max_packets_per_second is not None else 20.0))

    def detect(self, features: dict[str, Any]) -> ThreatEvent:
        protocol = str(features.get("protocol", "")).upper()
        unique_ports = int(features.get("unique_destination_ports", 0))
        packet_count = int(features.get("packet_count", 0))
        average_packet_size = float(features.get("average_packet_size", 0.0))
        packets_per_second = float(features.get("packets_per_second", 0.0))

        is_threat = (
            protocol == "TCP"
            and unique_ports <= self.max_unique_ports
            and packet_count >= self.min_packet_count
            and self.min_average_packet_size <= average_packet_size < self.max_average_packet_size
            and packets_per_second < self.max_packets_per_second
        )

        if is_threat:
            attack_type = "buffer_overflow_probe"
            threat_score = 0.86
            confidence = 0.8
            reason = "a sustained campaign of many oversized requests to a single service port, consistent with active fuzzing/exploitation"
        else:
            attack_type = "normal"
            threat_score = 0.05
            confidence = 0.9
            reason = "traffic pattern does not meet buffer-overflow-probe criteria"

        return ThreatEvent.from_result(
            source_ip=str(features.get("source_ip", "unknown")),
            destination_ip=str(features.get("destination_ip", "unknown")),
            attack_type=attack_type,
            threat_score=threat_score,
            confidence=confidence,
            detection_reason=reason,
            features=features,
            detector_name="RuleBasedBufferOverflowDetector",
        )


class RuleBasedReplayAttackDetector(Detector):
    """A credential/command-replay detector: a captured payload re-sent
    repeatedly over UDP, deliberately paced slow (packets_per_second
    below 1.0) -- a real, wide-margin gap clear of every other
    registered detector's own floor on this axis
    (RuleBasedBruteForceDetector's own 1.0/s included), rather than the
    narrow 15-20/s gap RuleBasedSynFloodDetector and
    RuleBasedMqttFloodDetector's own traffic shares. That gap was tried
    here first and abandoned: even retargeted to its real middle with a
    longer capture window to average out timing noise, live runs still
    occasionally measured a dip under 15.0/s (with three attacks
    already sharing that one 5-unit gap, this VM's own real timing
    variance made it unreliable for a fourth) and were claimed by
    RuleBasedBruteForceDetector's own <=15.0 ceiling instead.
    """

    def __init__(
        self,
        max_unique_ports: int | None = None,
        min_packet_count: int | None = None,
        max_packets_per_second: float | None = None,
        max_average_packet_size: float | None = None,
    ) -> None:
        config = _load_detection_policy()
        self.max_unique_ports = int(config.get("replay_attack_max_unique_destination_ports", max_unique_ports if max_unique_ports is not None else 2))
        self.min_packet_count = int(config.get("replay_attack_min_packet_count", min_packet_count if min_packet_count is not None else 15))
        self.max_packets_per_second = float(config.get("replay_attack_max_packets_per_second", max_packets_per_second if max_packets_per_second is not None else 1.0))
        self.max_average_packet_size = float(config.get("replay_attack_max_average_packet_size", max_average_packet_size if max_average_packet_size is not None else 200.0))

    def detect(self, features: dict[str, Any]) -> ThreatEvent:
        protocol = str(features.get("protocol", "")).upper()
        unique_ports = int(features.get("unique_destination_ports", 0))
        packet_count = int(features.get("packet_count", 0))
        packets_per_second = float(features.get("packets_per_second", 0.0))
        average_packet_size = float(features.get("average_packet_size", 0.0))

        is_threat = (
            protocol == "UDP"
            and unique_ports <= self.max_unique_ports
            and packet_count >= self.min_packet_count
            and packets_per_second < self.max_packets_per_second
            and average_packet_size <= self.max_average_packet_size
        )

        if is_threat:
            attack_type = "credential_replay"
            threat_score = 0.72
            confidence = 0.68
            reason = "a rapid, repeated burst of uniform small packets to a single port, consistent with a captured credential/command being replayed"
        else:
            attack_type = "normal"
            threat_score = 0.05
            confidence = 0.9
            reason = "traffic pattern does not meet replay-attack criteria"

        return ThreatEvent.from_result(
            source_ip=str(features.get("source_ip", "unknown")),
            destination_ip=str(features.get("destination_ip", "unknown")),
            attack_type=attack_type,
            threat_score=threat_score,
            confidence=confidence,
            detection_reason=reason,
            features=features,
            detector_name="RuleBasedReplayAttackDetector",
        )


class RuleBasedRogueBeaconDetector(Detector):
    """A rogue-configuration-beacon detector -- direction reversed, like
    every other tampering-style detector here: an already-compromised
    device continuously beaconing small, unauthorized updates outward.
    Shares RuleBasedDnsTunnelingDetector's own average_packet_size range
    but at a meaningfully higher, more continuous frequency
    (packets_per_second >= 5.5 here vs. that detector's own < 5.5
    ceiling) -- the real distinction between "occasional tampering" and
    "a live, continuously-beaconing implant" at this shape resolution.
    """

    def __init__(
        self,
        max_unique_ports: int | None = None,
        min_packet_count: int | None = None,
        min_average_packet_size: float | None = None,
        max_average_packet_size: float | None = None,
        min_packets_per_second: float | None = None,
    ) -> None:
        config = _load_detection_policy()
        self.max_unique_ports = int(config.get("rogue_beacon_max_unique_destination_ports", max_unique_ports if max_unique_ports is not None else 2))
        self.min_packet_count = int(config.get("rogue_beacon_min_packet_count", min_packet_count if min_packet_count is not None else 40))
        self.min_average_packet_size = float(config.get("rogue_beacon_min_average_packet_size", min_average_packet_size if min_average_packet_size is not None else 200.0))
        self.max_average_packet_size = float(config.get("rogue_beacon_max_average_packet_size", max_average_packet_size if max_average_packet_size is not None else 280.0))
        self.min_packets_per_second = float(config.get("rogue_beacon_min_packets_per_second", min_packets_per_second if min_packets_per_second is not None else 5.5))

    def detect(self, features: dict[str, Any]) -> ThreatEvent:
        protocol = str(features.get("protocol", "")).upper()
        unique_ports = int(features.get("unique_destination_ports", 0))
        packet_count = int(features.get("packet_count", 0))
        average_packet_size = float(features.get("average_packet_size", 0.0))
        packets_per_second = float(features.get("packets_per_second", 0.0))

        is_threat = (
            protocol == "UDP"
            and unique_ports <= self.max_unique_ports
            and packet_count >= self.min_packet_count
            and self.min_average_packet_size < average_packet_size < self.max_average_packet_size
            and packets_per_second >= self.min_packets_per_second
        )

        if is_threat:
            source_ip = str(features.get("destination_ip", "unknown"))
            destination_ip = str(features.get("source_ip", "unknown"))
            attack_type = "rogue_config_beacon"
            threat_score = 0.6
            confidence = 0.55
            reason = "frequent, low-confidence outbound beaconing pattern, possibly indicating an unauthorized or tampered device"
        else:
            source_ip = str(features.get("source_ip", "unknown"))
            destination_ip = str(features.get("destination_ip", "unknown"))
            attack_type = "normal"
            threat_score = 0.05
            confidence = 0.9
            reason = "traffic pattern does not meet rogue-beacon criteria"

        return ThreatEvent.from_result(
            source_ip=source_ip,
            destination_ip=destination_ip,
            attack_type=attack_type,
            threat_score=threat_score,
            confidence=confidence,
            detection_reason=reason,
            features=features,
            detector_name="RuleBasedRogueBeaconDetector",
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

    def detect_flows(self, flows: list[Any]) -> ThreatEvent:
        """Classify every flow in a capture window, not just a single
        pre-selected one -- returns the first genuinely flagged flow's
        event, applying detect()'s own "first non-normal wins" contract
        per-flow instead of trusting flows[0] to already be the signal.

        A capture window can contain more than the attack traffic itself:
        incidental background noise (ARP, IPv6 neighbour discovery
        triggered by an interface coming back up after isolate()/
        restore()) can land earlier in capture order than the real
        traffic, especially once a network has been isolated and restored
        more than once in its lifetime. This was found, not assumed: a
        real evaluation-harness run that isolated/restored the same
        network several times in a row saw exactly this -- a stray
        IPv6-neighbour-discovery packet became flows[0], and a real
        exfiltration flow captured moments later in the same window was
        silently ignored. Scanning every flow instead of trusting
        position in the capture fixes that without weakening detection
        for the common case, where the first flow already is the signal.
        """
        fallback_normal_event: ThreatEvent | None = None
        for flow in flows:
            event = self.detect(flow.to_dict())
            if event.attack_type != "normal":
                return event
            fallback_normal_event = fallback_normal_event or event

        if fallback_normal_event is None:
            raise ValueError("detect_flows() requires at least one flow")
        return fallback_normal_event  # every flow, and every rule set, agrees: normal traffic
