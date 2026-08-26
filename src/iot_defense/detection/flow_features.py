"""Feature aggregation for packet flows and traffic windows."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from ipaddress import ip_address
from typing import Any


@dataclass(slots=True)
class FlowFeatures:
    """Feature record for a traffic window or directional flow."""

    source_ip: str
    destination_ip: str
    protocol: str
    duration: float
    packet_count: int
    packets_per_second: float
    bytes_total: int
    average_packet_size: float
    unique_destination_ports: int
    unique_source_ports: int
    tcp_syn_count: int = 0
    tcp_ack_count: int = 0
    udp_packet_count: int = 0
    icmp_packet_count: int = 0
    window_start: float | None = None
    window_end: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FeatureAggregator:
    """Convert structured packet events into flow/window feature records."""

    def __init__(self, window_seconds: float = 3.0) -> None:
        self.window_seconds = window_seconds

    @staticmethod
    def _normalize_ip(value: Any) -> str | None:
        if value is None:
            return None

        normalized = str(value).strip()
        if not normalized or normalized.lower() in {"unknown", "none", "null"}:
            return None

        try:
            ip_address(normalized)
        except ValueError:
            return None

        return normalized

    def aggregate(self, events: list[dict[str, Any]]) -> list[FlowFeatures]:
        """Aggregate a list of packet events into directional flow feature records."""
        valid_events: list[dict[str, Any]] = []
        for event in events:
            src_ip = self._normalize_ip(event.get("src_ip"))
            dst_ip = self._normalize_ip(event.get("dst_ip"))
            if src_ip is None or dst_ip is None:
                continue

            normalized_event = dict(event)
            normalized_event["src_ip"] = src_ip
            normalized_event["dst_ip"] = dst_ip
            valid_events.append(normalized_event)

        if not valid_events:
            return []

        grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
        for event in valid_events:
            src_ip = str(event.get("src_ip", "unknown"))
            dst_ip = str(event.get("dst_ip", "unknown"))
            protocol = str(event.get("protocol", "UNKNOWN")).upper()
            key = (src_ip, dst_ip, protocol)
            grouped.setdefault(key, []).append(event)

        features: list[FlowFeatures] = []
        for (src_ip, dst_ip, protocol), group in grouped.items():
            timestamps = [float(event.get("timestamp", 0.0)) for event in group]
            start = min(timestamps) if timestamps else 0.0
            end = max(timestamps) if timestamps else 0.0
            duration = max(end - start, 0.0)
            packet_count = len(group)
            packets_per_second = (packet_count / duration) if duration > 0 else 0.0
            bytes_total = sum(int(event.get("packet_length", 0)) for event in group)
            average_packet_size = (bytes_total / packet_count) if packet_count else 0.0

            ports = [event.get("src_port") for event in group if event.get("src_port") is not None]
            dest_ports = [event.get("dst_port") for event in group if event.get("dst_port") is not None]
            tcp_syn_count = sum(1 for event in group if event.get("protocol") == "TCP" and event.get("src_port") is not None)
            tcp_ack_count = sum(1 for event in group if event.get("protocol") == "TCP" and event.get("dst_port") is not None)
            udp_packet_count = sum(1 for event in group if event.get("protocol") == "UDP")
            icmp_packet_count = sum(1 for event in group if event.get("protocol") == "ICMP")

            features.append(
                FlowFeatures(
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    protocol=protocol,
                    duration=duration,
                    packet_count=packet_count,
                    packets_per_second=packets_per_second,
                    bytes_total=bytes_total,
                    average_packet_size=average_packet_size,
                    unique_destination_ports=len(set(dest_ports)),
                    unique_source_ports=len(set(ports)),
                    tcp_syn_count=tcp_syn_count,
                    tcp_ack_count=tcp_ack_count,
                    udp_packet_count=udp_packet_count,
                    icmp_packet_count=icmp_packet_count,
                    window_start=start,
                    window_end=end,
                    metadata={"event_count": packet_count},
                )
            )
        return features

    def calculate_packets_per_second(self, events: list[dict[str, Any]]) -> float:
        if not events:
            return 0.0
        timestamps = [float(event.get("timestamp", 0.0)) for event in events]
        duration = max(max(timestamps) - min(timestamps), 0.0)
        return (len(events) / duration) if duration > 0 else float(len(events))

    def calculate_unique_ports(self, events: list[dict[str, Any]], field_name: str) -> int:
        values = {event.get(field_name) for event in events if event.get(field_name) is not None}
        return len(values)

    def count_tcp_flags(self, events: list[dict[str, Any]], flag_name: str) -> int:
        if flag_name == "syn":
            return sum(1 for event in events if event.get("protocol") == "TCP" and event.get("src_port") is not None)
        if flag_name == "ack":
            return sum(1 for event in events if event.get("protocol") == "TCP" and event.get("dst_port") is not None)
        return 0
