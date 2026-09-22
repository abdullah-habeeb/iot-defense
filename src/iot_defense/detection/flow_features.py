"""Feature aggregation for packet flows and traffic windows."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from ipaddress import ip_address
from typing import Any

# TCP flag bit positions (RFC 793) -- used to tell SYN/ACK packets apart from
# a real "tcp_flags" event field, not from port presence (every TCP packet,
# real or refused, carries a source and destination port).
_TCP_FLAG_SYN = 0x02
_TCP_FLAG_ACK = 0x10


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
    # Coefficient of variation (stddev / mean) of consecutive inter-packet
    # arrival gaps within this flow -- a real timing-regularity signal,
    # not a rate/size/count one, so it can catch what none of the
    # detectors above can: a device that talks to the same destination on
    # a near-perfectly regular schedule (classic C2 beaconing) looks
    # completely ordinary on every other axis here -- low volume, modest
    # size, nothing a rate or port-count threshold would ever flag. A
    # value near 0.0 means near-uniform spacing (suspicious); real organic
    # or bursty traffic has a much higher one. 999.0 (not 0.0) is the
    # default/insufficient-data sentinel deliberately -- fewer than 3
    # packets can't produce a real variance, and 0.0 would misread as
    # "perfectly regular" instead of "no signal", the opposite of what a
    # too-short flow actually tells you.
    inter_arrival_cv: float = 999.0
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
            # protocol here is already the uppercased grouping key (see
            # the loop above), not a re-read of each event's own raw
            # field -- found by a system review that these four
            # counters used to compare event.get("protocol") directly,
            # case-sensitively, against the grouping key's own
            # normalized value: every current real producer already
            # emits uppercase so this was dormant, but a future lower/
            # mixed-case source would have silently zeroed all four
            # counters (fail-open, not fail-loud) despite the flow
            # itself being correctly grouped as that protocol.
            tcp_syn_count = sum(
                1 for event in group
                if protocol == "TCP" and (event.get("tcp_flags") or 0) & _TCP_FLAG_SYN
            )
            tcp_ack_count = sum(
                1 for event in group
                if protocol == "TCP" and (event.get("tcp_flags") or 0) & _TCP_FLAG_ACK
            )
            udp_packet_count = sum(1 for event in group if protocol == "UDP")
            icmp_packet_count = sum(1 for event in group if protocol == "ICMP")
            inter_arrival_cv = self._interarrival_cv(timestamps)

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
                    inter_arrival_cv=inter_arrival_cv,
                    window_start=start,
                    window_end=end,
                    metadata={"event_count": packet_count},
                )
            )
        return features

    @staticmethod
    def _interarrival_cv(timestamps: list[float]) -> float:
        """Coefficient of variation of consecutive inter-packet gaps --
        see FlowFeatures.inter_arrival_cv's own field comment for what a
        low vs. high value means and why the insufficient-data default is
        999.0, not 0.0."""
        ordered = sorted(timestamps)
        if len(ordered) < 3:
            return 999.0
        gaps = [ordered[i + 1] - ordered[i] for i in range(len(ordered) - 1)]
        mean_gap = sum(gaps) / len(gaps)
        if mean_gap <= 0:
            return 999.0
        variance = sum((gap - mean_gap) ** 2 for gap in gaps) / len(gaps)
        return (variance ** 0.5) / mean_gap

    def calculate_packets_per_second(self, events: list[dict[str, Any]]) -> float:
        """Kept consistent with aggregate()'s own inline packets_per_second
        computation on purpose -- found by a system review that this
        public helper's zero-duration fallback (float(len(events)), i.e.
        the raw packet count) silently disagreed with aggregate()'s own
        real path (0.0), which would have misreported an ordinary
        single-packet or simultaneous-timestamp flow as an extreme rate
        for any caller reaching for this method instead of .aggregate().
        No such caller currently exists, but the disagreement itself was
        the bug worth closing, not just documenting.
        """
        if not events:
            return 0.0
        timestamps = [float(event.get("timestamp", 0.0)) for event in events]
        duration = max(max(timestamps) - min(timestamps), 0.0)
        return (len(events) / duration) if duration > 0 else 0.0

    def calculate_unique_ports(self, events: list[dict[str, Any]], field_name: str) -> int:
        values = {event.get(field_name) for event in events if event.get(field_name) is not None}
        return len(values)

    def count_tcp_flags(self, events: list[dict[str, Any]], flag_name: str) -> int:
        bit = {"syn": _TCP_FLAG_SYN, "ack": _TCP_FLAG_ACK}.get(flag_name)
        if bit is None:
            return 0
        return sum(
            1 for event in events
            if event.get("protocol") == "TCP" and (event.get("tcp_flags") or 0) & bit
        )
