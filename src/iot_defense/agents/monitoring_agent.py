"""Monitoring agent responsible for observing and packaging events."""

from __future__ import annotations

from typing import Any


class MonitoringAgent:
    """Collect observations from the simulated environment into a normalized event."""

    def observe(self, packet: dict[str, Any]) -> dict[str, Any]:
        """Normalize a raw packet-like event to a minimal monitoring observation."""
        return {
            "src_ip": packet.get("src_ip", "unknown"),
            "dst_ip": packet.get("dst_ip", "unknown"),
            "protocol": packet.get("protocol", "UNKNOWN"),
            "packet_length": int(packet.get("packet_length", 0)),
            "ttl": int(packet.get("ttl", 0)),
            "src_port": packet.get("src_port"),
            "dst_port": packet.get("dst_port"),
            "timestamp": float(packet.get("timestamp", 0.0)),
            "direction": packet.get("direction", "unknown"),
        }
