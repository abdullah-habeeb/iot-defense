"""Synthetic traffic generation for the foundation prototype."""

from __future__ import annotations

from typing import Any


class TrafficGenerator:
    """Generate a small set of benign and malicious traffic events for testing."""

    def __init__(self) -> None:
        self._normal_event = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.3",
            "protocol": "TCP",
            "packet_length": 140,
            "ttl": 64,
            "src_port": 5000,
            "dst_port": 80,
            "timestamp": 1.0,
            "direction": "outbound",
        }

        self._malicious_event = {
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.2",
            "protocol": "ICMP",
            "packet_length": 2500,
            "ttl": 32,
            "src_port": 0,
            "dst_port": 22,
            "timestamp": 2.0,
            "direction": "inbound",
        }

    def generate(self) -> dict[str, list[dict[str, Any]]]:
        """Return a batch of normal and malicious traffic events."""
        return {
            "normal": [self._normal_event],
            "malicious": [self._malicious_event],
        }
