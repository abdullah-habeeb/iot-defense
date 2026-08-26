"""Placeholder decoy adapter for future deception extensions."""

from __future__ import annotations

from typing import Any


class DecoyService:
    """A minimal decoy placeholder that can be extended later to Cowrie or Honeyd-style services."""

    def __init__(self, service_name: str = "mock_decoy") -> None:
        self.service_name = service_name

    def activate(self, target_ip: str) -> dict[str, Any]:
        """Activate a decoy for a suspicious address."""
        return {
            "service": self.service_name,
            "target_ip": target_ip,
            "status": "active",
        }
