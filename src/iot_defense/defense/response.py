"""Concrete response handlers for the foundation prototype."""

from __future__ import annotations

from typing import Any


class ResponseHandler:
    """Apply a chosen defense response to the suspicious source."""

    def apply(self, action: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return a minimal action record containing the response result."""
        context = context or {}
        response = {
            "action": action,
            "target": context.get("src_ip", "unknown"),
            "status": "executed",
        }
        if action == "isolate":
            response["status"] = "isolated"
        elif action == "decoy":
            response["status"] = "decoy_redirected"
        return response
