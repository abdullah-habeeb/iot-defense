"""Decision agent responsible for choosing a response to suspicious activity."""

from __future__ import annotations

from typing import Any


class DecisionAgent:
    """Select a response based on a detection result and configured policy."""

    def __init__(self, default_action: str = "allow") -> None:
        self.default_action = default_action

    def decide(self, detection_result: dict[str, Any]) -> str:
        """Return the response action for the current detection result."""
        if detection_result.get("suspicious"):
            return "isolate"
        return self.default_action
