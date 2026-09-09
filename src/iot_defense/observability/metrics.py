"""Helpers for computing simple defense metrics."""

from __future__ import annotations

from typing import Any

# Actions that represent genuine containment of a threat -- i.e. the
# response actually restricts the flagged device's connectivity, rather
# than just observing (ALERT) or diverting (DECOY) it. Kept as an explicit
# set rather than "not in {allow, alert, decoy}" so a future containment
# action must be added here deliberately, the same way ISOLATE and
# THROTTLE were.
_BLOCKING_ACTIONS = {"isolate", "throttle"}


class MetricsCollector:
    """Collect counts and simple evaluation metrics over observed events."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def record(self, event: dict[str, Any]) -> None:
        self.events.append(event)

    def summary(self) -> dict[str, Any]:
        total = len(self.events)
        suspicious = sum(1 for event in self.events if event.get("suspicious"))
        blocked = sum(1 for event in self.events if event.get("action") in _BLOCKING_ACTIONS)
        return {
            "total_events": total,
            "suspicious_events": suspicious,
            "blocked_events": blocked,
        }
