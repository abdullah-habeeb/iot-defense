"""Helpers for computing simple defense metrics."""

from __future__ import annotations

from typing import Any


class MetricsCollector:
    """Collect counts and simple evaluation metrics over observed events."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def record(self, event: dict[str, Any]) -> None:
        self.events.append(event)

    def summary(self) -> dict[str, Any]:
        total = len(self.events)
        suspicious = sum(1 for event in self.events if event.get("suspicious"))
        blocked = sum(1 for event in self.events if event.get("action") == "isolate")
        return {
            "total_events": total,
            "suspicious_events": suspicious,
            "blocked_events": blocked,
        }
