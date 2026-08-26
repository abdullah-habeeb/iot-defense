"""Simple policy definition for response selection."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DefensePolicy:
    """Configuration for defense actions and runtime thresholds."""

    default_action: str = "allow"
    suspicious_threshold: float = 0.75
    response_actions: list[str] = field(default_factory=lambda: ["allow", "alert", "isolate", "decoy"])
    isolation_timeout_seconds: int = 15

    def is_allowed(self, action: str) -> bool:
        return action in self.response_actions
