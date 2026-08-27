"""Structured results emitted by response execution."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from iot_defense.defense.decision import DefenseAction


@dataclass(slots=True)
class ResponseResult:
    """Outcome and timing information for one simulated response."""

    action: DefenseAction
    target_ip: str
    source_ip: str
    status: str
    started_at: str
    completed_at: str
    latency_ms: float
    message: str
    details: dict[str, Any]

    @classmethod
    def from_timing(
        cls,
        *,
        action: DefenseAction,
        target_ip: str,
        source_ip: str,
        status: str,
        started_at: str,
        latency_ms: float,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> "ResponseResult":
        return cls(
            action=action,
            target_ip=target_ip,
            source_ip=source_ip,
            status=status,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc).isoformat(),
            latency_ms=float(latency_ms),
            message=message,
            details=details or {},
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["action"] = self.action.value
        return data
