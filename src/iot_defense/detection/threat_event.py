"""Threat event model used to describe detected security events."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class ThreatEvent:
    """Structured threat representation for downstream decision-making."""

    timestamp: str
    source_ip: str
    destination_ip: str
    attack_type: str
    threat_score: float
    confidence: float
    detection_reason: str
    features: dict[str, Any] = field(default_factory=dict)
    detector_name: str = "unknown"

    @classmethod
    def from_result(cls, *, source_ip: str, destination_ip: str, attack_type: str, threat_score: float, confidence: float, detection_reason: str, features: dict[str, Any], detector_name: str = "unknown") -> "ThreatEvent":
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_ip=source_ip,
            destination_ip=destination_ip,
            attack_type=attack_type,
            threat_score=float(threat_score),
            confidence=float(confidence),
            detection_reason=detection_reason,
            features=features,
            detector_name=detector_name,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
