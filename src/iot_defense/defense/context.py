"""BDI-style security context model for explainable policy decisions.

This module provides a lightweight and explicit state representation.
It is intentionally not a full cognitive BDI framework.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from iot_defense.detection.threat_event import ThreatEvent


@dataclass(slots=True)
class Beliefs:
    """Observed beliefs derived from the latest threat event."""

    threat_type: str
    threat_score: float
    confidence: float
    source_device: str
    destination_device: str
    observed_features: dict[str, Any] = field(default_factory=dict)
    device_criticality: str = "unknown"
    previous_relevant_events: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class Desires:
    """Security objectives used to shape the selected intention."""

    protect_legitimate_iot_service: bool = True
    contain_malicious_activity: bool = True
    minimize_unnecessary_disruption: bool = True
    gather_attacker_intelligence_when_appropriate: bool = True


@dataclass(slots=True)
class SecurityContext:
    """Structured context that makes decision logic explicit and explainable."""

    beliefs: Beliefs
    desires: Desires
    intention: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_security_context(
    threat_event: ThreatEvent,
    *,
    previous_events: list[ThreatEvent] | None = None,
    device_criticality: str | None = None,
) -> SecurityContext:
    """Build a lightweight BDI-style context from a threat event."""
    prior = previous_events or []
    belief_history = [
        {
            "timestamp": event.timestamp,
            "attack_type": event.attack_type,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "threat_score": event.threat_score,
            "confidence": event.confidence,
        }
        for event in prior[-5:]
    ]

    beliefs = Beliefs(
        threat_type=threat_event.attack_type,
        threat_score=float(threat_event.threat_score),
        confidence=float(threat_event.confidence),
        source_device=threat_event.source_ip,
        destination_device=threat_event.destination_ip,
        observed_features=dict(threat_event.features),
        device_criticality=device_criticality or "unknown",
        previous_relevant_events=belief_history,
    )

    if beliefs.threat_type == "normal":
        intention = "protect_legitimate_iot_service"
    elif beliefs.threat_score >= 0.95 and beliefs.confidence >= 0.95:
        intention = "contain_malicious_activity"
    elif beliefs.threat_type == "reconnaissance_port_scan":
        intention = "gather_attacker_intelligence_when_appropriate"
    else:
        intention = "minimize_unnecessary_disruption"

    return SecurityContext(beliefs=beliefs, desires=Desires(), intention=intention)
