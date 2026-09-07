"""Decision agent that transforms threat events into defense decisions."""

from __future__ import annotations

from iot_defense.defense.context import build_security_context
from iot_defense.defense.decision import DefenseDecision
from iot_defense.defense.policy import DefensePolicy, RuleBasedDefensePolicy
from iot_defense.detection.threat_event import ThreatEvent


class DecisionAgent:
    """Convert threat events into contextualized decisions via a pluggable policy."""

    def __init__(self, policy: DefensePolicy | None = None) -> None:
        self.policy = policy or RuleBasedDefensePolicy()
        self._event_history: list[ThreatEvent] = []

    def build_context(self, threat_event: ThreatEvent, device_criticality: str | None = None):
        """Build BDI-style context from the current event and relevant history."""
        return build_security_context(
            threat_event,
            previous_events=self._event_history,
            device_criticality=device_criticality,
        )

    def decide(self, threat_event: ThreatEvent, device_criticality: str | None = None) -> DefenseDecision:
        """Return a structured decision for a threat event without executing actions."""
        context = self.build_context(threat_event, device_criticality=device_criticality)
        decision = self.policy.decide(context)
        self._event_history.append(threat_event)
        return decision

    def record(self, threat_event: ThreatEvent) -> None:
        """Record an event into history without evaluating a policy for it.

        Lets a caller build_context() a shared context once and evaluate
        several policies against it, while still contributing that event to
        future previous_relevant_events history exactly as decide() would.
        """
        self._event_history.append(threat_event)

    @property
    def event_history(self) -> list[ThreatEvent]:
        """Read-only view of the events recorded so far."""
        return list(self._event_history)
