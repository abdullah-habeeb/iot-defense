"""Deliberately non-adaptive baseline policies for the evaluation harness.

Neither baseline reads a registered attack's own preferred_action -- doing
so would make them just another view of our own system's judgment, not an
independent point of comparison. They represent what a defense system
looks like *without* per-attack-type differentiation, which is exactly
what comparing our 3-policy system against them is meant to measure the
value of.
"""

from __future__ import annotations

from iot_defense.defense.context import SecurityContext
from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.policy import DefensePolicy


class AlwaysAllowBaseline(DefensePolicy):
    """Never intervenes, regardless of threat -- the floor: whatever an
    attack accomplishes when nothing detects or blocks it."""

    def decide(self, context: SecurityContext) -> DefenseDecision:
        beliefs = context.beliefs
        return DefenseDecision.create(
            action=DefenseAction.ALLOW,
            target_ip=beliefs.destination_device,
            source_ip=beliefs.source_device,
            reason="Baseline: never intervenes regardless of threat.",
            confidence=beliefs.confidence,
            threat_score=beliefs.threat_score,
            policy_name=self.name,
            context=context.to_dict(),
        )


class NaiveBlockAllBaseline(DefensePolicy):
    """Any non-normal detection -> ISOLATE, regardless of attack type.

    Represents the common "single fixed response" design many simple
    detect-and-block systems use: one blunt response to every alert, no
    per-attack differentiation. This is what our 3-policy system's
    per-attack preferred_action (THROTTLE for brute-force, DECOY for
    reconnaissance/exploit, ISOLATE for dos/exfiltration) is meant to
    improve on -- containment without regard for whether a lighter,
    equally effective response existed.
    """

    def decide(self, context: SecurityContext) -> DefenseDecision:
        beliefs = context.beliefs
        is_normal = beliefs.threat_type == "normal"
        action = DefenseAction.ALLOW if is_normal else DefenseAction.ISOLATE
        reason = (
            "Baseline: normal traffic allowed."
            if is_normal
            else "Baseline: any detected threat is isolated outright, regardless of attack type."
        )
        return DefenseDecision.create(
            action=action,
            target_ip=beliefs.destination_device,
            source_ip=beliefs.source_device,
            reason=reason,
            confidence=beliefs.confidence,
            threat_score=beliefs.threat_score,
            policy_name=self.name,
            context=context.to_dict(),
        )
