"""Defense policy abstractions and baseline rule-based policy."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import yaml

from iot_defense.defense.context import SecurityContext
from iot_defense.defense.decision import DefenseAction, DefenseDecision


def _load_decision_policy_config() -> dict[str, Any]:
    config_path = Path(__file__).resolve().parents[2] / "config" / "policies.yaml"
    if not config_path.exists():
        return {}

    with config_path.open("r", encoding="utf-8") as fh:
        loaded = yaml.safe_load(fh) or {}

    return loaded.get("policy", {}).get("decision", {})


class DefensePolicy(ABC):
    """Policy interface for mapping context into a defense decision."""

    @property
    def name(self) -> str:
        return self.__class__.__name__

    @abstractmethod
    def decide(self, context: SecurityContext) -> DefenseDecision:
        """Return a defense decision from the given contextual state."""


class RuleBasedDefensePolicy(DefensePolicy):
    """Baseline configurable policy for producing explainable defense decisions."""

    def __init__(
        self,
        low_threat_score_max: float | None = None,
        recon_decoy_score_min: float | None = None,
        recon_decoy_confidence_min: float | None = None,
        severe_threat_score_min: float | None = None,
        severe_confidence_min: float | None = None,
    ) -> None:
        config = _load_decision_policy_config()
        self.low_threat_score_max = float(config.get("low_threat_score_max", low_threat_score_max if low_threat_score_max is not None else 0.2))
        self.recon_decoy_score_min = float(config.get("recon_decoy_score_min", recon_decoy_score_min if recon_decoy_score_min is not None else 0.8))
        self.recon_decoy_confidence_min = float(config.get("recon_decoy_confidence_min", recon_decoy_confidence_min if recon_decoy_confidence_min is not None else 0.8))
        self.severe_threat_score_min = float(config.get("severe_threat_score_min", severe_threat_score_min if severe_threat_score_min is not None else 0.95))
        self.severe_confidence_min = float(config.get("severe_confidence_min", severe_confidence_min if severe_confidence_min is not None else 0.95))

    def decide(self, context: SecurityContext) -> DefenseDecision:
        beliefs = context.beliefs
        attack_type = beliefs.threat_type
        threat_score = float(beliefs.threat_score)
        confidence = float(beliefs.confidence)

        if attack_type == "normal" and threat_score <= self.low_threat_score_max:
            action = DefenseAction.ALLOW
            reason = (
                "Traffic is classified as normal with very low threat score; "
                "continuing legitimate IoT service is preferred."
            )
        elif threat_score >= self.severe_threat_score_min and confidence >= self.severe_confidence_min:
            action = DefenseAction.ISOLATE
            reason = (
                "Threat score and confidence exceed severe thresholds; "
                "containment is prioritized to reduce potential impact."
            )
        elif (
            attack_type == "reconnaissance_port_scan"
            and threat_score >= self.recon_decoy_score_min
            and confidence >= self.recon_decoy_confidence_min
        ):
            action = DefenseAction.DECOY
            reason = (
                "Reconnaissance activity detected; deception is preferred to gather "
                "intelligence while avoiding immediate disruption of target services."
            )
        else:
            action = DefenseAction.ALERT
            reason = (
                "Suspicious activity observed but severity remains below isolation and "
                "deception thresholds; alerting is the least disruptive response."
            )

        return DefenseDecision.create(
            action=action,
            target_ip=beliefs.destination_device,
            source_ip=beliefs.source_device,
            reason=reason,
            confidence=confidence,
            threat_score=threat_score,
            policy_name=self.name,
            context=context.to_dict(),
        )
