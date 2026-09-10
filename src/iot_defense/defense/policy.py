"""Defense policy abstractions and baseline rule-based policy."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import yaml

from iot_defense.defense.context import SecurityContext
from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.stackelberg import StackelbergGame

# ATTACK_SCENARIOS is imported lazily inside __init__/decide below, not at
# module level: this module is eagerly imported by iot_defense.defense's
# own package __init__, which the registry itself pulls in while building
# ATTACK_SCENARIOS -- a top-level import here would deadlock that cycle.


def _load_decision_policy_config() -> dict[str, Any]:
    # parents[2] from src/iot_defense/defense/policy.py is src/, not the
    # repo root -- a real, previously silent bug found via a live check:
    # config_path.exists() was always False, so this function always
    # returned {} and every value below always fell back to its hardcoded
    # default, never the YAML's own. Behaviorally invisible only because
    # every hardcoded default here (and every ATTACK_SCENARIOS registry
    # default action_score_min/action_confidence_min consulted below) had
    # been kept numerically in sync with config/policies.yaml by hand --
    # but editing the YAML's policy.decision section had silently done
    # nothing at all until this fix.
    config_path = Path(__file__).resolve().parents[3] / "config" / "policies.yaml"
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

    # The two originally hand-written attacks kept their existing config-key
    # names (recon_decoy_*, dos_isolate_*) for backward compatibility with
    # config/policies.yaml; any newly registered attack without an entry
    # here falls back to a generic "<key>_score_min"/"<key>_confidence_min"
    # config key, or its registry defaults if that isn't configured either.
    _LEGACY_CONFIG_KEYS = {
        "reconnaissance": ("recon_decoy_score_min", "recon_decoy_confidence_min"),
        "dos": ("dos_isolate_score_min", "dos_isolate_confidence_min"),
    }

    def __init__(
        self,
        low_threat_score_max: float | None = None,
        severe_threat_score_min: float | None = None,
        severe_confidence_min: float | None = None,
        action_thresholds: dict[str, tuple[float, float]] | None = None,
    ) -> None:
        from iot_defense.attacks.registry import ATTACK_SCENARIOS

        self._attack_scenarios = ATTACK_SCENARIOS
        config = _load_decision_policy_config()
        self.low_threat_score_max = float(config.get("low_threat_score_max", low_threat_score_max if low_threat_score_max is not None else 0.2))
        self.severe_threat_score_min = float(config.get("severe_threat_score_min", severe_threat_score_min if severe_threat_score_min is not None else 0.95))
        self.severe_confidence_min = float(config.get("severe_confidence_min", severe_confidence_min if severe_confidence_min is not None else 0.95))

        if action_thresholds is not None:
            self.action_thresholds = dict(action_thresholds)
        else:
            self.action_thresholds = {}
            for key, scenario in ATTACK_SCENARIOS.items():
                score_key, confidence_key = self._LEGACY_CONFIG_KEYS.get(
                    key, (f"{key}_score_min", f"{key}_confidence_min")
                )
                score_min = float(config.get(score_key, scenario.action_score_min))
                confidence_min = float(config.get(confidence_key, scenario.action_confidence_min))
                self.action_thresholds[key] = (score_min, confidence_min)

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
        else:
            matched_scenario = next(
                (
                    scenario
                    for key, scenario in self._attack_scenarios.items()
                    if scenario.attack_type == attack_type
                    and threat_score >= self.action_thresholds[key][0]
                    and confidence >= self.action_thresholds[key][1]
                ),
                None,
            )
            if matched_scenario is not None:
                action = matched_scenario.preferred_action
                reason = (
                    f"{matched_scenario.label} activity detected with threat score and confidence "
                    f"above its action thresholds; {action.value} is the configured preferred response."
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


class StackelbergDefensePolicy(DefensePolicy):
    """Select a defense action using a simplified configurable leader-follower game."""

    def __init__(self, game: StackelbergGame | None = None) -> None:
        self.game = game or StackelbergGame()

    def decide(self, context: SecurityContext) -> DefenseDecision:
        beliefs = context.beliefs
        observed_threat = beliefs.threat_type.upper()
        solution = self.game.solve(observed_threat)
        reasoning = solution.to_dict()
        reason = (
            f"Observed threat: {observed_threat}. Defender candidate: {solution.selected_action.value}. "
            f"Predicted attacker response: {solution.predicted_attacker_strategy}. "
            f"Attacker utility: {solution.selected_attacker_utility:g}. "
            f"Defender utility: {solution.selected_defender_utility:g}. "
            f"Selected defense: {solution.selected_action.value}."
        )
        decision_context = context.to_dict()
        decision_context["stackelberg_reasoning"] = reasoning
        return DefenseDecision.create(
            action=solution.selected_action,
            target_ip=beliefs.destination_device,
            source_ip=beliefs.source_device,
            reason=reason,
            confidence=beliefs.confidence,
            threat_score=beliefs.threat_score,
            policy_name=self.name,
            context=decision_context,
        )


def compare_policies(
    context: SecurityContext,
    rule_policy: RuleBasedDefensePolicy | None = None,
    stackelberg_policy: StackelbergDefensePolicy | None = None,
    ppo_policy: DefensePolicy | None = None,
) -> dict[str, Any]:
    """Evaluate configured policies against the same context without executing actions."""
    rule_decision = (rule_policy or RuleBasedDefensePolicy()).decide(context)
    stack_decision = (stackelberg_policy or StackelbergDefensePolicy()).decide(context)
    reasoning = stack_decision.context["stackelberg_reasoning"]
    comparison = {
        "same_context": rule_decision.context["beliefs"] == context.to_dict()["beliefs"],
        "observed_threat": reasoning["observed_threat"],
        "rule_based_action": rule_decision.action.value,
        "stackelberg_action": stack_decision.action.value,
        "predicted_attacker_response": reasoning["predicted_attacker_strategy"],
        "defender_utility": reasoning["selected_defender_utility"],
        "rule_based_decision": rule_decision.to_dict(),
        "stackelberg_decision": stack_decision.to_dict(),
    }
    if ppo_policy is not None:
        ppo_decision = ppo_policy.decide(context, stackelberg_info=reasoning)
        comparison["ppo_action"] = ppo_decision.action.value
        comparison["ppo_decision"] = ppo_decision.to_dict()
    return comparison
