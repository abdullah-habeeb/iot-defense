"""Stable-Baselines3 PPO policy adapter for SecurityContext."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from iot_defense.defense.context import SecurityContext
from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.policy import DefensePolicy
from iot_defense.defense.ppo_env import DefenseDecisionEnv, INDEX_TO_ACTION, SecurityContextEncoder


class PPODefensePolicy(DefensePolicy):
    """Use a trained PPO model, with an explicit optional policy fallback."""

    def __init__(
        self,
        model_path: str | Path = "models/ppo_defense",
        fallback: DefensePolicy | None = None,
    ) -> None:
        self.model_path = Path(model_path)
        self.fallback = fallback
        self.encoder = SecurityContextEncoder()
        self.model: Any = None
        if self.model_path.with_suffix(".zip").exists() or self.model_path.exists():
            from stable_baselines3 import PPO

            self.model = PPO.load(str(self.model_path), device="cpu")
        elif fallback is None:
            raise FileNotFoundError(
                f"Trained PPO model not found at {self.model_path}. "
                "Train it first or pass an explicit fallback DefensePolicy."
            )

    def decide(self, context: SecurityContext, stackelberg_info: dict[str, Any] | None = None) -> DefenseDecision:
        if self.model is None:
            decision = self.fallback.decide(context)
            decision_context = dict(decision.context)
            decision_context["ppo_fallback"] = self.fallback.name
            return DefenseDecision.create(
                action=decision.action,
                target_ip=decision.target_ip,
                source_ip=decision.source_ip,
                reason=f"PPO model unavailable; explicit fallback policy selected this action. {decision.reason}",
                confidence=decision.confidence,
                threat_score=decision.threat_score,
                policy_name=self.name,
                context=decision_context,
            )
        observation = self.encoder.encode(context, stackelberg_info=stackelberg_info)
        action_index, _ = self.model.predict(observation, deterministic=True)
        action_index = int(action_index)
        if action_index not in INDEX_TO_ACTION:
            raise ValueError(f"PPO returned invalid defense action index: {action_index}")
        action = INDEX_TO_ACTION[action_index]
        return DefenseDecision.create(
            action=action,
            target_ip=context.beliefs.destination_device,
            source_ip=context.beliefs.source_device,
            reason=f"Action selected by trained adaptive PPO policy from the encoded security context: {action.value}.",
            confidence=context.beliefs.confidence,
            threat_score=context.beliefs.threat_score,
            policy_name=self.name,
            context={**context.to_dict(), "ppo_observation": observation.tolist(), "ppo_action_index": action_index},
        )


def create_training_environment() -> DefenseDecisionEnv:
    """Factory kept separate so PPO training never depends on Mininet."""
    return DefenseDecisionEnv()
