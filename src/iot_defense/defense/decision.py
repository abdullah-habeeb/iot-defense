"""Typed defense decision model produced by decision policies."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class DefenseAction(str, Enum):
    """Allowed defense actions for the current decision phase.

    Every dependent module (Stackelberg's DEFENDER_STRATEGIES, PPO's
    action space/observation size in ppo_env.py, the dashboard's action
    badge styling) derives its size and iteration order from this enum
    directly rather than a hardcoded count -- appending a member here is
    enough to make it selectable everywhere except config/policies.yaml's
    own Stackelberg payoff numbers, which are genuine judgment calls, not
    something to auto-generate, and attacks/registry.py's per-scenario
    preferred_action, which is a deliberate per-attack design choice.
    """

    ALLOW = "ALLOW"
    ALERT = "ALERT"
    ISOLATE = "ISOLATE"
    DECOY = "DECOY"
    THROTTLE = "THROTTLE"
    BLOCK_SOURCE = "BLOCK_SOURCE"
    QUARANTINE = "QUARANTINE"
    RESET_SESSIONS = "RESET_SESSIONS"
    FORENSIC_CAPTURE = "FORENSIC_CAPTURE"
    BANDWIDTH_CAP = "BANDWIDTH_CAP"


@dataclass(slots=True)
class DefenseDecision:
    """Explainable output of a defense policy."""

    action: DefenseAction
    target_ip: str
    source_ip: str
    reason: str
    confidence: float
    threat_score: float
    policy_name: str
    timestamp: str
    context: dict[str, Any]

    @classmethod
    def create(
        cls,
        *,
        action: DefenseAction,
        target_ip: str,
        source_ip: str,
        reason: str,
        confidence: float,
        threat_score: float,
        policy_name: str,
        context: dict[str, Any],
    ) -> "DefenseDecision":
        return cls(
            action=action,
            target_ip=target_ip,
            source_ip=source_ip,
            reason=reason,
            confidence=float(confidence),
            threat_score=float(threat_score),
            policy_name=policy_name,
            timestamp=datetime.now(timezone.utc).isoformat(),
            context=context,
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["action"] = self.action.value
        return data
