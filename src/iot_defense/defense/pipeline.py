"""Policy evaluation shared by the lab demo and the live defender.

Both ask the same question of the same security context: what do the three
policies propose, and which proposal runs? The live defender adds one
constraint the Mininet lab does not have: a real device can only perform the
responses its backend implements (no decoy host, for instance), so proposals
for unavailable actions are set aside before the arbiter chooses, and the
dashboard is told which ones and why. With policy.arbiter.consider_all_supported the arbiter also scores every
action the device CAN perform, so a policy that proposed something unavailable no longer forces a fallback to ALERT
when a performable action has better measured evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from iot_defense.defense.arbiter import ARBITER_NAME, ArbiterPolicy, select_decision
from iot_defense.defense.decision import DefenseAction, DefenseDecision

DEFAULT_PPO_MODEL_PATH = "models/ppo_defense"


def compute_proposals(
    context: Any, ppo_model_path: str = DEFAULT_PPO_MODEL_PATH
) -> tuple[dict[str, Any], DefenseDecision, DefenseDecision | None, DefenseDecision | None]:
    """Evaluate all three policies against the same security context."""
    from iot_defense.defense.policy import RuleBasedDefensePolicy, StackelbergDefensePolicy

    rule_policy = RuleBasedDefensePolicy()
    stack_policy = StackelbergDefensePolicy()

    # rule_decision is the actual fallback target when Stackelberg
    # fails (see the selection logic in the callers) -- deliberately not
    # wrapped in its own try/except, since there is nothing further
    # to fall back to if the fallback itself raises.
    rule_decision = rule_policy.decide(context)
    stack_decision = None
    stackelberg_reasoning: dict[str, Any] = {}
    stackelberg_fallback_used = False
    try:
        stack_decision = stack_policy.decide(context)
        stackelberg_reasoning = stack_decision.context.get("stackelberg_reasoning", {})
    except Exception as exc:  # noqa: BLE001
        # A real fallback, not just a comment claiming one exists --
        # found during a system review that this branch never
        # existed: selected decision was unconditionally
        # stack_decision, so a raising StackelbergDefensePolicy would
        # abort the whole run instead of actually falling back.
        print(f"[DemoController] Stackelberg decide error: {exc}")
        stackelberg_fallback_used = True

    # PPO – load if model exists, else fall back to rule-based
    ppo_decision = None
    ppo_fallback_used = False
    try:
        from iot_defense.defense.ppo_policy import PPODefensePolicy

        ppo = PPODefensePolicy(model_path=ppo_model_path, fallback=RuleBasedDefensePolicy())
        ppo_decision = ppo.decide(context)
        ppo_fallback_used = ppo.model is None
    except Exception as exc:  # noqa: BLE001
        print(f"[DemoController] PPO load error: {exc}")

    comparison: dict[str, Any] = {
        "rule_based": rule_decision.to_dict(),
        "stackelberg": stack_decision.to_dict() if stack_decision else None,
        "stackelberg_reasoning": stackelberg_reasoning,
        "stackelberg_fallback_used": stackelberg_fallback_used,
        "ppo": ppo_decision.to_dict() if ppo_decision else None,
        "ppo_fallback_used": ppo_fallback_used,
    }
    return comparison, rule_decision, stack_decision, ppo_decision


def arbitrate_for_device(
    arbiter: ArbiterPolicy | None,
    label: str,
    proposals: dict[str, DefenseDecision],
    supported: Iterable[DefenseAction] | None,
    reasons: dict[DefenseAction, str] | None = None,
) -> tuple[DefenseDecision | None, dict[str, DefenseDecision], dict[str, str]]:
    """Set aside proposals the device cannot perform, then let the arbiter choose.

    Returns (the arbiter's decision or None, the proposals the device can perform, {policy: action set aside}).
    When every proposal was set aside the arbiter can still choose among the actions the device can perform
    (policy.arbiter.consider_all_supported); a set-aside proposal then only lends its target, source and context
    to the decision it executes. The decision is None when there is no arbiter, nothing is available to choose
    among, or no candidate has measured evidence and no available proposal to fall back to.

    The decision's reasoning also lists each set-aside action under "unavailable" with who proposed it, its measured
    evidence (so the dashboard can show that a better-measured response exists but cannot be applied) and, from
    `reasons`, why this device cannot apply it."""
    allowed = frozenset(supported) if supported is not None else None
    kept = dict(proposals)
    dropped: dict[str, DefenseDecision] = {}
    if allowed is not None:
        for name, decision in list(kept.items()):
            if decision.action not in allowed:
                dropped[name] = kept.pop(name)
    excluded = {name: decision.action.value for name, decision in dropped.items()}
    if arbiter is None:
        return None, kept, excluded
    template = next(iter(dropped.values()), None) if dropped and not kept else None
    if not kept and not (arbiter.consider_all_supported and template is not None):
        return None, kept, excluded
    try:
        decision = arbiter.arbitrate(label, kept, available=allowed, template=template)
    except ValueError:
        return None, kept, excluded
    reasoning = decision.context["arbiter_reasoning"]
    reasoning["excluded_unavailable"] = excluded
    by_action: dict[DefenseAction, list[str]] = {}
    for name, dropped_decision in dropped.items():
        by_action.setdefault(dropped_decision.action, []).append(name)
    reasoning["unavailable"] = sorted(
        (
            {"action": action.value, "proposed_by": names, "evidence": arbiter.score_action(label, action), "reason": (reasons or {}).get(action)}
            for action, names in by_action.items()
        ),
        key=lambda u: -u["evidence"]["score"] if u["evidence"] else float("inf"),
    )
    return decision, kept, excluded


@dataclass
class PolicyEvaluation:
    comparison: dict[str, Any]
    selected: DefenseDecision
    arbiter: DefenseDecision | None = None
    excluded: dict[str, str] = field(default_factory=dict)
    """Policy name -> the action it proposed that this device cannot perform."""


class PolicyPipeline:
    """Propose with all three policies, drop what the device cannot do, choose."""

    def __init__(
        self,
        policy_mode: str = "arbiter",
        *,
        supported_actions: Iterable[DefenseAction] | None = None,
        arbiter: ArbiterPolicy | None = None,
        ppo_model_path: str = DEFAULT_PPO_MODEL_PATH,
        arbiter_consider_all: bool | None = None,
        unavailable_reasons: dict[DefenseAction, str] | None = None,
    ) -> None:
        from iot_defense.defense.arbiter import POLICY_MODES

        if policy_mode not in POLICY_MODES:
            raise ValueError(f"unknown policy mode {policy_mode!r}; expected one of {POLICY_MODES}")
        self.policy_mode = policy_mode
        self.supported = frozenset(supported_actions) if supported_actions is not None else None
        self.ppo_model_path = ppo_model_path
        self._arbiter = arbiter
        self._arbiter_loaded = arbiter is not None
        self._arbiter_consider_all = arbiter_consider_all  # None: use policy.arbiter.consider_all_supported
        self.unavailable_reasons = unavailable_reasons or {}

    def _load_arbiter(self) -> ArbiterPolicy | None:
        if not self._arbiter_loaded:
            try:
                self._arbiter = ArbiterPolicy.from_config(consider_all_supported=self._arbiter_consider_all)
            except Exception as exc:  # noqa: BLE001
                print(f"[PolicyPipeline] arbiter unavailable: {exc}", flush=True)
            if self._arbiter is None:
                print("[PolicyPipeline] no measured outcome table found -- using Stackelberg instead", flush=True)
            self._arbiter_loaded = True
        return self._arbiter

    def decide(self, context: Any) -> PolicyEvaluation:
        comparison, rule, stack, ppo = compute_proposals(context, self.ppo_model_path)
        proposals = {
            name: decision
            for name, decision in (("rule_based", rule), ("stackelberg", stack), ("ppo", ppo))
            if decision is not None
        }
        arbiter = self._load_arbiter() if self.policy_mode == "arbiter" else None
        arbiter_decision, proposals, excluded = arbitrate_for_device(
            arbiter, context.beliefs.threat_type, proposals, self.supported, self.unavailable_reasons
        )
        if arbiter_decision is not None:
            comparison["arbiter"] = arbiter_decision.to_dict()
        comparison["excluded_unavailable"] = excluded

        try:
            selected = select_decision(
                self.policy_mode,
                rule=proposals.get("rule_based"),
                stackelberg=proposals.get("stackelberg"),
                ppo=proposals.get("ppo"),
                arbiter=arbiter_decision,
            )
        except ValueError:
            # Nothing the device can do was proposed: record the event, change nothing.
            beliefs = context.beliefs
            selected = DefenseDecision.create(
                action=DefenseAction.ALERT,
                target_ip=beliefs.destination_device,
                source_ip=beliefs.source_device,
                reason="None of the policies proposed an action this device can perform; alerting only.",
                confidence=beliefs.confidence,
                threat_score=beliefs.threat_score,
                policy_name="LiveSafeFallback",
                context={},
            )
        return PolicyEvaluation(comparison=comparison, selected=selected, arbiter=arbiter_decision, excluded=excluded)


__all__ = ["ARBITER_NAME", "PolicyEvaluation", "PolicyPipeline", "arbitrate_for_device", "compute_proposals"]
