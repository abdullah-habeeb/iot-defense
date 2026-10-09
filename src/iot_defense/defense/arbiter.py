"""Execute the proposal with the best measured evidence of working.

The three policies (rule-based, Stackelberg, PPO) each propose an action for
the same context. The arbiter does not pick a favourite policy: it scores each
proposed ACTION by what was measured when that action was applied against this
kind of attack in live Mininet (evaluation/outcome_table.py) -- the mean
realized utility, minus a penalty proportional to its run-to-run spread so an
erratic action loses to a dependable one -- and executes the best-scoring
proposal. It can only choose among the proposals it is given, and it never
reads a registered preferred_action.

With no usable evidence for any proposal (an attack label never measured, or a
missing table) it falls back to the first available policy in `fallback_order`
and says so in its reasoning.
"""

from __future__ import annotations

import statistics
from pathlib import Path
from typing import TYPE_CHECKING, Any

from iot_defense.defense.decision import DefenseDecision
from iot_defense.defense.objective import load_policy_section

if TYPE_CHECKING:
    from iot_defense.evaluation.outcome import OutcomeTable

ARBITER_NAME = "ArbiterPolicy"
TIE_EPSILON = 1e-9


class ArbiterPolicy:
    def __init__(
        self,
        table: "OutcomeTable",
        *,
        risk_aversion: float = 1.0,
        min_samples: int = 2,
        fallback_order: tuple[str, ...] = ("stackelberg", "ppo", "rule_based"),
    ) -> None:
        self.table = table
        self.risk_aversion = risk_aversion
        self.min_samples = min_samples
        self.fallback_order = fallback_order

    @classmethod
    def from_config(cls) -> "ArbiterPolicy | None":
        """Build from policy.arbiter; None when the measured outcome table is
        not available (the caller then falls back to a single policy)."""
        from iot_defense.evaluation.outcome import OutcomeTable

        config = load_policy_section("arbiter")
        path = Path(config["outcome_table_path"])
        if not path.is_absolute():
            path = Path(__file__).resolve().parents[3] / path
        if not path.exists():
            return None
        return cls(
            OutcomeTable.from_jsonl(path),
            risk_aversion=float(config["risk_aversion"]),
            min_samples=int(config["min_samples"]),
        )

    def score(self, label: str, decision: DefenseDecision) -> dict[str, float | int] | None:
        """Evidence for one proposal: measured mean utility, spread and the
        risk-adjusted score; None when too few valid measurements exist."""
        samples = self.table.samples(label, decision.action)
        if len(samples) < self.min_samples:
            return None
        mean = statistics.fmean(samples)
        spread = statistics.pstdev(samples)
        return {"mean": mean, "sd": spread, "n": len(samples), "score": mean - self.risk_aversion * spread}

    def arbitrate(self, label: str, proposals: dict[str, DefenseDecision]) -> DefenseDecision:
        """Choose among `proposals` (policy name -> its decision) for an attack
        the detector labelled `label`."""
        if not proposals:
            raise ValueError("arbitrate() needs at least one proposal")
        evidence = {name: self.score(label, decision) for name, decision in proposals.items()}
        scored = {name: e for name, e in evidence.items() if e is not None}
        order = {name: index for index, name in enumerate(self.fallback_order)}

        def rank(name: str) -> int:
            return order.get(name, len(order))

        if scored:
            best = max(e["score"] for e in scored.values())
            winner = min((n for n, e in scored.items() if e["score"] >= best - TIE_EPSILON), key=rank)
            basis = "measured evidence"
        else:
            winner = min(proposals, key=rank)
            basis = "no measured evidence for any proposal -- fell back to " + winner

        chosen = proposals[winner]
        lines = []
        for name, decision in sorted(proposals.items(), key=lambda kv: rank(kv[0])):
            e = evidence[name]
            detail = (
                f"measured utility {e['mean']:.2f}+/-{e['sd']:.2f} over {e['n']} runs (risk-adjusted {e['score']:.2f})"
                if e is not None
                else "no measurements"
            )
            lines.append(f"{decision.action.value} from {name}: {detail}")
        reasoning: dict[str, Any] = {
            "label": label,
            "chosen_from": winner,
            "basis": basis,
            "risk_aversion": self.risk_aversion,
            "proposals": {
                name: {"action": decision.action.value, "evidence": evidence[name]}
                for name, decision in proposals.items()
            },
        }
        return DefenseDecision.create(
            action=chosen.action,
            target_ip=chosen.target_ip,
            source_ip=chosen.source_ip,
            reason=f"Executing {chosen.action.value} (proposed by {winner}); {basis}. " + "; ".join(lines) + ".",
            confidence=chosen.confidence,
            threat_score=chosen.threat_score,
            policy_name=ARBITER_NAME,
            context={**chosen.context, "arbiter_reasoning": reasoning},
        )


POLICY_MODES = ("arbiter", "stackelberg", "rule_based", "ppo")


def select_decision(
    mode: str,
    *,
    rule: DefenseDecision,
    stackelberg: DefenseDecision | None,
    ppo: DefenseDecision | None,
    arbiter: DefenseDecision | None,
) -> DefenseDecision:
    """Which decision the demo executes. Every mode degrades the same way
    when its own policy produced nothing: Stackelberg, then rule-based."""
    if mode not in POLICY_MODES:
        raise ValueError(f"unknown policy mode {mode!r}; expected one of {POLICY_MODES}")
    preferred = {"arbiter": arbiter, "stackelberg": stackelberg, "rule_based": rule, "ppo": ppo}[mode]
    for candidate in (preferred, stackelberg, rule):
        if candidate is not None:
            return candidate
    raise ValueError("no policy produced a decision")
