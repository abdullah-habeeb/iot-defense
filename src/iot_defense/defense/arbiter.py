"""Execute the response with the best measured evidence of working.

The three policies (rule-based, Stackelberg, PPO) each propose an action for
the same context. The arbiter does not pick a favourite policy: it scores each
candidate ACTION by what was measured when that action was applied against this
kind of attack in live Mininet (evaluation/outcome_table.py) -- the mean
realized utility, minus a penalty proportional to its run-to-run spread so an
erratic action loses to a dependable one -- and executes the best-scoring
candidate. It never reads a registered preferred_action.

Which actions are candidates is a setting (policy.arbiter.consider_all_supported):

  * false: only the policies' proposals. A device that cannot perform what the
    policies proposed has nothing to choose from and alerts.
  * true:  the proposals plus every action the device can perform (all of
    DefenseAction when nothing restricts it). A policy that proposes a response
    the device cannot apply no longer forces a fallback to ALERT when a
    performable action has better evidence. Each candidate records who
    proposed it, or "not_proposed" when it is a supported action no policy chose.

With no usable evidence for any candidate (an attack label never measured, or
a missing table) it falls back to the first available policy in
`fallback_order` and says so in its reasoning.

Ties on the risk-adjusted score are broken deterministically: a proposed action
over one nobody proposed; then the policy order (Stackelberg, PPO, rule-based) of
its best-ranked proposer; then DefenseAction declaration order.
"""

from __future__ import annotations

import statistics
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable

from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.objective import load_policy_section

if TYPE_CHECKING:
    from iot_defense.evaluation.outcome import OutcomeTable

ARBITER_NAME = "ArbiterPolicy"
NOT_PROPOSED = "not_proposed"
TIE_EPSILON = 1e-9
# Policy-specific entries of a proposal's context; they describe that policy's own action, so they are not carried
# over to an action the policy did not propose.
POLICY_SPECIFIC_CONTEXT = ("stackelberg_reasoning", "ppo_observation", "ppo_action_index")
ALSO_SCORED_IN_REASON = 3


class ArbiterPolicy:
    def __init__(
        self,
        table: "OutcomeTable",
        *,
        risk_aversion: float = 1.0,
        min_samples: int = 2,
        fallback_order: tuple[str, ...] = ("stackelberg", "ppo", "rule_based"),
        consider_all_supported: bool = False,
    ) -> None:
        self.table = table
        self.risk_aversion = risk_aversion
        self.min_samples = min_samples
        self.fallback_order = fallback_order
        self.consider_all_supported = consider_all_supported

    @classmethod
    def from_config(cls, *, consider_all_supported: bool | None = None) -> "ArbiterPolicy | None":
        """Build from policy.arbiter; None when the measured outcome table is
        not available (the caller then falls back to a single policy).
        `consider_all_supported`, when given, overrides the configured setting."""
        from iot_defense.evaluation.outcome import OutcomeTable

        config = load_policy_section("arbiter")
        path = Path(config["outcome_table_path"])
        if not path.is_absolute():
            path = Path(__file__).resolve().parents[3] / path
        if not path.exists():
            return None
        if consider_all_supported is None:
            consider_all_supported = bool(config.get("consider_all_supported", False))
        return cls(
            OutcomeTable.from_jsonl(path),
            risk_aversion=float(config["risk_aversion"]),
            min_samples=int(config["min_samples"]),
            consider_all_supported=consider_all_supported,
        )

    def score_action(self, label: str, action: DefenseAction) -> dict[str, float | int] | None:
        """Evidence for one action: measured mean utility, spread and the
        risk-adjusted score; None when too few valid measurements exist."""
        samples = self.table.samples(label, action)
        if len(samples) < self.min_samples:
            return None
        mean = statistics.fmean(samples)
        spread = statistics.pstdev(samples)
        return {"mean": mean, "sd": spread, "n": len(samples), "score": mean - self.risk_aversion * spread}

    def score(self, label: str, decision: DefenseDecision) -> dict[str, float | int] | None:
        """Evidence for one proposal."""
        return self.score_action(label, decision.action)

    def arbitrate(
        self,
        label: str,
        proposals: dict[str, DefenseDecision],
        *,
        available: Iterable[DefenseAction] | None = None,
        template: DefenseDecision | None = None,
    ) -> DefenseDecision:
        """Choose among the candidate actions for an attack the detector labelled `label`.

        `proposals` maps policy name -> its decision (only those the device can perform). `available` is the set of
        actions the device can perform (None: no restriction); it only matters when `consider_all_supported` is on.
        `template` supplies the target, source and context for the executed decision when nothing was proposed (all
        proposals set aside) -- it is not a proposal and is never scored."""
        if not proposals and not (self.consider_all_supported and template is not None):
            raise ValueError("arbitrate() needs at least one proposal")
        order = {name: index for index, name in enumerate(self.fallback_order)}

        def rank(name: str) -> int:
            return order.get(name, len(order))

        proposers: dict[DefenseAction, list[str]] = {}
        for name in sorted(proposals, key=rank):
            proposers.setdefault(proposals[name].action, []).append(name)
        candidates: list[DefenseAction] = list(proposers)
        if self.consider_all_supported:
            allowed = set(DefenseAction) if available is None else set(available)
            candidates += [action for action in DefenseAction if action in allowed and action not in proposers]

        evidence = {action: self.score_action(label, action) for action in candidates}
        scored = {action: e for action, e in evidence.items() if e is not None}
        enum_index = {action: index for index, action in enumerate(DefenseAction)}

        def tie_break(action: DefenseAction) -> tuple[int, int, int]:
            if action in proposers:
                return (0, rank(proposers[action][0]), enum_index[action])
            return (1, len(order), enum_index[action])

        base = proposals[min(proposals, key=rank)] if proposals else template
        assert base is not None
        if scored:
            best = max(e["score"] for e in scored.values())
            chosen_action = min((a for a, e in scored.items() if e["score"] >= best - TIE_EPSILON), key=tie_break)
            chosen_from = proposers[chosen_action][0] if chosen_action in proposers else NOT_PROPOSED
            basis = "measured evidence"
        elif proposals:
            chosen_from = min(proposals, key=rank)
            chosen_action = proposals[chosen_from].action
            scope = "candidate action" if self.consider_all_supported else "proposal"
            basis = f"no measured evidence for any {scope} -- fell back to {chosen_from}"
        else:
            raise ValueError("no measured evidence for any candidate action and no proposal to fall back to")

        proposed = chosen_action in proposers
        executed = proposals[chosen_from] if proposed else base
        context = {k: v for k, v in executed.context.items() if proposed or k not in POLICY_SPECIFIC_CONTEXT}

        def describe(action: DefenseAction) -> str:
            e = evidence[action]
            return (
                f"measured utility {e['mean']:.2f}+/-{e['sd']:.2f} over {e['n']} runs (risk-adjusted {e['score']:.2f})"
                if e is not None
                else "no measurements"
            )

        lines = [f"{proposals[name].action.value} from {name}: {describe(proposals[name].action)}" for name in sorted(proposals, key=rank)]
        also = sorted((a for a in candidates if a not in proposers and evidence[a] is not None), key=lambda a: (-evidence[a]["score"], tie_break(a)))
        if also:
            lines.append("also scored (not proposed): " + ", ".join(f"{a.value} {evidence[a]['score']:.2f}" for a in also[:ALSO_SCORED_IN_REASON]))

        def sort_key(action: DefenseAction) -> tuple[int, float, tuple[int, int, int]]:
            """Best-scoring first, candidates without evidence last."""
            e = evidence[action]
            return (0, -float(e["score"]), tie_break(action)) if e is not None else (1, 0.0, tie_break(action))

        reasoning: dict[str, Any] = {
            "label": label,
            "chosen_from": chosen_from,
            "chosen_action": chosen_action.value,
            "chosen_proposed": proposed,
            "basis": basis,
            "risk_aversion": self.risk_aversion,
            "consider_all_supported": self.consider_all_supported,
            "proposals": {
                name: {"action": decision.action.value, "evidence": evidence[decision.action]}
                for name, decision in proposals.items()
            },
            "candidates": [
                {"action": action.value, "proposed_by": list(proposers.get(action, [])), "evidence": evidence[action]}
                for action in sorted(candidates, key=sort_key)
            ],
        }
        origin = f"proposed by {chosen_from}" if proposed else "not proposed by any policy; best-evidenced action the device can perform"
        return DefenseDecision.create(
            action=chosen_action,
            target_ip=executed.target_ip,
            source_ip=executed.source_ip,
            reason=f"Executing {chosen_action.value} ({origin}); {basis}." + (" " + "; ".join(lines) + "." if lines else ""),
            confidence=executed.confidence,
            threat_score=executed.threat_score,
            policy_name=ARBITER_NAME,
            context={**context, "arbiter_reasoning": reasoning},
        )


class PosteriorArbiter(ArbiterPolicy):
    """An arbiter that does not take the detector's label on trust.

    The plain arbiter looks up evidence under the label it is given. That label comes from a
    detector that is sometimes wrong, so a missed attack (reported as "normal") sends the arbiter to
    the evidence for benign traffic. This one asks instead: given the detector said `label`, what is
    the probability the truth is each condition, and how well does each proposed action do on average
    over those possibilities?

        P(true = t | reported = r)  is proportional to  P(reported = r | true = t) * P(true = t)

    `confusion[t][r]` is how often the detector reports r when the truth is t, and `prior[t]` is how
    common t is in deployment (mostly benign). The action's score is then the posterior-weighted mean
    realized utility minus `risk_aversion` times the spread of utility across that mixture, so an
    action that is excellent for the most likely truth but terrible for a plausible alternative is
    penalised: hedging falls out of the arithmetic instead of being learned.

    It still only chooses among the proposals it is given and never reads a preferred_action. With a
    perfect detector (identity confusion) it reduces exactly to the plain arbiter.
    """

    def __init__(
        self,
        table: "OutcomeTable",
        *,
        confusion: dict[str, dict[str, float]],
        prior: dict[str, float],
        **kwargs: Any,
    ) -> None:
        super().__init__(table, **kwargs)
        self.confusion = confusion
        self.prior = prior

    def posterior(self, reported: str) -> dict[str, float]:
        weights = {t: p * self.confusion.get(t, {}).get(reported, 0.0) for t, p in self.prior.items()}
        total = sum(weights.values())
        if total <= 0.0:
            return {reported: 1.0}  # a label the confusion model has never seen: trust it, as the plain arbiter does
        return {t: w / total for t, w in weights.items() if w > 0.0}

    def score_action(self, label: str, action: DefenseAction) -> dict[str, float | int] | None:
        usable = []
        for truth, weight in self.posterior(label).items():
            samples = self.table.samples(truth, action)
            if len(samples) >= self.min_samples:
                usable.append((weight, statistics.fmean(samples), statistics.pstdev(samples), len(samples)))
        if not usable:
            return None
        total = sum(w for w, *_ in usable)
        mean = sum(w * m for w, m, _, _ in usable) / total
        # spread within each condition plus the spread BETWEEN the conditions the label could mean
        spread = (sum(w * (sd**2 + (m - mean) ** 2) for w, m, sd, _ in usable) / total) ** 0.5
        return {"mean": mean, "sd": spread, "n": sum(n for *_, n in usable), "score": mean - self.risk_aversion * spread}


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
