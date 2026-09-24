"""Policy-disagreement stress test: do rule-based, Stackelberg, and PPO
ever actually choose different actions, and under what conditions?

The main evaluation harness (harness.py) always classifies real captured
traffic cleanly -- high confidence, well inside each attack's own
registered thresholds -- so all three policies converge on the identical
registry preferred_action on every single trial (confirmed directly: 0
disagreements across 80 real trials x 3 policies). That is not a data
bug; it is a direct, structural consequence of how the three policies
were each independently built (rule-based's own thresholds, Stackelberg's
payoff tables, and PPO's training reward are all separately designed to
reach that same answer for a confidently-classified attack). It does
mean the harness alone cannot support any claim that these are three
meaningfully different decision mechanisms -- this module exists to
supply that evidence directly, by testing where the three policies
actually have room to disagree: synthetic SecurityContexts with
threat_score/confidence perturbed around each attack's own registered
action_score_min/action_confidence_min (ambiguous, near-boundary
detections), plus entirely unregistered "novel" attack_types no policy
was ever tuned for (out-of-distribution generalization).

No Mininet required -- this evaluates the three real policy classes
directly against synthetic contexts, the same pattern
evaluation/adaptive.py and this project's own PPO convergence checks
already use elsewhere.
"""
from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path
from typing import Any

from iot_defense.attacks.registry import ATTACK_SCENARIOS
from iot_defense.defense.context import Beliefs, Desires, SecurityContext
from iot_defense.defense.policy import RuleBasedDefensePolicy, StackelbergDefensePolicy
from iot_defense.defense.ppo_policy import PPODefensePolicy

# Perturbations applied to each attack's own registered
# action_score_min/action_confidence_min, in both directions -- 0.0 is
# exactly at the boundary; the others probe just inside/outside it.
PERTURBATIONS: tuple[float, ...] = (-0.15, -0.08, -0.03, 0.0, 0.03, 0.08, 0.15)

# Attack types this registry has never seen, at a spread of threat_score/
# confidence values -- probes generalization to out-of-distribution
# inputs, not just in-distribution ambiguity.
NOVEL_ATTACK_TYPES: tuple[str, ...] = (
    "zero_day_lateral_movement", "novel_firmware_exploit", "unknown_protocol_anomaly",
)
NOVEL_SCORE_CONFIDENCE_PAIRS: tuple[tuple[float, float], ...] = (
    (0.3, 0.3), (0.5, 0.5), (0.7, 0.6), (0.9, 0.85),
)


def _context(threat_type: str, threat_score: float, confidence: float, intention: str) -> SecurityContext:
    return SecurityContext(
        beliefs=Beliefs(
            threat_type=threat_type,
            threat_score=max(0.0, min(1.0, threat_score)),
            confidence=max(0.0, min(1.0, confidence)),
            source_device="10.0.0.100",
            destination_device="10.0.0.10",
        ),
        desires=Desires(),
        intention=intention,
    )


def _row(attack_key: str, attack_type: str, context: SecurityContext, extra: dict[str, Any], policies: dict) -> dict[str, Any]:
    rule_action = policies["rule"].decide(context).action
    stack_action = policies["stack"].decide(context).action
    ppo_decision = policies["ppo"].decide(context)
    ppo_action = ppo_decision.action
    return {
        "attack_key": attack_key,
        "attack_type": attack_type,
        "threat_score": round(context.beliefs.threat_score, 3),
        "confidence": round(context.beliefs.confidence, 3),
        **extra,
        "rule_action": rule_action.value,
        "stack_action": stack_action.value,
        "ppo_action": ppo_action.value,
        "ppo_used_fallback": policies["ppo"].model is None,
        "all_agree": rule_action == stack_action == ppo_action,
        "rule_vs_stack_agree": rule_action == stack_action,
        "rule_vs_ppo_agree": rule_action == ppo_action,
        "stack_vs_ppo_agree": stack_action == ppo_action,
    }


def run(model_path: str = "models/ppo_defense") -> list[dict[str, Any]]:
    policies = {
        "rule": RuleBasedDefensePolicy(),
        "stack": StackelbergDefensePolicy(),
        "ppo": PPODefensePolicy(model_path=model_path, fallback=RuleBasedDefensePolicy()),
    }

    rows: list[dict[str, Any]] = []
    for key, scenario in ATTACK_SCENARIOS.items():
        score_min, confidence_min = policies["rule"].action_thresholds[key]
        for d_score, d_conf in itertools.product(PERTURBATIONS, PERTURBATIONS):
            context = _context(scenario.attack_type, score_min + d_score, confidence_min + d_conf, scenario.intention)
            rows.append(_row(key, scenario.attack_type, context, {"d_score": d_score, "d_conf": d_conf, "boundary": "in_distribution"}, policies))

    for novel_type in NOVEL_ATTACK_TYPES:
        for threat_score, confidence in NOVEL_SCORE_CONFIDENCE_PAIRS:
            context = _context(novel_type, threat_score, confidence, "contain_malicious_activity")
            rows.append(_row(f"novel:{novel_type}", novel_type, context, {"d_score": None, "d_conf": None, "boundary": "out_of_distribution"}, policies))

    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    def _rate(subset: list[dict[str, Any]], field: str) -> float | None:
        return round(sum(1 for r in subset if r[field]) / len(subset), 4) if subset else None

    in_dist = [r for r in rows if r["boundary"] == "in_distribution"]
    out_dist = [r for r in rows if r["boundary"] == "out_of_distribution"]
    return {
        "total_contexts": len(rows),
        "in_distribution": {
            "n": len(in_dist),
            "all_agree_rate": _rate(in_dist, "all_agree"),
            "rule_vs_stack_agree_rate": _rate(in_dist, "rule_vs_stack_agree"),
            "rule_vs_ppo_agree_rate": _rate(in_dist, "rule_vs_ppo_agree"),
            "stack_vs_ppo_agree_rate": _rate(in_dist, "stack_vs_ppo_agree"),
        },
        "out_of_distribution": {
            "n": len(out_dist),
            "all_agree_rate": _rate(out_dist, "all_agree"),
            "rule_actions": sorted({r["rule_action"] for r in out_dist}),
            "stack_actions": sorted({r["stack_action"] for r in out_dist}),
            "ppo_actions": sorted({r["ppo_action"] for r in out_dist}),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-path", default="models/ppo_defense")
    parser.add_argument("--output", default="data/evaluation/policy_disagreement.jsonl")
    parser.add_argument("--summary-output", default="data/evaluation/policy_disagreement.summary.json")
    args = parser.parse_args()

    rows = run(model_path=args.model_path)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")

    summary = summarize(rows)
    Path(args.summary_output).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
