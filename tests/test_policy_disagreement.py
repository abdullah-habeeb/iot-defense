"""Unit tests for evaluation/policy_disagreement.py's core findings -- no
Mininet required. These lock in the qualitative results a paper would
cite, so a future change to reward shaping / thresholds / payoff tables
that silently erases the finding gets caught."""
from __future__ import annotations

from iot_defense.evaluation.policy_disagreement import run, summarize


def test_policies_disagree_substantially_near_decision_boundaries():
    """The main evaluation harness shows 0 disagreements across 80 real
    trials because real captured traffic classifies far from any
    threshold boundary. This is the direct evidence that the three
    policies are NOT just three names for one behavior -- given room to
    disagree, they do, most of the time."""
    rows = run()
    summary = summarize(rows)
    in_dist = summary["in_distribution"]
    assert in_dist["n"] > 500
    assert in_dist["all_agree_rate"] < 0.5, (
        f"expected substantial disagreement near decision boundaries, got "
        f"{in_dist['all_agree_rate']:.1%} full agreement"
    )


def test_stackelberg_and_ppo_agree_far_more_than_either_agrees_with_rule_based():
    """A real, positive finding worth being able to cite precisely: PPO's
    learned behavior tracks Stackelberg's strategic reasoning far more
    closely than it tracks rule-based's simpler threshold logic, even in
    ambiguous/boundary regions neither was directly evaluated against in
    the main harness."""
    rows = run()
    summary = summarize(rows)
    in_dist = summary["in_distribution"]
    assert in_dist["stack_vs_ppo_agree_rate"] > in_dist["rule_vs_ppo_agree_rate"]
    assert in_dist["stack_vs_ppo_agree_rate"] > in_dist["rule_vs_stack_agree_rate"]


def test_ppo_does_not_gracefully_degrade_on_out_of_distribution_attack_types():
    """A real, honest limitation worth disclosing, not hiding: unlike
    rule-based and Stackelberg (which both fall back to ALERT for a
    threat_type they don't recognize -- a deliberate, tested safe
    default), PPO's learned policy picks a fixed action regardless of
    context for any attack_type outside its training distribution. This
    test locks in the qualitative shape of that finding without
    asserting the specific action stays ISOLATE forever (a future
    retrain could shift it) -- what matters is that rule/Stackelberg
    stay stable and narrow while PPO's out-of-distribution behavior is
    characterized at all.
    """
    rows = run()
    summary = summarize(rows)
    out_dist = summary["out_of_distribution"]
    assert out_dist["n"] > 0
    assert out_dist["rule_actions"] == ["ALERT"]
    assert out_dist["stack_actions"] == ["ALERT"]
    assert out_dist["all_agree_rate"] == 0.0
