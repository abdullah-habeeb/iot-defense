"""Unit tests for evaluation/policy_disagreement.py -- no Mininet. It reports
action AGREEMENT only; which action is better is decided by measured outcomes
(outcome_report.py). Uses a PPO model trained on the synthetic table, so only
structural properties are asserted -- agreement rates depend on the data."""
from __future__ import annotations

from iot_defense.attacks.registry import ATTACK_SCENARIOS
from iot_defense.evaluation.policy_disagreement import NOVEL_ATTACK_TYPES, PERTURBATIONS, run, summarize


def test_covers_the_full_perturbation_grid_for_every_attack_plus_novel_types(trained_ppo_path):
    rows = run(model_path=trained_ppo_path)
    summary = summarize(rows)
    assert summary["in_distribution"]["n"] == len(ATTACK_SCENARIOS) * len(PERTURBATIONS) ** 2
    assert summary["out_of_distribution"]["n"] == len(NOVEL_ATTACK_TYPES) * 4
    assert not any(r["ppo_used_fallback"] for r in rows), "the PPO arm must be the trained model, never a silent fallback"


def test_rates_are_consistent_with_per_row_flags(trained_ppo_path):
    rows = run(model_path=trained_ppo_path)
    in_dist = [r for r in rows if r["boundary"] == "in_distribution"]
    summary = summarize(rows)["in_distribution"]
    assert summary["all_agree_rate"] == round(sum(r["all_agree"] for r in in_dist) / len(in_dist), 4)
    for r in in_dist:
        assert r["all_agree"] == (r["rule_vs_stack_agree"] and r["rule_vs_ppo_agree"])


def test_rule_based_and_stackelberg_fall_back_to_alert_on_unregistered_attack_types(trained_ppo_path):
    out_dist = summarize(run(model_path=trained_ppo_path))["out_of_distribution"]
    assert out_dist["rule_actions"] == ["ALERT"]
    assert out_dist["stack_actions"] == ["ALERT"]
