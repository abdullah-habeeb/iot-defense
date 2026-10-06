"""Unit tests for evaluation/outcome_report.py (paired statistics on measured outcomes)."""

from __future__ import annotations

import json

import numpy as np
import pytest

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.objective import Objective
from iot_defense.evaluation import outcome_report as report

OBJECTIVE = Objective.load()
ARMS = ("rule_based", "stackelberg", "ppo", "naive_block_all", "always_allow")


def trial_rows(condition, trial, spec=None, *, invalid=()):
    """One trial's five arm rows. spec: arm -> (action, containment, service_loss);
    arms not in spec do nothing (ALLOW)."""
    spec = spec or {}
    rows = []
    for arm in ARMS:
        action, containment, service_loss = spec.get(arm, ("ALLOW", 0.0, 0.0))
        rows.append(
            {
                "condition": condition, "trial": trial, "arm": arm, "action": action,
                "containment": containment if condition != "normal" else None,
                "service_loss": service_loss, "intel_verified": False,
                "valid_measurement": arm not in invalid, "execution_ok": True,
                "matches_preferred_action": False, "detection_correct": True,
            }
        )
    return rows


def many_trials(n, spec, condition="dos_flood"):
    return [row for t in range(n) for row in trial_rows(condition, t, spec)]


class TestPairedTrials:
    def test_trials_with_an_invalid_arm_are_excluded_and_counted(self):
        rows = trial_rows("dos_flood", 0) + trial_rows("dos_flood", 1, invalid=("ppo",))
        kept, excluded = report.paired_trials(rows)
        assert list(kept) == [("dos_flood", 0)] and excluded == 1

    def test_trial_missing_an_arm_is_excluded(self):
        rows = [r for r in trial_rows("dos_flood", 0) if r["arm"] != "ppo"]
        kept, excluded = report.paired_trials(rows)
        assert not kept and excluded == 1


class TestStatistics:
    def test_identical_utilities_give_p_one_not_a_spurious_result(self):
        result = report.paired_comparison(np.zeros(10))
        assert result["wilcoxon_p"] == 1.0 and result["sign_test_p"] == 1.0 and result["n_nonzero"] == 0

    def test_consistent_advantage_is_significant(self):
        result = report.paired_comparison(np.full(20, 1.0) + np.linspace(0, 0.1, 20))
        assert result["wilcoxon_p"] < 0.001 and result["sign_test_p"] < 0.001
        low, high = result["mean_diff_ci95"]
        assert 0 < low <= result["mean_diff"] <= high

    def test_balanced_differences_are_not_significant(self):
        result = report.paired_comparison(np.array([1.0, -1.0] * 10))
        assert result["wilcoxon_p"] > 0.5 and result["sign_test_p"] > 0.5

    def test_bootstrap_ci_is_deterministic_and_contains_the_mean(self):
        values = np.array([1.0, 2.0, 3.0, 4.0, 10.0])
        assert report.bootstrap_mean_ci(values) == report.bootstrap_mean_ci(values)
        low, high = report.bootstrap_mean_ci(values)
        assert low <= values.mean() <= high

    def test_holm_adjustment_is_monotone_and_matches_the_known_values(self):
        adjusted = report.holm({"a": 0.01, "b": 0.02, "c": 0.03})
        assert adjusted == pytest.approx({"a": 0.03, "b": 0.04, "c": 0.04})
        assert report.holm({"a": 0.9, "b": 0.8})["a"] <= 1.0


class TestSummaries:
    def spec(self):
        return {
            "rule_based": ("ISOLATE", 1.0, 1.0),
            "stackelberg": ("BLOCK_SOURCE", 1.0, 0.0),
            "ppo": ("BLOCK_SOURCE", 1.0, 0.0),
            "naive_block_all": ("ISOLATE", 1.0, 1.0),
        }

    def test_mean_utility_is_the_measured_vector_scored_by_the_objective(self):
        trials, _ = report.paired_trials(many_trials(6, self.spec()))
        summary = report.arm_summary(trials, OBJECTIVE)
        assert summary["stackelberg"]["mean_utility"] == pytest.approx(
            OBJECTIVE.utility(DefenseAction.BLOCK_SOURCE, containment=1.0, service=1.0, intelligence=0.0)
        )
        assert summary["rule_based"]["mean_utility"] < summary["stackelberg"]["mean_utility"]
        assert summary["always_allow"]["mean_containment_on_attacks"] == 0.0

    def test_pairwise_detects_the_real_difference_and_not_a_fake_one(self):
        trials, _ = report.paired_trials(many_trials(12, self.spec()))
        pairs = report.pairwise(trials, OBJECTIVE)
        assert pairs["rule_based_minus_stackelberg"]["mean_diff"] < 0
        assert pairs["rule_based_minus_stackelberg"]["wilcoxon_p"] < 0.01
        assert pairs["stackelberg_minus_ppo"]["wilcoxon_p"] == 1.0
        assert "wilcoxon_p_holm" in pairs["rule_based_minus_stackelberg"]
        assert pairs["ppo_minus_always_allow"]["mean_diff"] > 0

    def test_action_disagreement_counts_trials_where_actions_differ(self):
        trials, _ = report.paired_trials(many_trials(8, self.spec()))
        d = report.action_disagreement(trials)
        assert d["rule_based_vs_stackelberg"]["rate"] == 1.0
        assert d["stackelberg_vs_ppo"]["rate"] == 0.0
        assert d["all_three_identical"] == 0.0

    def test_per_condition_lists_actions_and_means(self):
        rows = many_trials(4, self.spec()) + many_trials(4, None, condition="normal")
        trials, _ = report.paired_trials(rows)
        by_condition = report.per_condition(trials, OBJECTIVE)
        assert by_condition["dos_flood"]["rule_based"]["actions"] == ["ISOLATE"]
        assert by_condition["normal"]["ppo"]["actions"] == ["ALLOW"]

    def test_sensitivity_can_reverse_the_ranking(self):
        spec = {
            "rule_based": ("THROTTLE", 1.0, 1.0),   # contains fully, kills service
            "stackelberg": ("THROTTLE", 0.5, 0.0),  # half contains, keeps service
            "ppo": ("THROTTLE", 0.5, 0.0),
            "naive_block_all": ("THROTTLE", 0.0, 1.0),
        }
        trials, _ = report.paired_trials(many_trials(5, spec))
        out = report.sensitivity(trials, OBJECTIVE)
        assert out["containment_heavy"]["ranking"][0] == "rule_based"
        assert out["service_heavy"]["ranking"][0] in {"stackelberg", "ppo"}
        assert set(out) == set(report.SENSITIVITY_OBJECTIVES)

    def test_rescoring_with_the_base_objective_matches_arm_summary(self):
        trials, _ = report.paired_trials(many_trials(3, self.spec()))
        row = trials[("dos_flood", 0)]["ppo"]
        assert report.rescored(row, OBJECTIVE) == pytest.approx(
            OBJECTIVE.utility(DefenseAction.BLOCK_SOURCE, containment=1.0, service=1.0, intelligence=0.0)
        )


class TestPriorCalibration:
    def test_cells_compare_prior_to_measured_containment(self):
        from conftest import synthetic_rows

        result = report.prior_vs_measured(synthetic_rows())
        assert result["cells"] and 0.0 <= result["mean_abs_error"] <= 1.0
        for cell in result["cells"]:
            assert cell["n"] > 0 and 0.0 <= cell["measured"] <= 1.0 and 0.0 <= cell["prior"] <= 1.0
            assert cell["abs_error"] == pytest.approx(abs(cell["prior"] - cell["measured"]))


class TestBuildReport:
    def results_file(self, tmp_path):
        spec = {
            "rule_based": ("ISOLATE", 1.0, 1.0), "stackelberg": ("BLOCK_SOURCE", 1.0, 0.0),
            "ppo": ("BLOCK_SOURCE", 1.0, 0.0), "naive_block_all": ("ISOLATE", 1.0, 1.0),
        }
        rows = many_trials(6, spec) + many_trials(6, None, "normal") + trial_rows("dos_flood", 99, invalid=("ppo",))
        path = tmp_path / "results.jsonl"
        path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        return path

    def test_end_to_end_report_and_markdown(self, tmp_path):
        from conftest import synthetic_rows

        table = tmp_path / "table.jsonl"
        table.write_text("".join(json.dumps(r) + "\n" for r in synthetic_rows()), encoding="utf-8")
        built = report.build_report(self.results_file(tmp_path), table)
        assert built["paired_trials"] == 12 and built["excluded_trials_invalid_measurement"] == 1
        text = report.render_markdown(built)
        for heading in ("Paired utility differences", "Do the policies choose different actions?", "Sensitivity", "prior vs measured"):
            assert heading in text
        assert "rule_based_minus_stackelberg" in text

    def test_no_valid_trials_is_an_error_not_an_empty_report(self, tmp_path):
        path = tmp_path / "r.jsonl"
        path.write_text("".join(json.dumps(r) + "\n" for r in trial_rows("dos_flood", 0, invalid=("ppo",))), encoding="utf-8")
        with pytest.raises(ValueError, match="no trial"):
            report.build_report(path)
