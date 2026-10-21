"""Strategies against a reactive attacker (evaluation/adaptive_eval.py), on synthetic tables."""

from __future__ import annotations

import json

import pytest

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.objective import Objective
from iot_defense.evaluation import adaptive_eval as ae
from iot_defense.evaluation.adaptive_outcome import AdaptiveMeasurement, AdaptiveOutcomeTable
from iot_defense.evaluation.outcome import OutcomeTable

OBJECTIVE = Objective.load()
A = DefenseAction
KEYED = (A.BLOCK_SOURCE, A.DECOY, A.RESET_SESSIONS)


def adaptive_rows(condition="dos_flood", reps=3):
    """Source-keyed responses are dodged after the switch; every other response keeps containing."""
    rows = []
    for rep in range(reps):
        for action in A:
            if action == A.ALLOW:
                m = AdaptiveMeasurement(condition, action, "success", 100, 100, 100, 100, False, 0.0, 0.0, False)
            else:
                m = AdaptiveMeasurement(condition, action, "success", 100, 0, 100, 95 if action in KEYED else 2, True, 0.0, 0.0, False)
            rows.append(m.to_row() | {"rep": rep})
    return rows


@pytest.fixture
def adaptive_table():
    return AdaptiveOutcomeTable(adaptive_rows(), OBJECTIVE)


class TestOverlay:
    def test_the_adaptive_conditions_cells_replace_the_standard_ones_and_the_rest_are_kept(self, synthetic_table, adaptive_table):
        merged = synthetic_table.with_cells_from(adaptive_table)
        assert merged.samples("dos_flood", A.BLOCK_SOURCE) == adaptive_table.samples("dos_flood", A.BLOCK_SOURCE)
        assert merged.samples("dos_flood", A.BLOCK_SOURCE) != synthetic_table.samples("dos_flood", A.BLOCK_SOURCE)
        other = next(c for c in ("tcp_syn_flood", "brute_force"))
        assert merged.samples(other, A.THROTTLE) == synthetic_table.samples(other, A.THROTTLE)
        assert synthetic_table.samples("dos_flood", A.BLOCK_SOURCE) != []  # the original is untouched

    def test_the_merge_has_the_standard_interface_and_prefers_what_survives_the_switch(self, synthetic_table, adaptive_table):
        merged = synthetic_table.with_cells_from(adaptive_table)
        assert isinstance(merged, OutcomeTable) and merged.best_action("dos_flood") not in KEYED
        merged.require_complete(("dos_flood", "normal"))


class TestScoring:
    def test_regret_is_measured_against_the_tables_own_best_action(self, adaptive_table):
        best = adaptive_table.best_action("dos_flood").value
        assert ae.regret(adaptive_table, "dos_flood", best) == pytest.approx(0.0)
        assert ae.regret(adaptive_table, "dos_flood", "BLOCK_SOURCE") > 1.0

    def test_an_arm_that_ignores_rotation_scores_worse_on_the_adaptive_table_but_not_on_the_standard_one(self, synthetic_table, adaptive_table):
        overlay = synthetic_table.with_cells_from(adaptive_table)
        naive_action = synthetic_table.best_action("dos_flood").value  # what a policy trained on the standard table picks
        wise_action = overlay.best_action("dos_flood").value
        scored = ae.score_arms({"naive": [lambda c: naive_action], "wise": [lambda c: wise_action]}, overlay, synthetic_table, ("dos_flood",))
        assert scored["wise"]["mean_adaptive_regret"] == pytest.approx(0.0)
        assert scored["naive"]["mean_standard_regret"] == pytest.approx(0.0)
        assert scored["naive"]["mean_adaptive_regret"] >= scored["wise"]["mean_adaptive_regret"]
        assert scored["wise"]["mean_standard_regret"] >= scored["naive"]["mean_standard_regret"]  # anticipating is not free on the standard table

    def test_several_models_of_one_arm_are_averaged(self, adaptive_table):
        best = adaptive_table.best_action("dos_flood").value
        scored = ae.score_arms({"mixed": [lambda c: best, lambda c: "BLOCK_SOURCE"]}, adaptive_table, adaptive_table, ("dos_flood",))
        assert scored["mixed"]["models"] == 2
        assert scored["mixed"]["mean_adaptive_regret"] == pytest.approx(ae.regret(adaptive_table, "dos_flood", "BLOCK_SOURCE") / 2)


class TestMechanismCheck:
    def test_predictions_are_compared_with_what_actually_lost_containment_after_the_switch(self, adaptive_table):
        check = ae.mechanism_check(adaptive_table, adaptive_rows(), ("dos_flood",))
        by_action = {c["action"]: c for c in check["cells"]}
        assert by_action["BLOCK_SOURCE"]["predicted_dodged"] and by_action["BLOCK_SOURCE"]["measured_dodged"]
        assert not by_action["THROTTLE"]["predicted_dodged"] and not by_action["THROTTLE"]["measured_dodged"]
        # every pair is accounted for exactly once: agreement, a false alarm, or a miss
        assert check["agree"] + len(check["false_alarms"]) + len(check["misses"]) == check["of"] == 9
        # a response whose prior containment is tiny is not worth dodging, so a rational attacker would not
        # bother switching: the model does not call RESET_SESSIONS dodged even though the synthetic rows lose it
        assert ("dos_flood", "RESET_SESSIONS") in [tuple(x) for x in check["misses"]]

    def test_a_response_the_model_says_is_dodged_but_which_held_up_is_reported_as_a_false_alarm(self):
        rows = [r for r in adaptive_rows() if r["action"] != "BLOCK_SOURCE"]
        rows += [AdaptiveMeasurement("dos_flood", A.BLOCK_SOURCE, "success", 100, 0, 100, 0, True, 0.0, 0.0, False).to_row() | {"rep": 0}]
        check = ae.mechanism_check(AdaptiveOutcomeTable(rows, OBJECTIVE), rows, ("dos_flood",))
        assert ("dos_flood", "BLOCK_SOURCE") in [tuple(x) for x in check["false_alarms"]]

    def test_rows_where_the_attacker_did_not_switch_say_nothing_about_dodging(self):
        rows = [AdaptiveMeasurement("dos_flood", A.THROTTLE, "success", 100, 90, 100, 90, False, 0.0, 0.0, False).to_row()]
        assert ae.mechanism_check(AdaptiveOutcomeTable(rows, OBJECTIVE), rows, ("dos_flood",))["of"] == 0


class TestTraining:
    def test_the_adaptive_ppo_trains_on_the_overlay_and_is_resumable(self, synthetic_table_path, tmp_path):
        adaptive_path = tmp_path / "adaptive.jsonl"
        adaptive_path.write_text("".join(json.dumps(r) + "\n" for r in adaptive_rows()), encoding="utf-8")
        seen = []

        def fake_train(table, **kwargs):
            seen.append((kwargs["output_path"], table.mean("dos_flood", A.BLOCK_SOURCE)))
            open(kwargs["output_path"] + ".zip", "w").close()
            return {"training_seconds": 0.0}

        first = ae.run_training(str(synthetic_table_path), str(adaptive_path), str(tmp_path), 1, worker=0, workers=2, train_fn=fake_train)
        second = ae.run_training(str(synthetic_table_path), str(adaptive_path), str(tmp_path), 1, worker=1, workers=2, train_fn=fake_train)
        assert len(first) + len(second) == len(ae.ADAPTIVE_PPO_SEEDS) and not set(first) & set(second)
        standard = OutcomeTable.from_jsonl(synthetic_table_path, OBJECTIVE).mean("dos_flood", A.BLOCK_SOURCE)
        assert all(mean != pytest.approx(standard) for _, mean in seen)  # trained on the adaptive cells, not the standard ones
        assert ae.run_training(str(synthetic_table_path), str(adaptive_path), str(tmp_path), 1, train_fn=fake_train) == []


def test_the_report_names_the_arms_and_the_mechanism_agreement():
    report = {
        "conditions": ["dos_flood"], "best_action_standard": {"dos_flood": "BLOCK_SOURCE"}, "best_action_adaptive": {"dos_flood": "THROTTLE"},
        "arms": {"rule_based": {"models": 1, "mean_adaptive_regret": 3.1, "mean_adaptive_regret_ci95": [3.1, 3.1], "mean_standard_regret": 3.0}},
        "mechanism_check": {"agree": 8, "of": 8, "false_alarms": [], "misses": []},
    }
    text = ae.render_markdown(report)
    assert "rule_based" in text and "BLOCK_SOURCE -> THROTTLE" in text and "8/8" in text
