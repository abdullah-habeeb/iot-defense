"""evaluation/arbiter_candidates_eval.py: held-out-block grading of the arbiter with and without the supported actions."""

from __future__ import annotations

import json

import pytest

from iot_defense.defense.decision import DefenseAction as A
from iot_defense.evaluation import arbiter_candidates_eval as ev
from iot_defense.evaluation.outcome import Measurement

LABEL = "c2_beaconing"


def table_rows(forensic_loss_by_block=(0.2, 0.0, 0.0)):
    """Three blocks. ISOLATE/QUARANTINE (what the policies propose) contain everything and kill the service; FORENSIC_CAPTURE
    contains nothing but verifies evidence, except in the first block where it does not."""
    spec = {
        A.ALLOW: (100, 0.0, False), A.ALERT: (100, 0.0, False), A.BLOCK_SOURCE: (100, 0.1, False), A.THROTTLE: (90, 0.1, False),
        A.ISOLATE: (0, 1.0, False), A.QUARANTINE: (0, 1.0, False),
    }
    rows = []
    for rep in range(3):
        for action, (residual, loss, intel) in spec.items():
            rows.append({**Measurement(LABEL, action, "success", 100, residual, loss, intel).to_row(), "rep": rep})
        rows.append({**Measurement(LABEL, A.FORENSIC_CAPTURE, "success", 100, 100, forensic_loss_by_block[rep], True).to_row(), "rep": rep})
    return rows


def harness_rows(trials=4):
    rows = []
    for trial in range(trials):
        for arm, action in (("rule_based", "ISOLATE"), ("stackelberg", "QUARANTINE"), ("ppo", "ISOLATE"), ("naive_block_all", "BLOCK_SOURCE"), ("always_allow", "ALLOW")):
            rows.append({"condition": LABEL, "arm": arm, "trial": trial, "action": action, "detected_attack_type": LABEL, "valid_measurement": True})
    return rows


@pytest.fixture()
def report(tmp_path):
    table, results = tmp_path / "table.jsonl", tmp_path / "results.jsonl"
    table.write_text("".join(json.dumps(r) + "\n" for r in table_rows()), encoding="utf-8")
    results.write_text("".join(json.dumps(r) + "\n" for r in harness_rows()), encoding="utf-8")
    return ev.evaluate(table, results)


def test_on_the_live_device_the_old_arbiter_alerts_and_the_new_one_forensically_captures(report):
    live = report["settings"]["live"]
    s = live["situations"][LABEL]
    assert s["all_proposals_unsupported_trials"] == s["trials"] == 4
    assert s["before"]["modal_action"] == "ALERT" and s["after"]["modal_action"] == "FORENSIC_CAPTURE" and s["modal_action_changed"]
    assert live["situations_with_a_changed_modal_action"] == [LABEL] and live["trials_with_a_different_choice"] == 4
    assert set(live["chosen_from_after"]) == {"not_proposed"}


def test_the_choice_is_graded_on_the_block_it_did_not_read(report):
    s = report["settings"]["live"]["situations"][LABEL]
    # FORENSIC_CAPTURE earns 4.1 in block 0 (it lost 0.2 of the service) and 4.7 in blocks 1 and 2; each fold is graded on its own block.
    assert s["after"]["heldout_utility"] == pytest.approx((4.1 + 4.7 + 4.7) / 3)
    assert s["before"]["heldout_utility"] == pytest.approx(2.9)  # ALERT: 3 - 0.1 in every block
    diff = report["settings"]["live"]["heldout_utility_after_minus_before"]
    assert diff["mean_diff"] == pytest.approx((4.1 + 4.7 + 4.7) / 3 - 2.9) and diff["n_nonzero"] == 4


def test_regret_is_against_the_best_action_the_device_can_apply(report):
    s = report["settings"]["live"]["situations"][LABEL]
    full_forensic = (4.1 + 4.7 + 4.7) / 3
    assert s["after"]["in_sample_regret"] == pytest.approx(0.0)  # FORENSIC_CAPTURE is the best live action
    assert s["before"]["in_sample_regret"] == pytest.approx(full_forensic - 2.9)
    assert report["settings"]["live"]["mean_over_situations"]["after"]["in_sample_regret"] == pytest.approx(0.0)


def test_the_lab_considers_every_response_and_the_report_renders(report):
    lab = report["settings"]["lab"]
    assert len(lab["available"]) == len(A) and lab["situations"][LABEL]["trials"] == 4
    text = ev.render_markdown(report)
    assert "## live" in text and "## lab" in text and "(focus)" in text  # c2_beaconing is one of the four attacks the change targets
    json.dumps(report)


def test_it_refuses_a_single_block(tmp_path):
    table, results = tmp_path / "t.jsonl", tmp_path / "r.jsonl"
    table.write_text("".join(json.dumps({**r, "rep": 0}) + "\n" for r in table_rows()), encoding="utf-8")
    results.write_text("".join(json.dumps(r) + "\n" for r in harness_rows()), encoding="utf-8")
    with pytest.raises(ValueError):
        ev.evaluate(table, results)
