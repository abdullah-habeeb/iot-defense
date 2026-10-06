import json

from iot_defense.evaluation.report import (
    _wilson_ci,
    generate_report,
    load_results,
    load_suricata_summary,
    render_markdown,
    summarize_detection,
)


def test_wilson_ci_matches_known_reference_value():
    """8/10 successes -> approximately (0.490, 0.943), the standard textbook
    Wilson reference (statsmodels proportion_confint(8, 10, 'wilson'))."""
    lower, upper = _wilson_ci(8, 10)
    assert abs(lower - 0.4904) < 0.001
    assert abs(upper - 0.9434) < 0.001


def test_wilson_ci_handles_zero_trials():
    assert _wilson_ci(0, 0) is None


def test_wilson_ci_stays_within_0_and_1_at_extreme_proportions():
    for k in (0, 5):
        lower, upper = _wilson_ci(k, 5)
        assert 0.0 <= lower <= upper <= 1.0


def _row(**overrides):
    row = dict(
        trial=0, condition="dos_flood", arm="rule_based", ground_truth_attack_type="dos_flood",
        detected_attack_type="dos_flood", detection_correct=True, detector_name="RuleBasedDosDetector",
        detection_latency_ms=1000.0, action="ISOLATE",
    )
    row.update(overrides)
    return row


def test_summarize_detection_counts_each_trial_once_with_a_ci():
    rows = [
        _row(trial=0), _row(trial=1, detection_correct=False),
        _row(arm="stackelberg", trial=0), _row(arm="ppo", trial=0),  # other arms share the same detection
        _row(condition="normal", ground_truth_attack_type="normal", detected_attack_type="normal", trial=0),
    ]
    summary = summarize_detection(rows)
    assert summary["trials"] == 3
    assert summary["detection_accuracy"] == round(2 / 3, 4)
    assert summary["detection_accuracy_ci95"] is not None
    assert summary["per_condition"]["dos_flood"]["trials"] == 2
    assert summary["per_condition"]["normal"]["detection_accuracy"] == 1.0


def test_render_markdown_points_policy_performance_at_the_outcome_report():
    detection = summarize_detection([_row()])
    text = render_markdown(detection, "x.jsonl")
    assert "outcome_report" in text and "`dos_flood`" in text
    assert "Suricata" not in text


def test_render_markdown_includes_suricata_when_given():
    detection = summarize_detection([_row()])
    suricata = {"et_open": {"accuracy": 0.4, "true_positive_rate": 0.4, "false_positive_rate": 0.1}}
    assert "ET-Open" in render_markdown(detection, "x.jsonl", suricata)


def test_load_suricata_summary_is_none_when_absent(tmp_path):
    assert load_suricata_summary(tmp_path / "missing.json") is None


def test_generate_report_round_trip(tmp_path):
    results = tmp_path / "results.jsonl"
    results.write_text("".join(json.dumps(_row(trial=t)) + "\n" for t in range(3)), encoding="utf-8")
    summary = generate_report(
        results_path=results, json_output_path=tmp_path / "s.json", markdown_output_path=tmp_path / "s.md",
        suricata_summary_path=tmp_path / "none.json",
    )
    assert summary["total_rows"] == 3 and summary["detection"]["trials"] == 3
    assert json.loads((tmp_path / "s.json").read_text())["suricata"] is None
    assert len(load_results(results)) == 3
    assert (tmp_path / "s.md").read_text().startswith("# Detection results")
