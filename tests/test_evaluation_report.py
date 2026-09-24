import json

from iot_defense.evaluation.report import (
    _wilson_ci,
    generate_report,
    load_results,
    load_suricata_summary,
    render_markdown,
    summarize_by_arm,
    summarize_by_condition,
)


def test_wilson_ci_matches_known_reference_value():
    """8/10 successes -> a 95% Wilson interval of approximately
    (0.490, 0.943) is a standard textbook reference value (matches
    statsmodels.stats.proportion.proportion_confint(8, 10,
    method='wilson')) -- added after a review found this evaluation
    reported bare percentages with no uncertainty measure at all."""
    lower, upper = _wilson_ci(8, 10)
    assert abs(lower - 0.4904) < 0.001
    assert abs(upper - 0.9434) < 0.001


def test_wilson_ci_handles_zero_trials():
    assert _wilson_ci(0, 0) is None


def test_wilson_ci_stays_within_0_and_1_at_extreme_proportions():
    lower, upper = _wilson_ci(0, 5)
    assert 0.0 <= lower <= upper <= 1.0
    lower, upper = _wilson_ci(5, 5)
    assert 0.0 <= lower <= upper <= 1.0


def test_summarize_by_arm_includes_confidence_intervals():
    rows = [
        {"arm": "rule_based", "ground_truth_attack_type": "dos_flood", "detection_correct": True,
         "response_verified": True, "matches_preferred_action": True, "execution_ok": True,
         "detection_latency_ms": 100.0},
        {"arm": "rule_based", "ground_truth_attack_type": "dos_flood", "detection_correct": True,
         "response_verified": False, "matches_preferred_action": False, "execution_ok": True,
         "detection_latency_ms": 100.0},
    ]
    summary = summarize_by_arm(rows)
    assert summary["rule_based"]["detection_accuracy_ci95"] is not None
    assert summary["rule_based"]["response_verified_rate_ci95"] is not None


def _row(**overrides):
    defaults = dict(
        trial=0,
        condition="dos_flood",
        arm="stackelberg",
        ground_truth_attack_type="dos_flood",
        detected_attack_type="dos_flood",
        detection_correct=True,
        detector_name="RuleBasedDosDetector",
        detection_latency_ms=1000.0,
        action="ISOLATE",
        matches_preferred_action=True,
        execution_ok=True,
        response_verified=True,
        outcome={"status": "success", "connectivity_lost": True},
    )
    defaults.update(overrides)
    return defaults


def _write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def test_summarize_by_arm_computes_rates_correctly():
    rows = [
        _row(arm="stackelberg", response_verified=True, matches_preferred_action=True),
        _row(arm="stackelberg", response_verified=False, matches_preferred_action=True),
        _row(arm="always_allow", action="ALLOW", matches_preferred_action=False, response_verified=None, outcome={"status": "success"}),
    ]
    summary = summarize_by_arm(rows)

    assert summary["stackelberg"]["trials"] == 2
    assert summary["stackelberg"]["response_verified_rate"] == 0.5
    assert summary["stackelberg"]["matches_preferred_action_rate_on_attacks"] == 1.0
    assert summary["always_allow"]["response_verified_rate"] == 0.0


def test_summarize_by_condition_breaks_down_per_condition():
    rows = [
        _row(condition="dos_flood", response_verified=True),
        _row(condition="dos_flood", response_verified=True),
        _row(condition="brute_force", ground_truth_attack_type="brute_force", detected_attack_type="brute_force", response_verified=False),
    ]
    summary = summarize_by_condition(rows, "stackelberg")

    assert summary["dos_flood"]["trials"] == 2
    assert summary["dos_flood"]["response_verified_rate"] == 1.0
    assert summary["brute_force"]["response_verified_rate"] == 0.0


def test_generate_report_writes_json_and_markdown(tmp_path):
    results_path = tmp_path / "results.jsonl"
    _write_jsonl(
        results_path,
        [
            _row(arm="stackelberg"),
            _row(arm="naive_block_all", response_verified=False, matches_preferred_action=False, action="ALERT"),
        ],
    )
    json_output = tmp_path / "summary.json"
    markdown_output = tmp_path / "summary.md"

    summary = generate_report(
        results_path=results_path,
        json_output_path=json_output,
        markdown_output_path=markdown_output,
        # Explicit, nonexistent path -- must not accidentally pick up this
        # project's own real data/evaluation/suricata_summary.json if the
        # test happens to run with the repo root as its working directory.
        suricata_summary_path=tmp_path / "no_such_suricata_summary.json",
    )

    assert json_output.exists()
    assert markdown_output.exists()
    saved = json.loads(json_output.read_text())
    assert saved["total_rows"] == 2
    assert saved["suricata"] is None
    markdown = markdown_output.read_text()
    assert "Rule-based (ours)" not in markdown  # arm not present in this fixture
    assert "Stackelberg (ours, deployed)" in markdown
    assert "NaiveBlockAllBaseline" in markdown
    assert "External detection comparison" not in markdown  # no suricata summary given
    assert summary["by_arm"]["stackelberg"]["response_verified_rate"] == 1.0


def test_load_suricata_summary_returns_none_when_missing(tmp_path):
    assert load_suricata_summary(tmp_path / "does_not_exist.json") is None


def test_render_markdown_includes_suricata_section_when_provided(tmp_path):
    rows = [_row(arm="stackelberg")]
    suricata_summary = {
        "total_pcaps": 120,
        "et_open": {"accuracy": 0.625, "true_positive_rate": 0.59, "false_positive_rate": 0.2},
        "lab": {"accuracy": 0.6417, "true_positive_rate": 0.57, "false_positive_rate": 0.0},
    }
    markdown = render_markdown(
        rows, summarize_by_arm(rows), summarize_by_condition(rows, "stackelberg"), "results.jsonl", suricata_summary
    )
    assert "External detection comparison" in markdown
    assert "62.5%" in markdown
    assert "ET-Open" in markdown
    assert "lab-tailored rules" in markdown


def test_load_results_skips_blank_lines(tmp_path):
    path = tmp_path / "results.jsonl"
    path.write_text(json.dumps(_row()) + "\n\n" + json.dumps(_row(trial=1)) + "\n", encoding="utf-8")
    rows = load_results(path)
    assert len(rows) == 2
