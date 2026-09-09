import json

from iot_defense.evaluation.report import generate_report, load_results, summarize_by_arm, summarize_by_condition


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
        results_path=results_path, json_output_path=json_output, markdown_output_path=markdown_output
    )

    assert json_output.exists()
    assert markdown_output.exists()
    saved = json.loads(json_output.read_text())
    assert saved["total_rows"] == 2
    markdown = markdown_output.read_text()
    assert "Rule-based (ours)" not in markdown  # arm not present in this fixture
    assert "Stackelberg (ours, deployed)" in markdown
    assert "NaiveBlockAllBaseline" in markdown
    assert summary["by_arm"]["stackelberg"]["response_verified_rate"] == 1.0


def test_load_results_skips_blank_lines(tmp_path):
    path = tmp_path / "results.jsonl"
    path.write_text(json.dumps(_row()) + "\n\n" + json.dumps(_row(trial=1)) + "\n", encoding="utf-8")
    rows = load_results(path)
    assert len(rows) == 2
