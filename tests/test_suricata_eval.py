import json
from pathlib import Path
from unittest.mock import patch

from iot_defense.evaluation.suricata_eval import (
    _distinct_pcaps,
    _patched_config,
    evaluate_pcaps,
    run_suricata_batch,
    run_suricata_per_pcap,
    summarize,
)


def _write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def _result_row(**overrides):
    defaults = dict(
        trial=0,
        condition="dos_flood",
        arm="stackelberg",
        ground_truth_attack_type="dos_flood",
        pcap_path="/tmp/eval/pcaps/trial000_dos_flood.pcap",
    )
    defaults.update(overrides)
    return defaults


def test_distinct_pcaps_deduplicates_across_arms(tmp_path):
    results_path = tmp_path / "results.jsonl"
    _write_jsonl(
        results_path,
        [
            _result_row(arm="rule_based"),
            _result_row(arm="stackelberg"),  # same trial/condition/pcap -- must not double-count
            _result_row(arm="ppo"),
            _result_row(trial=1, condition="normal", ground_truth_attack_type="normal", pcap_path="/tmp/eval/pcaps/trial001_normal.pcap"),
        ],
    )
    pcaps = _distinct_pcaps(results_path)
    assert set(pcaps) == {"trial000_dos_flood.pcap", "trial001_normal.pcap"}
    assert pcaps["trial000_dos_flood.pcap"]["ground_truth_attack_type"] == "dos_flood"


def test_distinct_pcaps_ignores_rows_with_no_pcap_path(tmp_path):
    results_path = tmp_path / "results.jsonl"
    _write_jsonl(results_path, [_result_row(pcap_path=None)])
    assert _distinct_pcaps(results_path) == {}


def test_patched_config_flips_pcap_file_flag(tmp_path):
    system_config = tmp_path / "suricata.yaml"
    system_config.write_text("outputs:\n  eve-log:\n      pcap-file: false\nother: 1\n", encoding="utf-8")

    patched = _patched_config(tmp_path, system_config)

    text = patched.read_text(encoding="utf-8")
    assert "pcap-file: true" in text
    assert "pcap-file: false" not in text


def test_run_suricata_batch_parses_alert_events_by_pcap_filename(tmp_path):
    """Regression test: a real run showed Suricata reports pcap_filename
    as the path it was actually invoked with (here, a relative path under
    pcap_dir) -- not a bare basename. An earlier version of this fixture
    used already-basename-only fake values and passed while the real code
    silently matched nothing, since _distinct_pcaps() always keys by
    basename. Using a realistic relative path here is the point of the
    test, not incidental."""
    out_dir = tmp_path / "out"

    def fake_run(cmd, **kwargs):
        # Simulate Suricata writing eve.json to the -l directory it was given.
        log_dir = tmp_path / "out"
        log_dir.mkdir(parents=True, exist_ok=True)
        eve = [
            {
                "event_type": "alert",
                "pcap_filename": "data/evaluation/pcaps/trial000_dos_flood.pcap",
                "alert": {"signature": "LAB DoS UDP flood"},
            },
            {"event_type": "flow", "pcap_filename": "data/evaluation/pcaps/trial000_dos_flood.pcap"},  # non-alert, must be ignored
            {
                "event_type": "alert",
                "pcap_filename": "data/evaluation/pcaps/trial001_normal.pcap",
                "alert": {"signature": "some false positive"},
            },
        ]
        (log_dir / "eve.json").write_text("\n".join(json.dumps(e) for e in eve) + "\n", encoding="utf-8")

    with patch("iot_defense.evaluation.suricata_eval.subprocess.run", side_effect=fake_run):
        alerts = run_suricata_batch("some_pcap_dir", "some_config", "some_rules", out_dir)

    assert len(alerts["trial000_dos_flood.pcap"]) == 1
    assert alerts["trial000_dos_flood.pcap"][0]["alert"]["signature"] == "LAB DoS UDP flood"
    assert len(alerts["trial001_normal.pcap"]) == 1
    assert "trial002_never_alerted.pcap" not in alerts


def test_run_suricata_per_pcap_runs_a_fresh_process_per_file(tmp_path):
    """Regression test: directory-replay (batch) mode does not reset
    threshold/detection_filter state between files, so a real run showed
    a pcap that reliably alerts in isolation silently not alerting when
    processed as part of a large batch sharing a destination IP with
    other pcaps. lab.rules must run one pcap at a time, each a fresh
    process, to be measured correctly."""
    calls = []

    def fake_run(cmd, **kwargs):
        pcap_path = cmd[cmd.index("-r") + 1]
        out_dir = Path(cmd[cmd.index("-l") + 1])
        calls.append(pcap_path)
        out_dir.mkdir(parents=True, exist_ok=True)
        # Each invocation only ever "sees" its own pcap's alert.
        signature = "LAB DoS UDP flood" if "dos_flood" in pcap_path else None
        events = [{"event_type": "alert", "alert": {"signature": signature}}] if signature else []
        (out_dir / "eve.json").write_text("\n".join(json.dumps(e) for e in events) + ("\n" if events else ""), encoding="utf-8")

    pcaps = {
        "trial000_dos_flood.pcap": {"pcap_path": "/x/trial000_dos_flood.pcap"},
        "trial001_normal.pcap": {"pcap_path": "/x/trial001_normal.pcap"},
    }
    with patch("iot_defense.evaluation.suricata_eval.subprocess.run", side_effect=fake_run):
        alerts = run_suricata_per_pcap(pcaps, "some_config", "lab_rules_path", tmp_path / "out")

    assert len(calls) == 2  # one Suricata invocation per pcap, not one for the whole set
    assert len(alerts["trial000_dos_flood.pcap"]) == 1
    assert alerts["trial001_normal.pcap"] == []


def test_evaluate_pcaps_marks_correctness_against_ground_truth(tmp_path):
    results_path = tmp_path / "results.jsonl"
    _write_jsonl(
        results_path,
        [
            _result_row(trial=0, condition="dos_flood", ground_truth_attack_type="dos_flood", pcap_path="/x/trial000_dos_flood.pcap"),
            _result_row(trial=1, condition="normal", ground_truth_attack_type="normal", pcap_path="/x/trial001_normal.pcap"),
        ],
    )

    def fake_per_pcap(pcaps, config_path, rules_path, out_dir):
        # "lab" ruleset correctly alerts on the attack and stays quiet on normal.
        return {"trial000_dos_flood.pcap": [{"alert": {"signature": "LAB DoS UDP flood"}}], "trial001_normal.pcap": []}

    def fake_batch(pcap_dir, config_path, rules_path, out_dir):
        # "et_open" (real-world signatures) misses the lab-synthetic attack entirely.
        return {}

    with patch("iot_defense.evaluation.suricata_eval._patched_config", return_value="fake_config"):
        with patch("iot_defense.evaluation.suricata_eval.run_suricata_batch", side_effect=fake_batch):
            with patch("iot_defense.evaluation.suricata_eval.run_suricata_per_pcap", side_effect=fake_per_pcap):
                rows = evaluate_pcaps(
                    results_path,
                    batch_rulesets={"et_open": "et_open_rules_path"},
                    per_pcap_rulesets={"lab": "lab_rules_path"},
                    pcap_dir="/x",
                    work_dir=tmp_path / "work",
                )

    by_pcap = {r["pcap_path"]: r for r in rows}
    dos_row = by_pcap["/x/trial000_dos_flood.pcap"]
    normal_row = by_pcap["/x/trial001_normal.pcap"]

    assert dos_row["lab_alerted"] is True
    assert dos_row["lab_correct"] is True
    assert dos_row["et_open_alerted"] is False
    assert dos_row["et_open_correct"] is False  # missed a real attack

    assert normal_row["lab_alerted"] is False
    assert normal_row["lab_correct"] is True
    assert normal_row["et_open_alerted"] is False
    assert normal_row["et_open_correct"] is True


def test_summarize_computes_accuracy_tpr_fpr():
    rows = [
        {"ground_truth_attack_type": "dos_flood", "lab_correct": True, "lab_alerted": True},
        {"ground_truth_attack_type": "brute_force", "lab_correct": False, "lab_alerted": False},
        {"ground_truth_attack_type": "normal", "lab_correct": True, "lab_alerted": False},
        {"ground_truth_attack_type": "normal", "lab_correct": False, "lab_alerted": True},
    ]
    summary = summarize(rows, ["lab"])

    assert summary["total_pcaps"] == 4
    assert summary["lab"]["accuracy"] == 0.5
    assert summary["lab"]["true_positive_rate"] == 0.5  # 1 of 2 attack rows alerted
    assert summary["lab"]["false_positive_rate"] == 0.5  # 1 of 2 normal rows alerted
