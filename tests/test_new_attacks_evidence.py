"""The evidence report's checks: each one passes on a coherent history and fails when that history is tampered with."""

from __future__ import annotations

import copy
import json
import subprocess

import pytest
from new_attacks_helpers import DEFAULT_PROFILE, synthetic_rows, valid_prereg

from iot_defense.experiments.new_attacks import common, evidence, measure

SSDP, TELNET = "ssdp_reflection", "telnet_scan_outbound"


def chain(records):
    previous = measure.GENESIS
    for record in records:
        record["prev_record_sha256"] = previous
        previous = common.sha256_text(common.canonical_json(record))
    return records


def good_world(monkeypatch):
    rows = synthetic_rows({SSDP: DEFAULT_PROFILE, TELNET: DEFAULT_PROFILE})
    text = "".join(json.dumps(r) + "\n" for r in rows)
    sha = common.sha256_text(text)
    log = chain([
        {"event": "started", "started_at": "2026-11-02T09:58:00+0000", "rows_lines_before": 0, "rows_sha256_before": None,
         "ntp_synchronized": "yes", "hostname": "vm"},
        {"event": "finished", "finished_at": "2026-11-02T10:10:00+0000", "rows_lines_after": len(rows), "rows_sha256_after": sha, "new_rows": len(rows)},
    ])
    facts = {
        "manifest": {"files": {"a": "1"}, "main_outcome_table_sha256": "ab" * 32, "rows_state": {"exists": False, "lines": 0}},
        "freeze_commit": {"commit": "f" * 40, "committer_time": "2026-11-02T09:00:00+00:00"},
        "prereg_commit": {"commit": "p" * 40, "committer_time": "2026-11-02T08:00:00+00:00"},
        "rows_commit": {"commit": "r" * 40, "committer_time": "2026-11-02T12:00:00+00:00"},
        "run_log": log, "rows": rows, "rows_sha256": sha,
        "smoke": [{"blind_safe": True, "actions_applied": ["ALLOW"]}],
        "git_head": "h" * 40, "drift": [], "results_stored": {"generated_at": "x", "v": 1},
        "github": {"available": True, "push_times": {"freeze": "2026-11-02T09:01:00Z"}, "comment_times": {}},
    }
    monkeypatch.setattr(common, "git", lambda *a, **k: text.rstrip("\n") if a[:1] == ("show",) else "")
    return facts, valid_prereg(), {"generated_at": "y", "v": 1}


def statuses(facts, spec, recomputed):
    return {c["id"]: c["status"] for c in evidence.run_checks(facts, spec=spec, recomputed=recomputed)}


def test_a_coherent_history_passes_every_check(monkeypatch):
    got = statuses(*good_world(monkeypatch))
    assert got == {f"E{i}": "PASS" for i in range(1, 14)}, got


@pytest.mark.parametrize("name,mutate,check,expected", [
    ("a frozen file changed", lambda f: f.update(drift=["analyze.py changed since the freeze"]), "E1", "FAIL"),
    ("a row edited afterwards", lambda f: f.update(rows_sha256="0" * 64), "E6", "FAIL"),
    ("a measurement before the freeze", lambda f: f["rows"][0].update(measured_at="2026-11-02T08:30:00+0000"), "E3", "FAIL"),
    ("a row existed at the freeze", lambda f: f["manifest"].update(rows_state={"exists": True, "lines": 3}), "E5", "FAIL"),
    ("no GitHub evidence", lambda f: f.update(github=None), "E4", "UNVERIFIED"),
    ("the push reached GitHub after the first row", lambda f: f["github"].update(push_times={"freeze": "2026-11-02T10:30:00Z"}), "E4", "FAIL"),
    ("the smoke test applied a response", lambda f: f["smoke"].append({"blind_safe": True, "actions_applied": ["ALLOW", "ISOLATE"]}), "E11", "FAIL"),
    ("no smoke test on record", lambda f: f.update(smoke=[]), "E11", "UNVERIFIED"),
    ("the clock was not synchronised", lambda f: f["run_log"][0].update(ntp_synchronized="no"), "E13", "WARN"),
    ("a block is incomplete", lambda f: f.update(rows=[r for r in f["rows"] if not (r["condition"] == TELNET and r["rep"] == 2 and r["order_index"] == 3)]), "E7", "FAIL"),
    ("a probe failed", lambda f: f["rows"][4].update(probe_error="timeout"), "E7", "FAIL"),
    ("rows are not committed yet", lambda f: f.update(rows_commit={"commit": None}), "E12", "UNVERIFIED"),
    ("rows committed before the last measurement", lambda f: f["rows_commit"].update(committer_time="2026-11-02T10:02:00+00:00"), "E12", "FAIL"),
    ("the old benchmark changed", lambda f: f.update(drift=["main_outcome_table_sha256 changed since the freeze"]), "E9", "FAIL"),
])
def test_each_tampering_is_caught(monkeypatch, name, mutate, check, expected):
    facts, spec, recomputed = good_world(monkeypatch)
    facts = copy.deepcopy(facts)
    mutate(facts)
    assert statuses(facts, spec, recomputed)[check] == expected, name


def test_the_hash_chain_detects_an_edited_or_removed_record(monkeypatch):
    facts, spec, recomputed = good_world(monkeypatch)
    edited = copy.deepcopy(facts)
    edited["run_log"][0]["hostname"] = "somewhere else"
    assert statuses(edited, spec, recomputed)["E6"] == "FAIL"
    removed = copy.deepcopy(facts)
    removed["run_log"].pop(0)
    assert statuses(removed, spec, recomputed)["E6"] == "FAIL"


def test_a_run_whose_rows_changed_between_runs_is_caught(monkeypatch):
    facts, spec, recomputed = good_world(monkeypatch)
    facts = copy.deepcopy(facts)
    second = chain([*facts["run_log"], {"event": "started", "started_at": "2026-11-02T11:00:00+0000", "rows_lines_before": 66,
                                         "rows_sha256_before": "9" * 64, "ntp_synchronized": "yes", "hostname": "vm"}])
    facts["run_log"] = second
    ok, detail = evidence._verify_chain(second, facts["rows_sha256"], 66)
    assert not ok and "between runs" in detail


def test_recomputation_must_match_the_stored_result(monkeypatch):
    facts, spec, recomputed = good_world(monkeypatch)
    assert statuses(facts, spec, {**recomputed, "v": 2})["E10"] == "FAIL"
    assert statuses(facts, spec, None)["E10"] == "UNVERIFIED"


def test_an_invalid_pre_registration_fails_e2(monkeypatch):
    facts, spec, recomputed = good_world(monkeypatch)
    spec["blind_declaration"]["saw_new_attack_measurements"] = True
    assert statuses(facts, spec, recomputed)["E2"] == "FAIL"


class TestGithubEvidence:
    def fake_gh(self, monkeypatch, events, comments):
        def run(command, **kwargs):
            path = command[2]
            payload = events if "/events" in path else comments
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps(payload), stderr="")

        monkeypatch.setattr(evidence.subprocess, "run", run)

    def test_push_and_comment_times_are_found_by_commit(self, monkeypatch):
        events = [{"type": "WatchEvent", "created_at": "x"},
                  {"type": "PushEvent", "created_at": "2026-11-02T09:01:00Z", "payload": {"head": "f" * 40, "commits": [{"sha": "e" * 40}]}},
                  {"type": "PushEvent", "created_at": "2026-11-02T12:01:00Z", "payload": {"head": "z" * 40, "commits": [{"sha": "r" * 40}]}}]
        comments = [{"body": "unrelated", "created_at": "a"}, {"body": f"Frozen at {'f' * 40}", "created_at": "2026-11-02T09:02:00Z"}]
        self.fake_gh(monkeypatch, events, comments)
        found = evidence.github_evidence("o/r", {"freeze": "f" * 40, "rows": "r" * 40}, 1)
        assert found["available"] and found["push_times"] == {"freeze": "2026-11-02T09:01:00Z", "rows": "2026-11-02T12:01:00Z"}
        assert found["comment_times"] == {"freeze": "2026-11-02T09:02:00Z"}

    def test_a_missing_gh_degrades_to_unavailable(self, monkeypatch):
        def broken(command, **kwargs):
            raise FileNotFoundError("gh")

        monkeypatch.setattr(evidence.subprocess, "run", broken)
        assert evidence.github_evidence("o/r", {"freeze": "f" * 40}, 1) == {"available": False, "push_times": {}, "comment_times": {}}


class TestRendering:
    def test_the_page_states_the_verdict_the_checks_and_the_limits(self, monkeypatch):
        facts, spec, recomputed = good_world(monkeypatch)
        checks = evidence.run_checks(facts, spec=spec, recomputed=recomputed)
        result = {
            "criteria": {"overall": "PASS", "passed": 2, "of": 2, "stackelberg_max_regret": 1.0, "not_worse_than_playbook_required": True, "per_attack": {}},
            "primary": {}, "tie_band": 0.25, "known_reference": {"mean_regret": {"stackelberg": 0.042, "rule_based": 2.996}},
            "prior_accuracy": {}, "ppo": "Not applicable.",
        }
        page = evidence.render_html(facts, checks, result, spec)
        assert "Pre-registered verdict: PASS" in page and "E13" in page and "What this does not show" in page and "34% to 100%" in page

    def test_a_page_without_measurements_says_so(self, monkeypatch):
        facts, spec, recomputed = good_world(monkeypatch)
        page = evidence.render_html(facts, evidence.run_checks(facts, spec=spec, recomputed=None), None, spec)
        assert "NOT MEASURED YET" in page

    def test_text_from_the_pre_registration_is_escaped(self, monkeypatch):
        facts, spec, recomputed = good_world(monkeypatch)
        spec["claim"] = "<script>alert(1)</script>"
        page = evidence.render_html(facts, evidence.run_checks(facts, spec=spec, recomputed=recomputed), None, spec)
        assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page

    def test_the_timeline_is_in_time_order_and_names_its_source(self, monkeypatch):
        facts, _, _ = good_world(monkeypatch)
        timeline = evidence._timeline(facts)
        times = [evidence.parse_time(t) for t, _, _ in timeline]
        assert times == sorted(times) and {"git", "run log", "rows file", "GitHub server"} <= {s for _, _, s in timeline}

    @pytest.mark.parametrize("text", ["2026-11-02T10:00:00+0000", "2026-11-02T10:00:00Z", "2026-11-02T10:00:00+05:30"])
    def test_times_are_parsed_with_their_zone(self, text):
        assert evidence.parse_time(text).tzinfo is not None

    def test_an_unparseable_time_is_none(self):
        assert evidence.parse_time("yesterday") is None and evidence.parse_time(None) is None
