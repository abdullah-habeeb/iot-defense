"""The measurement gate, the hash-chained run log and the blind-safe smoke test. No Mininet: the benchmark's own runner is faked."""

from __future__ import annotations

import ast
import inspect
import json

import pytest
from new_attacks_helpers import valid_prereg

from iot_defense.attacks import registry
from iot_defense.defense.decision import DefenseAction
from iot_defense.evaluation import outcome_table
from iot_defense.experiments.new_attacks import common, measure, prereg, smoke


@pytest.fixture()
def sandbox(tmp_path, monkeypatch):
    """Point the experiment at a temporary data directory and a prerequisite-free preflight."""
    rows, log = tmp_path / "rows.jsonl", tmp_path / "run_log.jsonl"
    monkeypatch.setattr(prereg, "verify_freeze", lambda *a, **k: [])
    monkeypatch.setattr(prereg, "validate", lambda *a, **k: [])
    monkeypatch.setattr(prereg, "load", lambda *a, **k: valid_prereg())
    state = {"status": "", "log": "abc123", "head": "H", "upstream": "H"}

    def fake_git(*args, **kwargs):
        if args[:1] == ("status",):
            return state["status"]
        if args[:1] == ("log",):
            return state["log"]
        if args == ("rev-parse", "HEAD"):
            return state["head"]
        if args == ("rev-parse", "@{u}"):
            return state["upstream"]
        return ""

    monkeypatch.setattr(common, "git", fake_git)
    return rows, log, state


class TestPreflight:
    def test_a_frozen_clean_pushed_tree_may_measure(self, sandbox):
        rows, log, _ = sandbox
        assert measure.preflight(rows_path=rows, run_log=log) == []

    def test_every_gate_can_close(self, sandbox, monkeypatch):
        rows, log, state = sandbox
        state["status"] = " M x.py"
        assert any("not clean" in p for p in measure.preflight(rows_path=rows, run_log=log))
        state["status"] = ""
        state["upstream"] = "OTHER"
        assert any("not been pushed" in p for p in measure.preflight(rows_path=rows, run_log=log))
        assert measure.preflight(skip_push_check=True, rows_path=rows, run_log=log) == []
        state["upstream"] = "H"
        state["log"] = ""
        assert any("never been committed" in p for p in measure.preflight(rows_path=rows, run_log=log))
        state["log"] = "abc"
        monkeypatch.setattr(prereg, "verify_freeze", lambda *a, **k: ["analyze.py changed since the freeze"])
        assert any("changed since the freeze" in p for p in measure.preflight(rows_path=rows, run_log=log))

    def test_rows_without_a_log_are_refused(self, sandbox):
        rows, log, _ = sandbox
        rows.write_text(json.dumps({"condition": "x"}) + "\n", encoding="utf-8")
        assert any("no run log" in p for p in measure.preflight(rows_path=rows, run_log=log))

    def test_a_rows_file_edited_outside_a_logged_run_is_refused(self, sandbox, monkeypatch):
        rows, log, _ = sandbox
        monkeypatch.setattr(outcome_table, "run", lambda **kw: kw["output_path"].write_text('{"a": 1}\n') and {})
        measure.run_measurement(1, phase="primary", skip_push_check=False, rows_path=rows, run_log=log)
        assert measure.preflight(rows_path=rows, run_log=log) == []
        rows.write_text('{"a": 2}\n', encoding="utf-8")  # tampered
        assert any("edited outside a logged run" in p for p in measure.preflight(rows_path=rows, run_log=log))


class TestRunLog:
    def test_a_run_writes_two_chained_records_and_leaves_the_registry_untouched(self, sandbox, monkeypatch):
        rows, log, _ = sandbox
        seen = {}

        def fake_run(*, reps, output_path, seed, conditions):
            seen.update(reps=reps, seed=seed, conditions=conditions, registered=set(registry.ATTACK_SCENARIOS) >= set(conditions))
            with output_path.open("a", encoding="utf-8") as fh:
                for i in range(3):
                    fh.write(json.dumps({"i": i}) + "\n")
            return {"new_blocks": 1}

        monkeypatch.setattr(outcome_table, "run", fake_run)
        finished = measure.run_measurement(3, phase="primary", skip_push_check=False, rows_path=rows, run_log=log)
        assert seen == {"reps": 3, "seed": 11, "conditions": ("ssdp_reflection", "telnet_scan_outbound"), "registered": True}
        assert len(registry.ATTACK_SCENARIOS) == 20
        records = common.read_jsonl(log)
        assert [r["event"] for r in records] == ["started", "finished"]
        assert records[0]["prev_record_sha256"] == measure.GENESIS
        assert records[1]["prev_record_sha256"] == common.sha256_text(common.canonical_json(records[0]))
        assert records[0]["rows_lines_before"] == 0 and finished["rows_lines_after"] == 3 and finished["new_rows"] == 3
        assert finished["rows_sha256_after"] == common.sha256_file(rows)
        assert records[0]["rows_sha256_before"] is None and records[0]["phase"] == "primary"

    def test_a_second_run_chains_onto_the_first(self, sandbox, monkeypatch):
        rows, log, _ = sandbox
        monkeypatch.setattr(outcome_table, "run", lambda **kw: kw["output_path"].open("a").write('{"a": 1}\n') and {})
        measure.run_measurement(1, phase="primary", skip_push_check=False, rows_path=rows, run_log=log)
        measure.run_measurement(2, phase="confirmatory", skip_push_check=False, rows_path=rows, run_log=log)
        records = common.read_jsonl(log)
        assert len(records) == 4
        assert records[2]["rows_sha256_before"] == records[1]["rows_sha256_after"]
        assert records[2]["prev_record_sha256"] == common.sha256_text(common.canonical_json(records[1]))

    def test_a_crash_is_logged_not_swallowed(self, sandbox, monkeypatch):
        rows, log, _ = sandbox

        def crash(**kw):
            raise OSError("mininet exploded")

        monkeypatch.setattr(outcome_table, "run", crash)
        with pytest.raises(RuntimeError, match="mininet exploded"):
            measure.run_measurement(1, phase="primary", skip_push_check=False, rows_path=rows, run_log=log)
        records = common.read_jsonl(log)
        assert [r["event"] for r in records] == ["started", "finished"] and "mininet exploded" in records[1]["error"]
        assert len(registry.ATTACK_SCENARIOS) == 20

    def test_the_environment_facts_are_recorded(self):
        facts = measure.environment_facts()
        assert {"hostname", "kernel", "python", "uid", "clock_utc", "ntp_synchronized", "time_zone"} <= set(facts)


class FakeEnv:
    def __init__(self, baseline: int = 40, loss: float = 0.0):
        self.applied: list[DefenseAction] = []
        self.last_attack_protocol = "UDP"
        self.baseline, self.loss = baseline, loss

    def _observe_scenario(self, condition):
        return object()

    def measure_response(self, action, event, condition):
        self.applied.append(action)
        from iot_defense.evaluation.outcome import Measurement

        return Measurement(condition, action, "success", self.baseline, self.baseline, self.loss, False), {"probe_error": None}


class TestSmoke:
    def test_it_applies_only_allow(self, monkeypatch):
        monkeypatch.setattr(smoke.time, "sleep", lambda s: None)
        env = FakeEnv()
        result = smoke.smoke_attack(env, "ssdp_reflection")
        assert set(env.applied) == {DefenseAction.ALLOW} and len(env.applied) == smoke.PROBES_PER_ATTACK
        assert result["baseline_ok"] and result["captured_protocol"] == "UDP"

    def test_a_baseline_below_three_packets_is_a_failure(self, monkeypatch):
        monkeypatch.setattr(smoke.time, "sleep", lambda s: None)
        assert not smoke.smoke_attack(FakeEnv(baseline=2), "ssdp_reflection")["baseline_ok"]
        assert not smoke.smoke_attack(FakeEnv(loss=-1.0), "ssdp_reflection")["baseline_ok"]

    def test_the_module_cannot_name_any_other_response(self):
        tree = ast.parse(inspect.getsource(smoke))
        named = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "DefenseAction"}
        assert named == {"ALLOW"}
