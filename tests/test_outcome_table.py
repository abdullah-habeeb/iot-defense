"""Unit tests for evaluation/outcome_table.py's orchestration -- no Mininet."""

from __future__ import annotations

import json

import pytest

from iot_defense.defense.decision import DefenseAction
from iot_defense.detection.threat_event import ThreatEvent
from iot_defense.evaluation import outcome_table
from iot_defense.evaluation.outcome import Measurement


def test_action_order_brackets_the_actions_with_allow_probes():
    order = outcome_table.action_order(11, 0, "dos_flood")
    assert order[0] == order[-1] == DefenseAction.ALLOW and len(order) == outcome_table.BLOCK_ROWS
    assert sorted(a.value for a in order[:-1]) == sorted(a.value for a in DefenseAction)


def test_action_order_is_reproducible_but_differs_across_blocks():
    assert outcome_table.action_order(11, 0, "dos_flood") == outcome_table.action_order(11, 0, "dos_flood")
    orders = {tuple(outcome_table.action_order(11, rep, c)) for rep in range(3) for c in ("dos_flood", "brute_force", "normal")}
    assert len(orders) > 1, "action order must vary across blocks so it cannot be a confound"


def test_completed_blocks_requires_every_action(tmp_path):
    path = tmp_path / "t.jsonl"
    rows = [{"condition": "dos_flood", "rep": 0} for _ in range(outcome_table.BLOCK_ROWS)] + [{"condition": "normal", "rep": 0}] * 3
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    assert outcome_table.completed_blocks(path) == {("dos_flood", 0)}
    assert outcome_table.completed_blocks(tmp_path / "missing.jsonl") == set()


class FakeEnv:
    def _observe_scenario(self, condition):
        return ThreatEvent.from_result(
            source_ip="10.0.0.100", destination_ip="10.0.0.10", attack_type=condition, threat_score=0.9,
            confidence=0.9, detection_reason="t", features={}, detector_name="t",
        )

    def __init__(self, allow_residuals=(100, 120)):
        self.calls: list[DefenseAction] = []
        self._allow = iter(allow_residuals)

    def measure_response(self, action, threat_event, condition):
        self.calls.append(action)
        if action == DefenseAction.ALLOW:
            residual = next(self._allow)
            return Measurement(condition, action, "success", residual, residual, 0.0, False), {"status": "success"}
        return Measurement(condition, action, "success", 0, 10, 0.0, False), {"status": "success"}


def test_summarize_table_reports_every_cell_and_the_allow_baseline(tmp_path):
    from conftest import synthetic_rows

    path = tmp_path / "t.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in synthetic_rows(reps=2)), encoding="utf-8")
    text = outcome_table.summarize_table(path)
    assert "dos_flood" in text and "ISOLATE" in text and "ALLOW baseline packets" in text
    assert "no valid probe" not in text
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps({**synthetic_rows(reps=1)[0], "service_loss": -1.0}) + "\n", encoding="utf-8")
    assert "no valid probe" in outcome_table.summarize_table(bad)


def test_measure_block_averages_the_before_and_after_allow_probes_into_every_rows_baseline(monkeypatch):
    monkeypatch.setattr(outcome_table, "SETTLE_SECONDS", 0.0)
    env = FakeEnv(allow_residuals=(100, 120))
    rows = outcome_table.measure_block(env, "dos_flood", rep=2, seed=11)
    assert env.calls[0] == env.calls[-1] == DefenseAction.ALLOW
    assert len(rows) == outcome_table.BLOCK_ROWS
    assert {r["baseline_packets"] for r in rows} == {110}
    assert sum(r["action"] == "ALLOW" for r in rows) == 2
    assert [r["order_index"] for r in rows] == list(range(outcome_table.BLOCK_ROWS))
    non_allow = next(r for r in rows if r["action"] != "ALLOW")
    assert Measurement.from_row(non_allow).containment == pytest.approx(1 - 10 / 110)
    assert all(r["rep"] == 2 and r["seed"] == 11 and r["probe_error"] is None for r in rows)
    # rows round-trip through Measurement, so the table loader can use them
    assert all(Measurement.from_row(r).valid for r in rows)
