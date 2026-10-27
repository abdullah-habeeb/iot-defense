"""Unit tests for defense/objective.py and evaluation/outcome.py."""

from __future__ import annotations

import json
import random

import pytest

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.objective import Objective, load_policy_section
from iot_defense.evaluation.outcome import (
    MIN_BASELINE_PACKETS,
    Measurement,
    OutcomeTable,
    consensus_baseline,
    realized_utility,
    with_baseline,
)

OBJECTIVE = Objective.load()


def measurement(**overrides) -> Measurement:
    base = dict(
        condition="dos_flood", action=DefenseAction.ISOLATE, status="success",
        baseline_packets=100, residual_packets=0, service_loss=1.0, intel_verified=False,
    )
    base.update(overrides)
    return Measurement(**base)


class TestObjective:
    def test_loads_from_yaml_with_a_cost_for_every_action(self):
        assert set(OBJECTIVE.action_cost) == set(DefenseAction)
        assert OBJECTIVE.max_utility == OBJECTIVE.containment + OBJECTIVE.service + OBJECTIVE.intelligence

    def test_missing_action_cost_is_rejected(self):
        data = {"containment": 1, "service": 1, "intelligence": 1, "action_cost": {"ALLOW": 0.0}}
        with pytest.raises(ValueError, match="missing actions"):
            Objective.from_mapping(data)

    def test_attack_utility_is_the_weighted_sum_minus_cost(self):
        value = OBJECTIVE.utility(DefenseAction.DECOY, containment=1.0, service=0.5, intelligence=1.0)
        expected = OBJECTIVE.containment + 0.5 * OBJECTIVE.service + OBJECTIVE.intelligence - OBJECTIVE.action_cost[DefenseAction.DECOY]
        assert value == pytest.approx(expected)

    def test_benign_utility_ignores_containment_and_intelligence(self):
        value = OBJECTIVE.utility(DefenseAction.ALLOW, containment=None, service=1.0, intelligence=1.0)
        assert value == pytest.approx(OBJECTIVE.service)

    def test_missing_section_raises(self):
        with pytest.raises(KeyError):
            load_policy_section("no_such_section")


class TestMeasurement:
    def test_full_containment_and_total_service_loss(self):
        m = measurement()
        assert m.containment == 1.0
        assert m.valid

    def test_containment_is_relative_to_the_unresponded_baseline(self):
        assert measurement(residual_packets=25).containment == pytest.approx(0.75)

    def test_containment_is_clipped_to_minus_one_and_one(self):
        assert measurement(residual_packets=500).containment == -1.0
        assert measurement(residual_packets=0).containment == 1.0

    def test_noise_around_a_no_op_is_not_turned_into_positive_containment(self):
        """Run-to-run count noise must average to ~0 for a useless response;
        clipping at 0 would give it a positive mean."""
        noisy = [measurement(action=DefenseAction.ALERT, residual_packets=r).containment for r in (70, 85, 100, 115, 130)]
        assert sum(noisy) / len(noisy) == pytest.approx(0.0, abs=1e-9)

    def test_with_baseline_rescores_against_the_given_baseline(self):
        m = measurement(baseline_packets=0, residual_packets=10)
        assert not m.valid  # an attack measurement without a baseline never scores
        rebased = with_baseline(m, 40)
        assert rebased.valid and rebased.containment == pytest.approx(0.75)

    def test_consensus_baseline_is_the_rounded_mean_of_allow_probes(self):
        allow = [measurement(action=DefenseAction.ALLOW, residual_packets=r) for r in (100, 111)]
        assert consensus_baseline(allow) == 106

    @pytest.mark.parametrize("bad", [[], [measurement()]])
    def test_consensus_baseline_requires_allow_probes(self, bad):
        with pytest.raises(ValueError, match="ALLOW"):
            consensus_baseline(bad)

    def test_allow_is_its_own_baseline_so_containment_is_zero(self):
        m = measurement(action=DefenseAction.ALLOW, residual_packets=100, service_loss=0.0)
        assert m.containment == 0.0

    def test_benign_condition_has_no_containment(self):
        m = measurement(condition="normal", baseline_packets=0, residual_packets=10)
        assert m.containment is None
        assert m.valid

    def test_a_failed_execution_is_still_a_valid_measurement(self):
        m = measurement(status="failed", residual_packets=100, service_loss=0.0)
        assert m.valid
        assert m.containment == 0.0

    def test_baseline_below_minimum_is_invalid_for_attacks(self):
        assert not measurement(baseline_packets=MIN_BASELINE_PACKETS - 1).valid
        assert measurement(baseline_packets=MIN_BASELINE_PACKETS).valid

    @pytest.mark.parametrize("loss", [-1.0, 1.01])
    def test_out_of_range_service_loss_is_invalid(self, loss):
        assert not measurement(service_loss=loss).valid

    def test_row_round_trip(self):
        m = measurement(residual_packets=7, intel_verified=True)
        assert Measurement.from_row(json.loads(json.dumps(m.to_row()))) == m

    def test_realized_utility_uses_measured_values(self):
        m = measurement(residual_packets=20, service_loss=0.25, intel_verified=True, action=DefenseAction.DECOY)
        expected = OBJECTIVE.utility(DefenseAction.DECOY, containment=0.8, service=0.75, intelligence=1.0)
        assert realized_utility(m, OBJECTIVE) == pytest.approx(expected)


def _rows(*pairs):
    return [measurement(condition=c, action=a, **kw).to_row() for c, a, kw in pairs]


class TestOutcomeTable:
    def test_groups_valid_rows_and_counts_invalid(self):
        rows = _rows(
            ("dos_flood", DefenseAction.ISOLATE, {}),
            ("dos_flood", DefenseAction.ISOLATE, {"residual_packets": 50}),
            ("dos_flood", DefenseAction.ISOLATE, {"service_loss": -1.0}),
        )
        table = OutcomeTable(rows, OBJECTIVE)
        assert len(table.samples("dos_flood", DefenseAction.ISOLATE)) == 2
        assert table.invalid_rows == 1

    def test_mean_and_best_action(self):
        rows = _rows(
            ("dos_flood", DefenseAction.ISOLATE, {}),
            ("dos_flood", DefenseAction.BLOCK_SOURCE, {"service_loss": 0.0}),
        )
        # only two actions measured -> best_action over all would KeyError; use mean directly
        table = OutcomeTable(rows, OBJECTIVE)
        assert table.mean("dos_flood", DefenseAction.BLOCK_SOURCE) > table.mean("dos_flood", DefenseAction.ISOLATE)

    def test_unmeasured_cell_raises_instead_of_defaulting(self):
        table = OutcomeTable([], OBJECTIVE)
        with pytest.raises(KeyError):
            table.mean("dos_flood", DefenseAction.ISOLATE)
        with pytest.raises(KeyError):
            table.sample("dos_flood", DefenseAction.ISOLATE, random.Random(0))

    def test_sample_returns_a_measured_value(self):
        rows = _rows(("dos_flood", DefenseAction.ISOLATE, {}), ("dos_flood", DefenseAction.ISOLATE, {"residual_packets": 50}))
        table = OutcomeTable(rows, OBJECTIVE)
        values = set(table.samples("dos_flood", DefenseAction.ISOLATE))
        assert all(table.sample("dos_flood", DefenseAction.ISOLATE, random.Random(s)) in values for s in range(10))

    def test_require_complete_names_the_missing_cells(self):
        table = OutcomeTable(_rows(("dos_flood", DefenseAction.ISOLATE, {})), OBJECTIVE)
        with pytest.raises(ValueError, match="no valid measurement"):
            table.require_complete(("dos_flood",))
        assert ("dos_flood", "ALLOW") in table.missing_cells(("dos_flood",))

    def test_synthetic_table_is_complete_and_has_the_known_best_action(self, synthetic_table):
        from conftest import synthetic_best_actions
        from iot_defense.defense.ppo_env import TRAINING_SCENARIOS

        synthetic_table.require_complete(TRAINING_SCENARIOS())
        for condition, best in synthetic_best_actions().items():
            assert synthetic_table.best_action(condition) == best

    def test_from_jsonl(self, tmp_path):
        path = tmp_path / "t.jsonl"
        path.write_text(json.dumps(measurement().to_row()) + "\n\n", encoding="utf-8")
        assert len(OutcomeTable.from_jsonl(path).samples("dos_flood", DefenseAction.ISOLATE)) == 1
