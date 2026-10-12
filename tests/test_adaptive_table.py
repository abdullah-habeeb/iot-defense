"""The reactive-attacker (two-round) measurement and its table.

The Mininet-facing parts run on the same small iptables emulator test_ppo_real_env.py uses, so the
protocol is exercised for real without Mininet.
"""

from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_ppo_real_env import _senders, _threat_event, _wired_env

from iot_defense.attacks.registry import ATTACK_SCENARIOS
from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.objective import Objective
from iot_defense.defense.ppo_real_env import ATTACKER_IP, INVALID_SERVICE_LOSS, PROBE_COMMENT
from iot_defense.evaluation import adaptive_table as table_module
from iot_defense.evaluation.adaptive_outcome import (
    ADAPTIVE_CONDITIONS,
    MITIGATED_FRACTION,
    ROTATION_SOURCE_IP,
    AdaptiveMeasurement,
    AdaptiveOutcomeTable,
    is_mitigated,
    round_containment,
)

OBJECTIVE = Objective.load()
A = DefenseAction


def measurement(action=A.BLOCK_SOURCE, *, b1=100, r1=5, b2=100, r2=90, rotated=True, loss1=0.0, loss2=0.0, intel=False, condition="dos_flood"):
    return AdaptiveMeasurement(condition, action, "success", b1, r1, b2, r2, rotated, loss1, loss2, intel)


class TestUtility:
    def test_is_mitigated_needs_a_usable_baseline_and_a_real_drop(self):
        assert is_mitigated(10, 100) and not is_mitigated(60, 100)
        assert not is_mitigated(0, None)  # nothing has been responded to yet
        assert not is_mitigated(0, 2)  # a baseline too small to judge from
        assert is_mitigated(int(MITIGATED_FRACTION * 100) - 1, 100) and not is_mitigated(int(MITIGATED_FRACTION * 100), 100)

    def test_round_containment_matches_the_standard_definition(self):
        assert round_containment(A.ALLOW, 0, 100) == 0.0  # ALLOW is the baseline itself
        assert round_containment(A.BLOCK_SOURCE, 0, 100) == 1.0 and round_containment(A.BLOCK_SOURCE, 100, 100) == 0.0
        assert round_containment(A.BLOCK_SOURCE, 250, 100) == -1.0  # clipped, not unbounded
        assert round_containment(A.BLOCK_SOURCE, 10, 0) == 0.0

    def test_a_response_that_only_stops_the_first_source_scores_half_the_containment(self):
        dodged = measurement(r1=0, r2=100)  # contained in round 1, fully dodged in round 2
        held = measurement(A.THROTTLE, r1=0, r2=0, rotated=True)
        assert dodged.containments == (1.0, 0.0) and held.containments == (1.0, 1.0)
        gap = held.utility(OBJECTIVE) - dodged.utility(OBJECTIVE)
        # same cost difference aside, the held response gains half the containment weight
        cost_diff = OBJECTIVE.action_cost[A.BLOCK_SOURCE] - OBJECTIVE.action_cost[A.THROTTLE]
        assert gap == pytest.approx(OBJECTIVE.containment * 0.5 + cost_diff)

    def test_utility_averages_the_rounds_and_counts_cost_and_intelligence_once(self):
        m = measurement(A.DECOY, r1=0, r2=50, loss1=0.2, loss2=0.4, intel=True, rotated=False)
        expected = (
            (OBJECTIVE.containment * 1.0 + OBJECTIVE.service * 0.8) + (OBJECTIVE.containment * 0.5 + OBJECTIVE.service * 0.6)
        ) / 2 + OBJECTIVE.intelligence - OBJECTIVE.action_cost[A.DECOY]
        assert m.utility(OBJECTIVE) == pytest.approx(expected)

    def test_validity_rejects_unreadable_probes_and_unusable_baselines(self):
        assert measurement().valid
        assert not measurement(loss1=INVALID_SERVICE_LOSS).valid and not measurement(loss2=1.5).valid
        assert not measurement(b1=2).valid and not measurement(b2=0).valid

    def test_rows_round_trip(self):
        m = measurement(A.QUARANTINE, intel=True)
        assert AdaptiveMeasurement.from_row(json.loads(json.dumps(m.to_row()))) == m


class TestTable:
    DODGED_BY_SWITCHING = (A.BLOCK_SOURCE, A.DECOY, A.RESET_SESSIONS)

    def rows(self):
        """Every action measured (best_action ranges over all of them): source-keyed responses are dodged
        in round 2, the rest keep containing; ALLOW is the plain baseline."""
        rows = []
        for rep in range(3):
            for action in A:
                if action == A.ALLOW:
                    rows.append(measurement(action, b1=100, r1=100, b2=100, r2=100, rotated=False).to_row() | {"rep": rep})
                else:
                    dodged = action in self.DODGED_BY_SWITCHING
                    rows.append(measurement(action, r1=0, r2=95 if dodged else 2, rotated=True).to_row() | {"rep": rep})
        return rows

    def test_the_table_has_the_standard_interface_and_scores_the_two_round_episode(self):
        table = AdaptiveOutcomeTable(self.rows(), OBJECTIVE)
        assert table.best_action("dos_flood") not in self.DODGED_BY_SWITCHING  # the source-keyed ones are dodged
        assert len(table.samples("dos_flood", A.BLOCK_SOURCE)) == 3
        assert table.mean("dos_flood", A.THROTTLE) > table.mean("dos_flood", A.BLOCK_SOURCE)

    def test_rotation_rate_reports_how_often_the_attacker_switched(self):
        table = AdaptiveOutcomeTable(self.rows(), OBJECTIVE)
        assert table.rotation_rate("dos_flood", A.BLOCK_SOURCE) == 1.0 and table.rotation_rate("dos_flood", A.ALLOW) == 0.0
        nan = table.rotation_rate("brute_force", A.ISOLATE)
        assert nan != nan  # never measured

    def test_invalid_rows_are_counted_and_excluded(self):
        rows = self.rows() + [measurement(A.ISOLATE, loss1=INVALID_SERVICE_LOSS).to_row()]
        table = AdaptiveOutcomeTable(rows, OBJECTIVE)
        assert table.invalid_rows == 1 and len(table.samples("dos_flood", A.ISOLATE)) == 3  # the invalid fourth was dropped

    def test_from_jsonl_reads_the_file(self, tmp_path):
        path = tmp_path / "t.jsonl"
        path.write_text("".join(json.dumps(r) + "\n" for r in self.rows()), encoding="utf-8")
        assert AdaptiveOutcomeTable.from_jsonl(path, OBJECTIVE).best_action("dos_flood") not in self.DODGED_BY_SWITCHING


class TestProbe:
    """measure_adaptive on the iptables emulator."""

    def env(self, monkeypatch, counters):
        """counters: residual the sensor's counter reports for round 1, then round 2."""
        env, hosts, log = _wired_env()
        readings = iter(counters)
        calls = {"n": 0}

        def registered(net):
            log.append("traffic:attack")
            hosts["sensor"].counter = next(readings)

        def rotated(net):
            log.append("traffic:rotated")
            hosts["sensor"].counter = next(readings)

        monkeypatch.setattr(env, "_attack_for", lambda condition: SimpleNamespace(
            generate_traffic=registered, traffic_direction="inbound", sender_ips=_senders(condition)))
        monkeypatch.setattr(env, "_rotated_generator", lambda condition, ip: rotated)
        return env, hosts, log, calls

    def test_a_mitigated_round_one_makes_the_attacker_rotate_to_a_fresh_source(self, monkeypatch):
        env, hosts, log, _ = self.env(monkeypatch, [3, 88])
        m, _ = env.measure_adaptive(A.BLOCK_SOURCE, _threat_event(), "dos_flood", baseline1=100)
        assert m.rotated and (m.residual1, m.residual2) == (3, 88)
        assert log == ["execute:BLOCK_SOURCE", "sensor:counter_installed", "traffic:attack", "sensor:counter_removed",
                       "sensor:counter_installed", "traffic:rotated", "sensor:counter_removed", "restore"]
        counters = [c for c in hosts["sensor"].commands if PROBE_COMMENT in c and " -A INPUT" in c]
        assert f"-s {ATTACKER_IP} " in counters[0] and f"-s {ROTATION_SOURCE_IP} " in counters[1]

    def test_an_unmitigated_round_one_means_the_attacker_just_repeats_itself(self, monkeypatch):
        env, hosts, log, _ = self.env(monkeypatch, [96, 97])
        m, _ = env.measure_adaptive(A.THROTTLE, _threat_event(), "dos_flood", baseline1=100)
        assert not m.rotated and "traffic:rotated" not in log and log.count("traffic:attack") == 2
        counters = [c for c in hosts["sensor"].commands if PROBE_COMMENT in c and " -A INPUT" in c]
        assert all(f"-s {ATTACKER_IP} " in c for c in counters)

    def test_the_first_unresponded_probe_never_rotates_and_is_its_own_baseline(self, monkeypatch):
        env, _, log, _ = self.env(monkeypatch, [100, 104])
        m, _ = env.measure_adaptive(A.ALLOW, _threat_event(), "dos_flood", baseline1=None)
        assert not m.rotated and (m.baseline1, m.residual1, m.baseline2, m.residual2) == (100, 100, 104, 104)

    def test_a_non_allow_probe_has_placeholder_baselines_until_the_block_supplies_them(self, monkeypatch):
        env, _, _, _ = self.env(monkeypatch, [3, 88])
        m, _ = env.measure_adaptive(A.BLOCK_SOURCE, _threat_event(), "dos_flood", baseline1=100)
        assert (m.baseline1, m.baseline2) == (0, 0) and not m.valid

    def test_the_counter_is_removed_and_the_response_restored_even_if_round_two_fails(self, monkeypatch):
        env, hosts, log, _ = self.env(monkeypatch, [3, 88])
        monkeypatch.setattr(env, "_rotated_generator", lambda condition, ip: (lambda net: (_ for _ in ()).throw(RuntimeError("generator died"))))
        m, outcome = env.measure_adaptive(A.BLOCK_SOURCE, _threat_event(), "dos_flood", baseline1=100)
        assert "generator died" in outcome["probe_error"] and m.service_loss1 == INVALID_SERVICE_LOSS and not m.valid
        assert hosts["sensor"].installed == 0 and log[-1] == "restore"

    def test_only_conditions_with_a_spoofable_variant_are_accepted(self, monkeypatch):
        env, _, _, _ = self.env(monkeypatch, [1, 1])
        with pytest.raises(ValueError):
            env.measure_adaptive(A.BLOCK_SOURCE, _threat_event(), "brute_force", baseline1=100)
        with pytest.raises(ValueError):
            env.measure_rotated_baseline("normal")

    def test_every_adaptive_condition_is_a_registered_inbound_attack_with_a_rotated_generator(self):
        from iot_defense.defense.ppo_real_env import RealMininetDefenseEnv

        env = RealMininetDefenseEnv()
        registered = {s.attack_type: s for s in ATTACK_SCENARIOS.values()}
        for condition in ADAPTIVE_CONDITIONS:
            assert condition in registered and registered[condition].traffic_direction == "inbound"
            assert not registered[condition].sender_ips  # the single-source original
            assert callable(env._rotated_generator(condition, ROTATION_SOURCE_IP))

    def test_the_rotated_baseline_is_counted_from_the_fresh_source_with_no_response(self, monkeypatch):
        env, hosts, log, _ = self.env(monkeypatch, [77])
        assert env.measure_rotated_baseline("dos_flood") == 77
        assert not any(entry.startswith("execute") for entry in log)
        counter = next(c for c in hosts["sensor"].commands if PROBE_COMMENT in c and " -A INPUT" in c)
        assert f"-s {ROTATION_SOURCE_IP} " in counter


class FakeEnv:
    """Stands in for RealMininetDefenseEnv at the block level: the attacker rotates against any
    response that is not THROTTLE or QUARANTINE."""

    def __init__(self):
        self.calls = []
        self.network_started = False
        self.closed = False

    def _ensure_network(self):
        self.network_started = True

    def close(self):
        self.closed = True

    def _observe_scenario(self, condition):
        return SimpleNamespace(attack_type=condition)

    def measure_rotated_baseline(self, condition, rotated_ip=ROTATION_SOURCE_IP):
        return 400

    def measure_adaptive(self, action, threat_event, condition, baseline1, rotated_ip=ROTATION_SOURCE_IP):
        self.calls.append((action, baseline1))
        holds = action in (A.THROTTLE, A.QUARANTINE, A.ISOLATE)
        mitigated = action != A.ALLOW
        m = AdaptiveMeasurement(
            condition, action, "success",
            baseline1=100 if action == A.ALLOW else 0, residual1=100 if action == A.ALLOW else (2 if mitigated else 100),
            baseline2=100 if action == A.ALLOW else 0, residual2=100 if action == A.ALLOW else (2 if holds else 380),
            rotated=mitigated, service_loss1=0.0, service_loss2=0.0, intel_verified=False,
        )
        return m, {}


class TestBlock:
    def test_a_block_has_eleven_rows_with_consensus_baselines_applied(self, monkeypatch):
        monkeypatch.setattr(table_module, "SETTLE_SECONDS", 0.0)
        env = FakeEnv()
        rows = table_module.measure_block(env, "dos_flood", rep=0, seed=11)
        assert len(rows) == table_module.BLOCK_ROWS == 11
        assert [r["action"] for r in rows][0] == "ALLOW" and [r["action"] for r in rows][-1] == "ALLOW"
        assert {r["baseline1"] for r in rows} == {100}
        assert all(r["baseline2"] == (400 if r["rotated"] else 100) for r in rows)
        assert all(r["rotated_baseline_probes"] == [400, 400] and r["detected_condition"] == "dos_flood" for r in rows)

    def test_the_first_probe_is_judged_against_no_baseline_and_later_ones_against_its_count(self, monkeypatch):
        monkeypatch.setattr(table_module, "SETTLE_SECONDS", 0.0)
        env = FakeEnv()
        table_module.measure_block(env, "dos_flood", rep=0, seed=11)
        assert env.calls[0] == (A.ALLOW, None) and all(b == 100 for _, b in env.calls[1:])

    def test_the_resulting_rows_load_into_a_table_that_prefers_the_responses_that_hold(self, monkeypatch):
        monkeypatch.setattr(table_module, "SETTLE_SECONDS", 0.0)
        rows = table_module.measure_block(FakeEnv(), "dos_flood", rep=0, seed=11)
        table = AdaptiveOutcomeTable(rows, OBJECTIVE)
        assert table.invalid_rows == 0
        assert table.best_action("dos_flood") in (A.THROTTLE, A.QUARANTINE, A.ISOLATE)
        assert table.mean("dos_flood", A.BLOCK_SOURCE) < table.mean("dos_flood", A.THROTTLE)

    def test_run_is_resumable_and_writes_whole_blocks_only(self, monkeypatch, tmp_path):
        monkeypatch.setattr(table_module, "SETTLE_SECONDS", 0.0)
        out = tmp_path / "adaptive.jsonl"
        envs = []
        factory = lambda: envs.append(FakeEnv()) or envs[-1]
        first = table_module.run(reps=1, output_path=out, seed=11, conditions=("dos_flood",), env_factory=factory)
        assert first["new_blocks"] == 1 and table_module.completed_blocks(out) == {("dos_flood", 0)}
        again = table_module.run(reps=1, output_path=out, seed=11, conditions=("dos_flood", "icmp_ping_flood"), env_factory=factory)
        assert again["new_blocks"] == 1 and again["skipped_complete_blocks"] == 1
        assert envs[0].closed and envs[1].closed and envs[0].network_started
        # a block cut short is not complete, so a resume re-measures it
        lines = out.read_text().splitlines()
        out.write_text("\n".join(lines[: len(lines) - 4]) + "\n")
        assert table_module.completed_blocks(out) == {("dos_flood", 0)}

    def test_block_baselines_need_the_allow_probes(self):
        with pytest.raises(ValueError):
            table_module.block_baselines([measurement(A.THROTTLE)], [400])
        same, rotated = table_module.block_baselines([measurement(A.ALLOW, b1=0, r1=100, r2=104, rotated=False)] * 2, [390, 410])
        assert (same, rotated) == (102, 400)

    def test_the_summary_reports_rotation_and_both_rounds(self, monkeypatch, tmp_path):
        monkeypatch.setattr(table_module, "SETTLE_SECONDS", 0.0)
        path = tmp_path / "t.jsonl"
        path.write_text("".join(json.dumps(r) + "\n" for r in table_module.measure_block(FakeEnv(), "dos_flood", 0, 11)))
        text = table_module.summarize_table(path)
        assert "BLOCK_SOURCE" in text and "rotated" in text and "fresh-source" in text
