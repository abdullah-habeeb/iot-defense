"""Grading the frozen policies on synthetic measured rows, and the check that this pipeline reproduces the known benchmark numbers."""

from __future__ import annotations

import copy
import json

import pytest
from new_attacks_helpers import DEFAULT_PROFILE, new_class_entry, synthetic_rows, valid_prereg, write_prereg

from iot_defense.attacks import registry
from iot_defense.defense.decision import DefenseAction
from iot_defense.experiments.new_attacks import analyze, common

MAIN_TABLE = common.MAIN_TABLE_PATH
pytestmark = pytest.mark.skipif(not MAIN_TABLE.exists(), reason="the 693-row benchmark is not present")

SSDP, TELNET = "ssdp_reflection", "telnet_scan_outbound"


def profiles(**best):
    """Both attacks share the default profile except for the overrides in `best` (attack -> {action: (c, loss, intel)})."""
    return {SSDP: {**DEFAULT_PROFILE, **best.get(SSDP, {})}, TELNET: {**DEFAULT_PROFILE, **best.get(TELNET, {})}}


def run(tmp_path, spec=None, rows=None):
    spec_path, rows_path = tmp_path / "prereg.yaml", tmp_path / "rows.jsonl"
    write_prereg(spec_path, spec or valid_prereg())
    rows_path.write_text("".join(json.dumps(r) + "\n" for r in (rows if rows is not None else synthetic_rows(profiles()))), encoding="utf-8")
    return analyze.analyze(rows_path, prereg_path=spec_path)


class TestKnownBenchmark:
    def test_the_same_pipeline_reproduces_the_headline_numbers(self, tmp_path):
        reference = run(tmp_path)["known_reference"]
        assert reference["situations"] == 21
        assert reference["mean_regret"]["stackelberg"] == pytest.approx(0.042, abs=0.001)
        assert reference["mean_regret"]["rule_based"] == pytest.approx(2.996, abs=0.001)


class TestGrading:
    def test_the_registry_is_restored_and_every_policy_is_graded(self, tmp_path):
        result = run(tmp_path)
        assert len(registry.ATTACK_SCENARIOS) == 20
        for key in (SSDP, TELNET):
            entry = result["primary"][key]
            assert entry["status"] == "OK" and entry["complete_blocks"] == [0, 1, 2]
            assert set(entry["policies"]) == set(analyze.POLICIES)

    def test_regret_is_best_mean_minus_the_chosen_mean(self, tmp_path):
        result = run(tmp_path)
        entry = result["primary"][SSDP]
        means = entry["mean_utility"]
        best = max(means.values())
        assert entry["best_mean"] == pytest.approx(best)
        for name, policy in entry["policies"].items():
            assert policy["regret"] == pytest.approx(best - means[policy["action"]], abs=1e-4)
            assert policy["rank"] == 1 + sum(1 for m in means.values() if m > means[policy["action"]] + 1e-9)
            assert len(policy["regret_by_block"]) == 3

    def test_the_playbook_follows_the_frozen_entry_and_the_baselines_are_what_they_say(self, tmp_path):
        result = run(tmp_path)
        assert result["decisions"][SSDP]["rule_based"] == "BANDWIDTH_CAP" and result["decisions"][TELNET]["rule_based"] == "QUARANTINE"
        for key in (SSDP, TELNET):
            assert result["decisions"][key]["fixed_quarantine"] == "QUARANTINE" and result["decisions"][key]["allow"] == "ALLOW"
        assert result["decisions"][SSDP]["nearest_known_attack_name"] == "dns_amplification"

    def test_a_known_class_is_decided_exactly_as_for_its_known_attacks(self, tmp_path):
        """ssdp_reflection reuses the 'reflection' class, so Stackelberg must choose what it chooses for dns_amplification."""
        result = run(tmp_path)
        from iot_defense.defense.game_model import build_game_payoffs
        from iot_defense.defense.policy import StackelbergDefensePolicy
        from iot_defense.defense.ppo_env import context_for_scenario
        from iot_defense.defense.stackelberg import StackelbergGame

        known = StackelbergDefensePolicy(game=StackelbergGame(payoffs=build_game_payoffs())).decide(context_for_scenario("dns_amplification"))
        assert result["decisions"][SSDP]["stackelberg"] == known.action.value
        assert result["decisions"][SSDP]["class"] == "reflection"

    def test_a_new_class_changes_only_the_new_attack(self, tmp_path):
        spec = valid_prereg()
        spec["attacks"][TELNET].update({"attack_class": "NEW", "new_class": new_class_entry("scan_out")})
        result = run(tmp_path, spec)
        assert result["decisions"][TELNET]["class"] == "scan_out"
        assert result["decisions"][SSDP]["stackelberg"] == run(tmp_path, valid_prereg())["decisions"][SSDP]["stackelberg"]

    def test_the_priors_error_is_reported_per_action(self, tmp_path):
        accuracy = run(tmp_path)["prior_accuracy"][SSDP]
        assert set(accuracy["error_by_action"]) == {a.value for a in DefenseAction}
        assert accuracy["mean_absolute_error"] >= 0 and accuracy["largest_error_action"] in accuracy["error_by_action"]

    def test_ppo_is_declared_not_applicable(self, tmp_path):
        assert "Not applicable" in run(tmp_path)["ppo"]


class TestCriteria:
    def make(self, tmp_path, ceiling=1.0, not_worse=True, make_stackelberg_best=True):
        """Rows in which the response Stackelberg picks is (or is not) clearly the best one."""
        spec = valid_prereg()
        spec["success_criteria"] = {"stackelberg_max_regret": ceiling, "stackelberg_not_worse_than_playbook": not_worse}
        picks = run(tmp_path, spec)["decisions"]
        overrides = {}
        for key in (SSDP, TELNET):
            chosen = picks[key]["stackelberg"]
            if make_stackelberg_best:
                overrides[key] = {chosen: (1.0, 0.0, True)}          # the best utility on the table: 5 + 3 + 2 - cost
            else:
                overrides[key] = {"BLOCK_SOURCE" if chosen != "BLOCK_SOURCE" else "QUARANTINE": (1.0, 0.0, True), chosen: (0.0, 1.0, False)}
        return run(tmp_path, spec, synthetic_rows(profiles(**overrides)))

    def test_it_passes_when_stackelberg_chose_the_best_response(self, tmp_path):
        result = self.make(tmp_path)
        assert result["criteria"]["overall"] == "PASS" and result["criteria"]["passed"] == 2
        assert all(result["primary"][k]["policies"]["stackelberg"]["regret"] == 0.0 for k in (SSDP, TELNET))

    def test_it_fails_when_stackelberg_chose_a_bad_response(self, tmp_path):
        result = self.make(tmp_path, make_stackelberg_best=False)
        assert result["criteria"]["overall"] == "FAIL"
        assert all(v["verdict"] == "FAIL" for v in result["criteria"]["per_attack"].values())

    def test_the_regret_ceiling_is_what_the_pre_registration_says(self, tmp_path):
        loose = self.make(tmp_path, ceiling=100.0, not_worse=False, make_stackelberg_best=False)
        assert loose["criteria"]["overall"] == "PASS"  # a huge ceiling and no playbook requirement: any choice passes
        tight = self.make(tmp_path, ceiling=0.0001, not_worse=False, make_stackelberg_best=False)
        assert tight["criteria"]["overall"] == "FAIL"

    def test_missing_blocks_make_the_verdict_incomplete(self, tmp_path):
        result = run(tmp_path, rows=[r for r in synthetic_rows(profiles()) if not (r["rep"] == 2 and r["condition"] == TELNET)])
        assert result["criteria"]["per_attack"][TELNET]["verdict"] == "INCOMPLETE" and result["criteria"]["overall"] == "INCOMPLETE"
        assert result["primary"][TELNET]["complete_blocks"] == [0, 1]

    def test_a_half_written_block_is_not_counted(self, tmp_path):
        rows = synthetic_rows(profiles())
        rows = [r for r in rows if not (r["rep"] == 1 and r["condition"] == SSDP and r["order_index"] == 5)]
        assert 1 not in run(tmp_path, rows=rows)["primary"][SSDP]["complete_blocks"]

    def test_confirmatory_blocks_are_reported_apart_and_do_not_change_the_verdict(self, tmp_path):
        base = run(tmp_path, rows=synthetic_rows(profiles()))
        more = run(tmp_path, rows=synthetic_rows(profiles(), reps=6))
        assert base["confirmatory"] is None and more["confirmatory"][SSDP]["complete_blocks"] == [3, 4, 5]
        assert more["criteria"] == base["criteria"] and more["primary"] == base["primary"]


class TestRenderingAndFreezeCheck:
    def test_markdown_lists_every_policy_and_the_verdict(self, tmp_path):
        text = analyze.render_markdown(run(tmp_path))
        assert "Pre-registered verdict" in text and all(label in text for label in analyze.POLICY_LABELS.values())
        assert "0.042" in text and "PPO" in text

    def test_an_invalid_pre_registration_is_refused(self, tmp_path):
        spec = valid_prereg()
        spec["status"] = "TEMPLATE"
        with pytest.raises(ValueError, match="not valid"):
            run(tmp_path, spec)

    def test_the_result_is_deterministic(self, tmp_path):
        first, second = run(tmp_path), run(tmp_path)
        strip = lambda r: {k: v for k, v in copy.deepcopy(r).items() if k != "generated_at"}
        assert strip(first) == strip(second)
