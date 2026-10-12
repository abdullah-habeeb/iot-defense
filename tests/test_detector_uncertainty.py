"""Strategies under detector uncertainty (evaluation/detector_uncertainty.py).

Runs on the synthetic outcome table (see conftest.py), so no Mininet and no trained models are needed.
"""

from __future__ import annotations

from collections import Counter

import numpy as np
import pytest

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.objective import Objective
from iot_defense.defense.ppo_env import DefenseDecisionEnv, TRAINING_SCENARIOS
from iot_defense.evaluation import detector_uncertainty as du
from iot_defense.evaluation.outcome import OutcomeTable

ATTACKS = tuple(c for c in TRAINING_SCENARIOS() if c != "normal")


def draw(sampler, true, n=4000, seed=1):
    rng = np.random.default_rng(seed)
    return Counter(sampler(true, rng) for _ in range(n))


class TestNoiseModels:
    def test_no_noise_reports_the_truth(self):
        for model in ("uniform", "miss", "partner"):
            sampler = du.make_sampler(model, 0.0)
            assert all(draw(sampler, c, n=50) == Counter({c: 50}) for c in TRAINING_SCENARIOS())

    def test_uniform_errors_occur_at_the_stated_rate_and_never_repeat_the_truth(self):
        counts = draw(du.make_sampler("uniform", 0.2), ATTACKS[0])
        assert counts[ATTACKS[0]] / 4000 == pytest.approx(0.8, abs=0.03)
        wrong = {k for k in counts if k != ATTACKS[0]}
        assert len(wrong) > 10 and ATTACKS[0] not in wrong

    def test_miss_turns_attacks_into_normal_and_normal_into_attacks(self):
        sampler = du.make_sampler("miss", 0.3)
        assert set(draw(sampler, ATTACKS[0])) == {ATTACKS[0], "normal"}
        normal = draw(sampler, "normal")
        assert normal["normal"] / 4000 == pytest.approx(0.7, abs=0.03) and set(normal) - {"normal"} <= set(ATTACKS)

    def test_partner_swaps_a_single_source_attack_with_its_distributed_twin_and_nothing_else(self):
        pairs = du.partner_map()
        assert pairs and all(pairs[pairs[a]] == a for a in pairs)  # symmetric
        assert all(a.endswith("_distributed") != b.endswith("_distributed") for a, b in pairs.items())
        single = next(a for a in pairs if not a.endswith("_distributed"))
        counts = draw(du.make_sampler("partner", 0.25), single)
        assert set(counts) == {single, pairs[single]} and counts[pairs[single]] / 4000 == pytest.approx(0.25, abs=0.03)
        unpaired = next(c for c in TRAINING_SCENARIOS() if c not in pairs)
        assert draw(du.make_sampler("partner", 0.5), unpaired, n=100) == Counter({unpaired: 100})

    def test_measured_replays_the_detectors_own_confusions(self):
        confusion = {"c2_beaconing": Counter({"c2_beaconing": 6, "normal": 2})}
        counts = draw(du.make_sampler("measured", 0.0, confusion=confusion), "c2_beaconing")
        assert counts["normal"] / 4000 == pytest.approx(0.25, abs=0.03)
        assert draw(du.make_sampler("measured", 0.0, confusion=confusion), "dos_flood", n=20) == Counter({"dos_flood": 20})

    def test_measured_confusion_is_read_from_the_harness_rows(self):
        rows = [{"arm": "rule_based", "condition": "c2_beaconing", "detected_attack_type": t} for t in ("c2_beaconing", "normal")]
        rows.append({"arm": "ppo", "condition": "c2_beaconing", "detected_attack_type": "ignored"})
        assert du.measured_confusion(rows)["c2_beaconing"] == Counter({"c2_beaconing": 1, "normal": 1})

    def test_mixture_only_returns_known_conditions_and_unknown_models_are_rejected(self):
        assert set(draw(du.make_sampler("mixture", 0.5), ATTACKS[0])) <= set(TRAINING_SCENARIOS())
        with pytest.raises(ValueError):
            du.make_sampler("gaussian", 0.1)


class TestTrainingEnvironmentUsesTheSampler:
    def test_the_reported_label_comes_from_the_sampler_not_the_uniform_error_rate(self, synthetic_table):
        env = DefenseDecisionEnv.from_config(synthetic_table, label_sampler=lambda true, rng: "normal")
        _, info = env.reset(seed=3)
        reported = {info["reported_condition"]}
        for step in range(60):
            _, _, done, _, info = env.step(step % len(DefenseAction))
            reported.add(info["next_reported_condition"])
            if done:
                env.reset()
        assert reported == {"normal"}

    def test_without_a_sampler_behaviour_is_unchanged(self, synthetic_table):
        env = DefenseDecisionEnv.from_config(synthetic_table)
        assert env.label_sampler is None and env.conditions == TRAINING_SCENARIOS()


class TestEvaluation:
    @pytest.fixture(scope="module")
    def table(self, synthetic_table_path):
        return OutcomeTable.from_jsonl(synthetic_table_path, Objective.load())

    @staticmethod
    def best_for_label(table):
        best = {c: table.best_action(c).value for c in TRAINING_SCENARIOS()}
        return lambda contexts, labels: [best[label] for label in labels]

    def test_a_policy_that_trusts_the_label_has_zero_regret_when_the_detector_is_right(self, table):
        result = du.evaluate_setting(table, {"trust": self.best_for_label(table)}, du.make_sampler("uniform", 0.0), 5, seed=1)
        assert result["regret"]["trust"].max() == pytest.approx(0.0)
        assert result["reported"] == result["true"]

    def test_the_same_policy_loses_utility_in_proportion_to_the_detectors_errors(self, table):
        sampler = du.make_sampler("uniform", 0.3)
        result = du.evaluate_setting(table, {"trust": self.best_for_label(table)}, sampler, 60, seed=1)
        wrong = np.array([t != r for t, r in zip(result["true"], result["reported"])])
        assert 0.2 < wrong.mean() < 0.4
        assert result["regret"]["trust"][~wrong].max() == pytest.approx(0.0)
        assert result["regret"]["trust"][wrong].mean() > 0.5

    def test_arms_are_compared_on_identical_draws(self, table):
        fn = self.best_for_label(table)
        result = du.evaluate_setting(table, {"a": fn, "b": fn}, du.make_sampler("miss", 0.2), 10, seed=7)
        summary = du.summarize_setting(result, reference="a")
        assert np.array_equal(result["regret"]["a"], result["regret"]["b"])
        assert summary["vs_a"]["b"]["mean_diff"] == 0.0 and summary["vs_a"]["b"]["equal"] == 1.0
        assert summary["draws"] == 10 * len(TRAINING_SCENARIOS())

    def test_draws_are_reproducible_from_the_seed(self):
        a = du.observations(du.make_sampler("uniform", 0.3), 3, seed=5)
        b = du.observations(du.make_sampler("uniform", 0.3), 3, seed=5)
        assert a[0] == b[0] and a[1] == b[1]

    def test_the_observation_is_of_the_reported_label_not_the_true_one(self):
        true, reported, contexts = du.observations(du.make_sampler("miss", 1.0), 2, seed=2)
        for t, r, context in zip(true, reported, contexts):
            assert r != t and context.beliefs.threat_type == r

    def test_paired_comparison_reports_who_wins_and_by_how_much(self):
        out = du.paired(np.array([0.0, 0.0, 1.0, 1.0]), np.array([1.0, 1.0, 1.0, 1.0]))
        assert out["mean_diff"] == pytest.approx(-0.5) and out["a_better"] == 0.5 and out["equal"] == 0.5 and out["a_worse"] == 0.0
        assert out["ci95"][0] <= out["mean_diff"] <= out["ci95"][1]


class TestPriorsAndPosterior:
    def test_benign_weights_sum_to_one_and_put_the_stated_share_on_normal(self):
        weights = du.benign_weights(0.9)
        assert sum(weights.values()) == pytest.approx(1.0) and weights["normal"] == pytest.approx(0.9)
        assert len({round(w, 9) for c, w in weights.items() if c != "normal"}) == 1

    def test_the_environment_draws_conditions_from_the_prior(self, synthetic_table):
        env = DefenseDecisionEnv.from_config(synthetic_table, condition_weights=du.benign_weights(0.9))
        _, info = env.reset(seed=11)
        drawn = [info["true_condition"]]
        for step in range(1500):
            _, _, done, _, info = env.step(step % len(DefenseAction))
            drawn.append(info["next_true_condition"])
            if done:
                env.reset()
        assert drawn.count("normal") / len(drawn) == pytest.approx(0.9, abs=0.04)

    def test_invalid_condition_weights_are_rejected(self, synthetic_table):
        with pytest.raises(ValueError):
            DefenseDecisionEnv.from_config(synthetic_table, condition_weights={"normal": 0.0})
        with pytest.raises(ValueError):
            DefenseDecisionEnv.from_config(synthetic_table, condition_weights={"normal": -1.0, ATTACKS[0]: 2.0})

    def test_estimated_confusion_rows_are_distributions_that_recover_the_noise_rate(self):
        confusion = du.estimate_confusion(du.make_sampler("miss", 0.3), 2000, seed=3)
        assert all(sum(row.values()) == pytest.approx(1.0) for row in confusion.values())
        assert confusion[ATTACKS[0]]["normal"] == pytest.approx(0.3, abs=0.04)
        assert confusion["normal"]["normal"] == pytest.approx(0.7, abs=0.04)

    def test_stratified_mean_reweights_benign_and_attack_draws(self):
        values, is_normal = np.array([0.0, 0.0, 4.0, 4.0]), np.array([True, True, False, False])
        assert du.stratified_mean(values, is_normal, 0.9) == pytest.approx(0.4)
        assert du.stratified_mean(values, is_normal, 0.5) == pytest.approx(2.0)
        low, high = du.stratified_ci(values, is_normal, 0.5)
        assert low <= 2.0 <= high


class TestTrainingTasks:
    def test_eight_models_with_distinct_paths(self):
        tasks = du.training_tasks()
        kinds = [k for k, _ in tasks]
        assert (kinds.count("deployed"), kinds.count("aware"), kinds.count("aware_prior")) == (2, 3, 3)
        assert len({du.model_path("/m", kind, seed) for kind, seed in tasks}) == 8

    def test_training_is_partitioned_between_workers_and_skips_models_already_on_disk(self, synthetic_table_path, tmp_path):
        calls = []

        weights = {}

        def fake_train(table, **kwargs):
            weights[kwargs["output_path"]] = kwargs["condition_weights"]
            calls.append((kwargs["output_path"], kwargs["label_sampler"] is not None))
            open(kwargs["output_path"] + ".zip", "w").close()
            return {"training_seconds": 0.0}

        first = du.run_training(synthetic_table_path, tmp_path, 1, worker=0, workers=2, train_fn=fake_train)
        second = du.run_training(synthetic_table_path, tmp_path, 1, worker=1, workers=2, train_fn=fake_train)
        assert len(first) + len(second) == 8 and not set(first) & set(second)
        again = du.run_training(synthetic_table_path, tmp_path, 1, worker=0, workers=1, train_fn=fake_train)
        assert again == [] and len(calls) == 8
        assert {aware for path, aware in calls if "aware" in path} == {True}
        assert {aware for path, aware in calls if "deployed" in path} == {False}
        # only the "prior" models are trained at a realistic benign share; the others draw conditions equally
        assert all((w is not None) == ("aware_prior" in path) for path, w in weights.items())
        assert all(w["normal"] == pytest.approx(0.9) for w in weights.values() if w)
