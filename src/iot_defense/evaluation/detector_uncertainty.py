"""Do the strategies still agree when the detector is not always right?

On clean, correctly labelled observations Stackelberg and PPO both pick the measured-best action, so
they score the same. That says little about two *different* strategies, because nothing in that test
exercises what makes them different. A real detector sometimes misses an attack, raises a false
alarm, or confuses one attack for a look-alike. Here every decision is made from an observation the
detector may have got wrong, and is scored against the TRUE condition's measured utility.

Noise models (each draws the label the detector reports, given the true condition):
  uniform   wrong label uniformly among the other conditions
  miss      an attack is reported as normal; normal traffic is reported as a random attack
  partner   a single-source attack is read as its distributed twin, and the reverse (the two
            families whose best responses differ most)
  measured  exactly the confusions the real detector made in the live held-out harness

Arms: rule-based; Stackelberg (uses the reported label); PPO as deployed (trained with 15% uniform
label noise); PPO "aware" (trained on a mixture of all three noise models at 20% with every condition
equally often, so ~5% of its training traffic is benign); PPO "aware+prior" (the same noise, but ~90%
benign, as a deployed learner would see); the plain arbiter (evidence looked up under the REPORTED
label); and the posterior arbiter (evidence averaged over what the label could really mean, given the
detector's error rates and how common each condition is).

Why traffic mix matters: a policy that learns to distrust "normal" is rewarded when nearly everything
is an attack and ruined when nearly everything is benign. Results are therefore reported at a realistic
benign share (90%) as well as with every condition weighted equally.

Limits: observations come from the same canonical contexts the models were trained on, plus jitter;
"aware" PPO is told the structure of the noise through its training, Stackelberg is not, which is
precisely the difference between a learned and a model-based strategy that this tests; conditions are
weighted equally.
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable

import numpy as np

from iot_defense.defense.arbiter import ArbiterPolicy, PosteriorArbiter
from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.policy import RuleBasedDefensePolicy, StackelbergDefensePolicy
from iot_defense.defense.ppo_env import (
    INDEX_TO_ACTION,
    TRAINING_SCENARIOS,
    SecurityContextEncoder,
    load_ppo_training_config,
    noisy_context,
)
from iot_defense.evaluation.outcome import OutcomeTable
from iot_defense.evaluation.outcome_report import bootstrap_mean_ci, load_jsonl

Sampler = Callable[[str, np.random.Generator], str]

DEFAULT_TABLE = "data/outcomes/outcome_table.jsonl"
DEFAULT_HARNESS = "data/evaluation/results_measured.jsonl"
DEFAULT_MODELS_DIR = "data/evaluation/uncertainty_models"
DEFAULT_OUTPUT = "data/evaluation/detector_uncertainty.json"
LEVELS = (0.1, 0.2, 0.3)
PRIOR_BENIGN = 0.9               # share of benign traffic the "prior" policies are built for
SHARES = (1 / 21, 0.9, 0.99)     # benign shares the results are reported at (1/21 = every condition equal)
CALIBRATION_DRAWS = 300          # per condition, to estimate the detector's confusion for the posterior arbiter
NOISE_MODELS = ("uniform", "miss", "partner")
AWARE_LEVEL = 0.2
DEPLOYED_MODEL = "models/ppo_defense"  # the model the demo ships, trained with seed 7
EVAL_SEED = 20261011


# ── noise models ──────────────────────────────────────────────────────────────
def partner_map(conditions: tuple[str, ...] = ()) -> dict[str, str]:
    """single-source attack <-> its distributed twin (e.g. dos_flood <-> dos_flood_distributed)."""
    conditions = conditions or TRAINING_SCENARIOS()
    pairs: dict[str, str] = {}
    for condition in conditions:
        if condition.endswith("_distributed") and condition[: -len("_distributed")] in conditions:
            base = condition[: -len("_distributed")]
            pairs[condition], pairs[base] = base, condition
    return pairs


def measured_confusion(harness_rows: list[dict[str, Any]]) -> dict[str, Counter]:
    """What the real detector reported for each true condition in the live held-out harness
    (every arm shares one detection per trial, so one arm's rows suffice)."""
    confusion: dict[str, Counter] = defaultdict(Counter)
    for row in harness_rows:
        if row["arm"] == "rule_based":
            confusion[row["condition"]][row["detected_attack_type"]] += 1
    return confusion


def make_sampler(
    model: str, level: float, conditions: tuple[str, ...] | None = None, confusion: dict[str, Counter] | None = None
) -> Sampler:
    conditions = conditions or TRAINING_SCENARIOS()
    attacks = tuple(c for c in conditions if c != "normal")
    partners = partner_map(conditions)

    def uniform(true: str, rng: np.random.Generator) -> str:
        if rng.random() < level:
            return str(rng.choice([c for c in conditions if c != true]))
        return true

    def miss(true: str, rng: np.random.Generator) -> str:
        if rng.random() < level:
            return str(rng.choice(attacks)) if true == "normal" else "normal"
        return true

    def partner(true: str, rng: np.random.Generator) -> str:
        if true in partners and rng.random() < level:
            return partners[true]
        return true

    def measured(true: str, rng: np.random.Generator) -> str:
        counts = (confusion or {}).get(true)
        if not counts:
            return true
        labels = list(counts)
        weights = np.array([counts[label] for label in labels], dtype=float)
        return str(rng.choice(labels, p=weights / weights.sum()))

    def mixture(true: str, rng: np.random.Generator) -> str:
        return (uniform, miss, partner)[int(rng.integers(0, 3))](true, rng)

    samplers = {"uniform": uniform, "miss": miss, "partner": partner, "measured": measured, "mixture": mixture}
    if model not in samplers:
        raise ValueError(f"unknown noise model {model!r}; expected one of {sorted(samplers)}")
    return samplers[model]


def benign_weights(benign_share: float, conditions: tuple[str, ...] | None = None) -> dict[str, float]:
    """Probability of each true condition when `benign_share` of traffic is benign and the attacks
    share the remainder equally."""
    conditions = conditions or TRAINING_SCENARIOS()
    attacks = [c for c in conditions if c != "normal"]
    return {c: (benign_share if c == "normal" else (1.0 - benign_share) / len(attacks)) for c in conditions}


def estimate_confusion(sampler: Sampler, draws: int, seed: int, smoothing: float = 0.5) -> dict[str, dict[str, float]]:
    """P(reported | true) estimated from `draws` calibration observations per condition (Laplace-smoothed),
    which is what a deployment could learn about its own detector from labelled history."""
    rng = np.random.default_rng(seed)
    labels = TRAINING_SCENARIOS()
    confusion: dict[str, dict[str, float]] = {}
    for true in labels:
        counts = Counter(sampler(true, rng) for _ in range(draws))
        total = draws + smoothing * len(labels)
        confusion[true] = {r: (counts.get(r, 0) + smoothing) / total for r in labels}
    return confusion


def stratified_mean(values: np.ndarray, is_normal: np.ndarray, benign_share: float) -> float:
    return float(benign_share * values[is_normal].mean() + (1.0 - benign_share) * values[~is_normal].mean())


def stratified_ci(values: np.ndarray, is_normal: np.ndarray, benign_share: float, seed: int = 0, resamples: int = 1000) -> list[float]:
    """Bootstrap interval for the benign-share-weighted mean, resampling benign and attack draws separately."""
    rng = np.random.default_rng(seed)
    normal, attack = values[is_normal], values[~is_normal]
    means = (benign_share * rng.choice(normal, size=(resamples, len(normal))).mean(axis=1)
             + (1.0 - benign_share) * rng.choice(attack, size=(resamples, len(attack))).mean(axis=1))
    low, high = np.percentile(means, [2.5, 97.5])
    return [float(low), float(high)]


# ── evaluation ────────────────────────────────────────────────────────────────
DecideFn = Callable[[list[Any], list[str]], list[str]]  # (contexts, reported labels) -> action values


def observations(sampler: Sampler, trials_per_condition: int, seed: int) -> tuple[list[str], list[str], list[Any]]:
    """Draw (true, reported, context) for every condition. The context is the detector's jittered
    observation OF THE REPORTED LABEL, exactly as the training environment builds it."""
    config = load_ppo_training_config()
    rng = np.random.default_rng(seed)
    true_labels: list[str] = []
    reported_labels: list[str] = []
    contexts: list[Any] = []
    for true in TRAINING_SCENARIOS():
        for _ in range(trials_per_condition):
            reported = sampler(true, rng)
            context, _ = noisy_context(
                reported, rng, label_error_rate=0.0,
                score_sigma=float(config["score_noise_sigma"]), feature_jitter=float(config["feature_jitter"]),
            )
            true_labels.append(true)
            reported_labels.append(reported)
            contexts.append(context)
    return true_labels, reported_labels, contexts


def regrets(table: OutcomeTable, true_labels: list[str], actions: list[str]) -> np.ndarray:
    best = {c: table.mean(c, table.best_action(c)) for c in set(true_labels)}
    return np.array([best[t] - table.mean(t, DefenseAction(a)) for t, a in zip(true_labels, actions)])


def evaluate_setting(
    table: OutcomeTable, decide: dict[str, DecideFn], sampler: Sampler, trials_per_condition: int, seed: int
) -> dict[str, Any]:
    true_labels, reported_labels, contexts = observations(sampler, trials_per_condition, seed)
    actions = {name: fn(contexts, reported_labels) for name, fn in decide.items()}
    per_draw = {name: regrets(table, true_labels, chosen) for name, chosen in actions.items()}
    return {"true": true_labels, "reported": reported_labels, "actions": actions, "regret": per_draw}


def paired(a: np.ndarray, b: np.ndarray) -> dict[str, Any]:
    diff = a - b
    low, high = bootstrap_mean_ci(diff)
    return {"mean_diff": float(diff.mean()), "ci95": [low, high], "a_better": float((diff < -1e-9).mean()),
            "equal": float((np.abs(diff) <= 1e-9).mean()), "a_worse": float((diff > 1e-9).mean())}


def summarize_setting(result: dict[str, Any], reference: str = "stackelberg") -> dict[str, Any]:
    regret = result["regret"]
    mean = {name: float(values.mean()) for name, values in regret.items()}
    ci = {name: list(bootstrap_mean_ci(values)) for name, values in regret.items()}
    wrong = np.array([t != r for t, r in zip(result["true"], result["reported"])])
    is_normal = np.array([t == "normal" for t in result["true"]])
    summary: dict[str, Any] = {
        "draws": len(result["true"]),
        "detector_wrong": float(wrong.mean()),
        "mean_regret": mean,
        "mean_regret_ci95": ci,
        "mean_regret_when_detector_wrong": {n: float(v[wrong].mean()) if wrong.any() else None for n, v in regret.items()},
        # Split by what was really on the wire, so the result can be re-weighted to a realistic traffic mix.
        "regret_by_truth": {
            n: {"normal": float(v[is_normal].mean()), "attack": float(v[~is_normal].mean())} for n, v in regret.items()
        },
        "vs_" + reference: {
            name: paired(regret[name], regret[reference]) for name in regret if name != reference
        },
    }
    summary["by_share"] = {}
    for share in SHARES:
        entry: dict[str, Any] = {"mean_regret": {n: stratified_mean(v, is_normal, share) for n, v in regret.items()}, "vs_" + reference: {}}
        for name, values in regret.items():
            if name != reference:
                diff = values - regret[reference]
                entry["vs_" + reference][name] = {
                    "mean_diff": stratified_mean(diff, is_normal, share), "ci95": stratified_ci(diff, is_normal, share),
                }
        summary["by_share"][f"{share:.4f}"] = entry
    if "ppo_deployed" in result["actions"] and reference in result["actions"]:
        same = np.array([a == b for a, b in zip(result["actions"][reference], result["actions"]["ppo_deployed"])])
        summary["stackelberg_same_action_as_ppo_deployed"] = float(same.mean())
    return summary


# ── policies as batch decision functions ──────────────────────────────────────
def _proposal(action: str) -> DefenseDecision:
    return DefenseDecision.create(
        action=DefenseAction(action), target_ip="10.0.0.10", source_ip="10.0.0.100", reason="proposal",
        confidence=0.0, threat_score=0.0, policy_name="proposal", context={},
    )


def rule_fn() -> DecideFn:
    policy = RuleBasedDefensePolicy()
    return lambda contexts, _labels: [policy.decide(c).action.value for c in contexts]


def stackelberg_fn() -> DecideFn:
    policy = StackelbergDefensePolicy()
    return lambda contexts, _labels: [policy.decide(c).action.value for c in contexts]


def ppo_fn(model_path: str) -> DecideFn:
    from stable_baselines3 import PPO

    model = PPO.load(model_path, device="cpu")
    encoder = SecurityContextEncoder()

    def decide(contexts: list[Any], _labels: list[str]) -> list[str]:
        observation = np.stack([encoder.encode(c) for c in contexts])
        chosen, _ = model.predict(observation, deterministic=True)
        return [INDEX_TO_ACTION[int(i)].value for i in chosen]

    return decide


def arbiter_fn(table: OutcomeTable, rule: DecideFn, stack: DecideFn, ppo: DecideFn) -> DecideFn:
    """The arbiter's evidence is keyed by the label it is GIVEN, which live is the detector's."""
    arbiter = ArbiterPolicy(table)

    def decide(contexts: list[Any], labels: list[str]) -> list[str]:
        r, s, p = rule(contexts, labels), stack(contexts, labels), ppo(contexts, labels)
        return [
            arbiter.arbitrate(label, {"rule_based": _proposal(a), "stackelberg": _proposal(b), "ppo": _proposal(c)}).action.value
            for label, a, b, c in zip(labels, r, s, p)
        ]

    return decide


def posterior_arbiter_fn(
    table: OutcomeTable, rule: DecideFn, stack: DecideFn, ppo: DecideFn,
    confusion: dict[str, dict[str, float]], prior: dict[str, float],
) -> DecideFn:
    arbiter = PosteriorArbiter(table, confusion=confusion, prior=prior)

    def decide(contexts: list[Any], labels: list[str]) -> list[str]:
        r, s, p = rule(contexts, labels), stack(contexts, labels), ppo(contexts, labels)
        return [
            arbiter.arbitrate(label, {"rule_based": _proposal(a), "stackelberg": _proposal(b), "ppo": _proposal(c)}).action.value
            for label, a, b, c in zip(labels, r, s, p)
        ]

    return decide


def averaged(fns: list[DecideFn]) -> Callable[[list[Any], list[str]], list[list[str]]]:
    return lambda contexts, labels: [fn(contexts, labels) for fn in fns]


# ── training the models this experiment needs ─────────────────────────────────
def training_tasks() -> list[tuple[str, int]]:
    return [("deployed", 1), ("deployed", 2), ("aware", 1), ("aware", 2), ("aware", 3),
            ("aware_prior", 1), ("aware_prior", 2), ("aware_prior", 3)]


def model_path(models_dir: str | Path, kind: str, seed: int) -> str:
    return str(Path(models_dir) / f"{kind}_s{seed}")


def run_training(
    table_path: str | Path, models_dir: str | Path, timesteps: int, worker: int = 0, workers: int = 1,
    train_fn: Callable[..., dict[str, Any]] | None = None,
) -> list[str]:
    """Train this worker's share of the models, skipping any already on disk (resumable)."""
    from iot_defense.simulation.train_ppo import train_on_table

    train_fn = train_fn or train_on_table
    table = OutcomeTable.from_jsonl(table_path)
    Path(models_dir).mkdir(parents=True, exist_ok=True)
    done: list[str] = []
    for index, (kind, seed) in enumerate(training_tasks()):
        if index % workers != worker:
            continue
        path = model_path(models_dir, kind, seed)
        if Path(path + ".zip").exists():
            continue
        sampler = make_sampler("mixture", AWARE_LEVEL) if kind.startswith("aware") else None
        weights = benign_weights(PRIOR_BENIGN) if kind == "aware_prior" else None
        info = train_fn(table, total_timesteps=timesteps, output_path=path, seed=seed, label_sampler=sampler,
                        condition_weights=weights)
        print(f"[uncertainty] trained {kind} seed {seed} ({info['training_seconds']}s)", flush=True)
        done.append(path)
    return done


# ── report ────────────────────────────────────────────────────────────────────
ARMS = ("rule_based", "stackelberg", "ppo_deployed", "ppo_aware", "ppo_aware_prior", "arbiter", "arbiter_posterior")


def build_report(table_path: str, harness_path: str, models_dir: str, trials: int) -> dict[str, Any]:
    table = OutcomeTable.from_jsonl(table_path)
    confusion = measured_confusion(load_jsonl(harness_path))
    rule, stack = rule_fn(), stackelberg_fn()
    families = {
        "ppo_deployed": [DEPLOYED_MODEL] + [model_path(models_dir, "deployed", s) for s in (1, 2)],
        "ppo_aware": [model_path(models_dir, "aware", s) for s in (1, 2, 3)],
        "ppo_aware_prior": [model_path(models_dir, "aware_prior", s) for s in (1, 2, 3)],
    }
    missing = [p for paths in families.values() for p in paths if not Path(p + ".zip").exists()]
    if missing:
        raise SystemExit(f"models not trained yet: {missing}; run the `train` command first")
    fns = {family: [ppo_fn(p) for p in paths] for family, paths in families.items()}
    prior = benign_weights(PRIOR_BENIGN)

    settings: list[tuple[str, float | None]] = [("clean", None)] + [(m, p) for m in NOISE_MODELS for p in LEVELS] + [("measured", None)]
    out: dict[str, Any] = {"trials_per_condition": trials, "models": families, "prior_benign": PRIOR_BENIGN, "shares": list(SHARES),
                           "measured_confusion": {k: dict(v) for k, v in confusion.items() if any(l != k for l in v)}, "settings": {}}
    for index, (model, level) in enumerate(settings):
        if model == "clean":
            sampler = make_sampler("uniform", 0.0)
        elif model == "measured":
            sampler = make_sampler("measured", 0.0, confusion=confusion)
        else:
            sampler = make_sampler(model, float(level))
        seed = EVAL_SEED + index
        decide: dict[str, DecideFn] = {"rule_based": rule, "stackelberg": stack}
        for family, family_fns in fns.items():
            for i, fn in enumerate(family_fns):
                decide[f"{family}#{i}"] = fn
        decide["arbiter"] = arbiter_fn(table, rule, stack, fns["ppo_deployed"][0])
        # the posterior arbiter knows only what a deployment could: its detector's calibration history and the traffic mix
        estimated = estimate_confusion(sampler, CALIBRATION_DRAWS, seed + 10_000)
        decide["arbiter_posterior"] = posterior_arbiter_fn(table, rule, stack, fns["ppo_deployed"][0], estimated, prior)
        result = evaluate_setting(table, decide, sampler, trials, seed)
        # average each PPO family over its seeds, per draw, so a draw is judged on the family
        for family, family_fns in fns.items():
            result["regret"][family] = np.mean([result["regret"].pop(f"{family}#{i}") for i in range(len(family_fns))], axis=0)
            result["actions"][family] = result["actions"][f"{family}#0"]
            for i in range(len(family_fns)):
                result["actions"].pop(f"{family}#{i}", None)
        out["settings"][model + ("" if level is None else f"@{level}")] = summarize_setting(result)
        print(f"[uncertainty] done {model} {level}", flush=True)
    return out


def _share_key(share: float) -> str:
    return f"{share:.4f}"


def render_markdown(report: dict[str, Any]) -> str:
    lines = ["# Strategies under detector uncertainty", "",
             f"{report['trials_per_condition']} draws per condition (21 conditions) per setting; PPO families are averaged over 3 seeds each. "
             "Mean regret against the TRUE condition's measured utility (lower is better; 0 = the measured-best action). "
             "'wrong' = share of draws where the detector mislabelled.", ""]
    for share, title in ((0.9, "Realistic traffic: 90% benign"), (SHARES[0], "Every condition equally often (~5% benign)"), (0.99, "99% benign")):
        key = _share_key(share)
        lines += [f"## {title}", "", "| Setting | wrong | " + " | ".join(ARMS) + " | aware+prior − Stackelberg | posterior arbiter − Stackelberg |",
                  "|---|---|" + "---|" * len(ARMS) + "---|---|"]
        for name, s in report["settings"].items():
            entry = s["by_share"][key]
            d1, d2 = entry["vs_stackelberg"]["ppo_aware_prior"], entry["vs_stackelberg"]["arbiter_posterior"]
            lines.append(f"| {name} | {s['detector_wrong']:.1%} | " + " | ".join(f"{entry['mean_regret'][a]:.2f}" for a in ARMS)
                         + f" | {d1['mean_diff']:+.2f} [{d1['ci95'][0]:+.2f}, {d1['ci95'][1]:+.2f}]"
                         + f" | {d2['mean_diff']:+.2f} [{d2['ci95'][0]:+.2f}, {d2['ci95'][1]:+.2f}] |")
        lines.append("")
    lines += ["The last two columns are the arm's mean regret minus Stackelberg's: negative means the arm is better "
              "(bootstrap 95% interval, benign and attack draws resampled separately).", ""]
    confusion = report.get("measured_confusion")
    if confusion:
        lines.append("Real detector confusions in the live harness: " + "; ".join(f"{t} read as {dict(c)}" for t, c in confusion.items()) + ".")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    train_p = sub.add_parser("train", help="train the extra PPO models (resumable)")
    train_p.add_argument("--table", default=DEFAULT_TABLE)
    train_p.add_argument("--models-dir", default=DEFAULT_MODELS_DIR)
    train_p.add_argument("--timesteps", type=int, default=None)
    train_p.add_argument("--worker", type=int, default=0)
    train_p.add_argument("--workers", type=int, default=1)
    an_p = sub.add_parser("analyze", help="evaluate every arm under each noise model and write the report")
    an_p.add_argument("--table", default=DEFAULT_TABLE)
    an_p.add_argument("--harness", default=DEFAULT_HARNESS)
    an_p.add_argument("--models-dir", default=DEFAULT_MODELS_DIR)
    an_p.add_argument("--trials", type=int, default=200)
    an_p.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    if args.command == "train":
        timesteps = args.timesteps or int(load_ppo_training_config()["training_timesteps"])
        run_training(args.table, args.models_dir, timesteps, args.worker, args.workers)
        return
    began = time.time()
    report = build_report(args.table, args.harness, args.models_dir, args.trials)
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    markdown = render_markdown(report)
    Path(args.output).with_suffix(".md").write_text(markdown + "\n", encoding="utf-8")
    print(markdown)
    print(f"\n[uncertainty] analysis took {time.time() - began:.0f}s")


if __name__ == "__main__":
    main()
