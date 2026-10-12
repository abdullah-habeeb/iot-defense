"""How do the strategies fare against an attacker that reacts to the response?

Reads the adaptive outcome table (evaluation/adaptive_table.py: each response measured over two rounds
against a scripted attacker that switches source address once its traffic is impeded) and asks:

1. Which arm picks the response that does best over both rounds? Arms: rule-based; Stackelberg as
   deployed (its game has no notion of the attacker switching address); Stackelberg anticipating
   rotation (config policy.game_model.follower_rotation, written from mechanism knowledge BEFORE any
   adaptive measurement); PPO trained on the standard table (never saw a reactive attacker); PPO trained
   on the adaptive table (the standard table with the adaptive conditions' cells replaced; scored on the
   table it learned from, so an upper bound, not a held-out result); and the arbiter given the standard
   policies' proposals but evidence from the standard or the adaptive table.
2. What does anticipating cost when the attacker does NOT react? Each arm's action is also scored on the
   standard (non-adaptive) table.
3. Is the model's mechanism claim right? Stackelberg-with-rotation predicts which responses a rational
   attacker would dodge by switching address. The measurement shows which responses actually lost
   containment after the switch. That comparison is independent of the scripted attacker's rule.

Honest limits: the attacker is scripted (a threat model, not an observation of real attackers); only four
spoofable attacks are covered; utilities are the table means over a few repetitions; the adaptive PPO is
in-sample.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import fmean
from typing import Any, Callable

import numpy as np

from iot_defense.defense.arbiter import ArbiterPolicy
from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.game_model import build_game_payoffs, with_rotation
from iot_defense.defense.objective import Objective, load_policy_section
from iot_defense.defense.policy import RuleBasedDefensePolicy, StackelbergDefensePolicy
from iot_defense.defense.ppo_env import TRAINING_SCENARIOS, context_for_scenario, load_ppo_training_config
from iot_defense.defense.ppo_policy import PPODefensePolicy
from iot_defense.defense.stackelberg import StackelbergGame
from iot_defense.evaluation.adaptive_outcome import ADAPTIVE_CONDITIONS, AdaptiveOutcomeTable
from iot_defense.evaluation.outcome import OutcomeTable
from iot_defense.evaluation.outcome_report import bootstrap_mean_ci

DEFAULT_STANDARD = "data/outcomes/outcome_table.jsonl"
DEFAULT_ADAPTIVE = "data/outcomes/adaptive_table.jsonl"
DEFAULT_MODELS_DIR = "data/evaluation/adaptive_models"
DEFAULT_OUTPUT = "data/evaluation/adaptive_eval.json"
STANDARD_PPO = ("models/ppo_defense", "data/evaluation/uncertainty_models/deployed_s1", "data/evaluation/uncertainty_models/deployed_s2")
ADAPTIVE_PPO_SEEDS = (1, 2, 3)
# A response "was dodged" when the attacker's switch cost it at least this much containment.
DODGED = 0.3

Chooser = Callable[[str], str]  # condition -> action value


def choices_of(policy: Any) -> Chooser:
    return lambda condition: policy.decide(context_for_scenario(condition)).action.value


def rule_chooser() -> Chooser:
    return choices_of(RuleBasedDefensePolicy())


def stackelberg_chooser(anticipate_rotation: bool) -> Chooser:
    model = load_policy_section("game_model")
    if anticipate_rotation:
        model = with_rotation(model)
    return choices_of(StackelbergDefensePolicy(StackelbergGame(build_game_payoffs(model=model))))


def ppo_chooser(model_path: str) -> Chooser:
    return choices_of(PPODefensePolicy(model_path=model_path))


def _proposal(action: str) -> DefenseDecision:
    return DefenseDecision.create(
        action=DefenseAction(action), target_ip="10.0.0.10", source_ip="10.0.0.100", reason="proposal",
        confidence=0.0, threat_score=0.0, policy_name="proposal", context={},
    )


def arbiter_chooser(table: OutcomeTable, rule: Chooser, stack: Chooser, ppo: Chooser) -> Chooser:
    arbiter = ArbiterPolicy(table)
    return lambda condition: arbiter.arbitrate(
        condition, {"rule_based": _proposal(rule(condition)), "stackelberg": _proposal(stack(condition)), "ppo": _proposal(ppo(condition))}
    ).action.value


def regret(table: OutcomeTable, condition: str, action: str) -> float:
    return table.mean(condition, table.best_action(condition)) - table.mean(condition, DefenseAction(action))


def score_arms(
    arms: dict[str, list[Chooser]], adaptive: OutcomeTable, standard: OutcomeTable, conditions: tuple[str, ...]
) -> dict[str, Any]:
    """Per arm (averaged over its models, if several): regret on the adaptive table, regret on the standard
    table, and what it chose."""
    report: dict[str, Any] = {}
    for name, choosers in arms.items():
        per_condition = {}
        for condition in conditions:
            actions = [chooser(condition) for chooser in choosers]
            per_condition[condition] = {
                "actions": actions,
                "adaptive_regret": fmean(regret(adaptive, condition, a) for a in actions),
                "standard_regret": fmean(regret(standard, condition, a) for a in actions),
            }
        adaptive_regrets = np.array([c["adaptive_regret"] for c in per_condition.values()])
        standard_regrets = np.array([c["standard_regret"] for c in per_condition.values()])
        report[name] = {
            "models": len(choosers),
            "per_condition": per_condition,
            "mean_adaptive_regret": float(adaptive_regrets.mean()),
            "mean_adaptive_regret_ci95": list(bootstrap_mean_ci(adaptive_regrets)) if len(adaptive_regrets) > 1 else [float(adaptive_regrets.mean())] * 2,
            "mean_standard_regret": float(standard_regrets.mean()),
        }
    return report


def mechanism_check(adaptive: AdaptiveOutcomeTable, rows: list[dict[str, Any]], conditions: tuple[str, ...]) -> dict[str, Any]:
    """Does the model's claim 'this response is dodged by switching address' match what was measured?

    Measured: over the rows where the attacker switched, how much containment the response lost between
    round 1 and round 2. Predicted: whether a rational attacker would switch against that response in the
    rotation-enabled game (i.e. ROTATE_SOURCE is its best reply)."""
    from iot_defense.evaluation.adaptive_outcome import AdaptiveMeasurement

    game = StackelbergGame(build_game_payoffs(model=with_rotation(load_policy_section("game_model"))))
    from iot_defense.attacks.registry import ATTACK_SCENARIOS

    keys = {s.attack_type: s.observed_threat_key for s in ATTACK_SCENARIOS.values()}
    measured: dict[tuple[str, str], list[float]] = {}
    for row in rows:
        m = AdaptiveMeasurement.from_row(row)
        if m.valid and m.rotated and m.condition in conditions:
            c1, c2 = m.containments
            measured.setdefault((m.condition, m.action.value), []).append(c1 - c2)
    cells = []
    for (condition, action), losses in sorted(measured.items()):
        predicted = game.attacker_best_response(keys[condition], DefenseAction(action))[0] == "ROTATE_SOURCE"
        lost = fmean(losses)
        cells.append({"condition": condition, "action": action, "predicted_dodged": predicted,
                      "containment_lost_after_switch": lost, "measured_dodged": lost >= DODGED, "n": len(losses)})
    agree = sum(c["predicted_dodged"] == c["measured_dodged"] for c in cells)
    return {"cells": cells, "agree": agree, "of": len(cells),
            "false_alarms": [(c["condition"], c["action"]) for c in cells if c["predicted_dodged"] and not c["measured_dodged"]],
            "misses": [(c["condition"], c["action"]) for c in cells if c["measured_dodged"] and not c["predicted_dodged"]]}


def build_report(standard_path: str, adaptive_path: str, models_dir: str) -> dict[str, Any]:
    objective = Objective.load()
    standard = OutcomeTable.from_jsonl(standard_path, objective)
    adaptive_only = AdaptiveOutcomeTable.from_jsonl(adaptive_path, objective)
    overlay = standard.with_cells_from(adaptive_only)
    rows = [json.loads(line) for line in Path(adaptive_path).read_text(encoding="utf-8").splitlines() if line.strip()]
    conditions = tuple(c for c in ADAPTIVE_CONDITIONS if adaptive_only.samples(c, DefenseAction.ALLOW))

    rule, stack, stack_rot = rule_chooser(), stackelberg_chooser(False), stackelberg_chooser(True)
    ppo_standard = [ppo_chooser(p) for p in STANDARD_PPO if Path(p + ".zip").exists()]
    adaptive_models = [f"{models_dir}/adaptive_s{s}" for s in ADAPTIVE_PPO_SEEDS]
    ppo_adaptive = [ppo_chooser(p) for p in adaptive_models if Path(p + ".zip").exists()]
    arms: dict[str, list[Chooser]] = {
        "rule_based": [rule], "stackelberg": [stack], "stackelberg_anticipating": [stack_rot], "ppo_standard": ppo_standard,
        "arbiter_standard_evidence": [arbiter_chooser(standard, rule, stack, ppo_standard[0])],
        "arbiter_adaptive_evidence": [arbiter_chooser(overlay, rule, stack, ppo_standard[0])],
        # the arbiter can only choose among what the strategies propose: give it a strategy that anticipates
        "arbiter_standard_evidence_anticipating": [arbiter_chooser(standard, rule, stack_rot, ppo_standard[0])],
        "arbiter_adaptive_evidence_anticipating": [arbiter_chooser(overlay, rule, stack_rot, ppo_standard[0])],
    }
    if ppo_adaptive:
        arms["ppo_adaptive_in_sample"] = ppo_adaptive
    scored = score_arms(arms, overlay, standard, conditions)
    best = {c: overlay.best_action(c).value for c in conditions}
    rotation = {c: {a.value: adaptive_only.rotation_rate(c, a) for a in DefenseAction if adaptive_only.samples(c, a)} for c in conditions}
    return {"conditions": list(conditions), "best_action_adaptive": best,
            "best_action_standard": {c: standard.best_action(c).value for c in conditions},
            "arms": scored, "mechanism_check": mechanism_check(adaptive_only, rows, conditions), "rotation_rate": rotation,
            "invalid_rows": adaptive_only.invalid_rows}


def render_markdown(report: dict[str, Any]) -> str:
    lines = ["# Strategies against a reactive attacker", "",
             f"Conditions: {', '.join(report['conditions'])}. Regret is measured against the best response for that table "
             "(0 = best). 'adaptive' = scored over both rounds against the switching attacker; 'standard' = scored on the ordinary "
             "one-round table, i.e. what the same choice costs when the attacker does NOT react.", "",
             "| Arm | models | adaptive regret [95% CI] | standard regret |", "|---|---|---|---|"]
    for name, arm in report["arms"].items():
        lo, hi = arm["mean_adaptive_regret_ci95"]
        lines.append(f"| {name} | {arm['models']} | {arm['mean_adaptive_regret']:.2f} [{lo:.2f}, {hi:.2f}] | {arm['mean_standard_regret']:.2f} |")
    lines += ["", "Best response per condition: " + "; ".join(
        f"{c}: {report['best_action_standard'][c]} -> {report['best_action_adaptive'][c]}" for c in report["conditions"]) + " (standard -> adaptive).", ""]
    check = report["mechanism_check"]
    lines += ["## Does the model's mechanism claim match the measurement?", "",
              f"Stackelberg-with-rotation predicts which responses a rational attacker dodges by switching address; the table shows which "
              f"actually lost containment after the switch. Agreement: {check['agree']}/{check['of']} (response, attack) pairs.",
              f"Predicted dodged but held up: {check['false_alarms'] or 'none'}. Dodged but not predicted: {check['misses'] or 'none'}.", ""]
    return "\n".join(lines)


# ── training the adaptive PPO ─────────────────────────────────────────────────
def run_training(standard_path: str, adaptive_path: str, models_dir: str, timesteps: int, worker: int = 0, workers: int = 1,
                 train_fn: Callable[..., dict[str, Any]] | None = None) -> list[str]:
    from iot_defense.simulation.train_ppo import train_on_table

    train_fn = train_fn or train_on_table
    objective = Objective.load()
    overlay = OutcomeTable.from_jsonl(standard_path, objective).with_cells_from(AdaptiveOutcomeTable.from_jsonl(adaptive_path, objective))
    Path(models_dir).mkdir(parents=True, exist_ok=True)
    trained = []
    for index, seed in enumerate(ADAPTIVE_PPO_SEEDS):
        path = f"{models_dir}/adaptive_s{seed}"
        if index % workers != worker or Path(path + ".zip").exists():
            continue
        info = train_fn(overlay, total_timesteps=timesteps, output_path=path, seed=seed)
        print(f"[adaptive_eval] trained adaptive PPO seed {seed} ({info['training_seconds']}s)", flush=True)
        trained.append(path)
    return trained


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("train", "analyze"):
        p = sub.add_parser(name)
        p.add_argument("--standard", default=DEFAULT_STANDARD)
        p.add_argument("--adaptive", default=DEFAULT_ADAPTIVE)
        p.add_argument("--models-dir", default=DEFAULT_MODELS_DIR)
    sub.choices["train"].add_argument("--timesteps", type=int, default=None)
    sub.choices["train"].add_argument("--worker", type=int, default=0)
    sub.choices["train"].add_argument("--workers", type=int, default=1)
    sub.choices["analyze"].add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    if args.command == "train":
        run_training(args.standard, args.adaptive, args.models_dir, args.timesteps or int(load_ppo_training_config()["training_timesteps"]),
                     args.worker, args.workers)
        return
    report = build_report(args.standard, args.adaptive, args.models_dir)
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    markdown = render_markdown(report)
    Path(args.output).with_suffix(".md").write_text(markdown + "\n", encoding="utf-8")
    print(markdown)


if __name__ == "__main__":
    main()
