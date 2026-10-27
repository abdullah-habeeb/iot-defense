"""Grade the frozen policies against what was measured for the two new attacks.

Nothing here learns or tunes. Stackelberg and the rule-based playbook decide from the frozen pre-registration alone (the same
policy classes the live system uses); the measured rows are only the answer key. For each new attack and each policy:

    regret = (mean utility of the best of the 10 responses) - (mean utility of the response the policy chose)

on the three primary blocks (reps 0 to 2), with the per-block spread and the rank of the choice. Baselines: priors without the
attacker's reaction, the best single fixed response on the 20 known attacks, the nearest known attack's measured best response
(what a measurement-driven defender could borrow), a fixed QUARANTINE, and ALLOW. PPO cannot take part: its observation encodes
the attack label as one of the 21 known conditions, so an unseen attack cannot even be presented to it.

The pre-registered success criteria are evaluated on the primary blocks. Confirmatory blocks (reps 3 to 5), if measured, are
reported separately and do not change the verdict.

    python -m iot_defense.experiments.new_attacks.analyze
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path
from typing import Any

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.game_model import build_game_payoffs
from iot_defense.defense.model_outcomes import ModelOutcomeTable
from iot_defense.defense.objective import Objective, load_policy_section
from iot_defense.defense.policy import RuleBasedDefensePolicy, StackelbergDefensePolicy
from iot_defense.defense.ppo_env import context_for_scenario
from iot_defense.defense.stackelberg import StackelbergGame
from iot_defense.evaluation.outcome import OutcomeTable
from iot_defense.experiments.new_attacks import common, prereg
from iot_defense.experiments.new_attacks.scenarios import NEW_ATTACK_KEYS, build_scenarios, registered

PRIMARY_REPS = (0, 1, 2)
BLOCK_ROWS = len(DefenseAction) + 1
TIE_BAND = 0.25  # actions within this many utility points of the best are listed as practically tied
PPO_NOTE = (
    "Not applicable. PPO's observation encodes the attack label as one of the 21 known conditions, so an unseen attack cannot be "
    "presented to a trained model; using it would mean rebuilding and retraining it on the very measurements being predicted."
)

POLICIES = ("stackelberg", "rule_based", "priors_without_attacker", "best_fixed_known", "nearest_known_attack", "fixed_quarantine", "allow")
POLICY_LABELS = {
    "stackelberg": "Stackelberg (frozen priors)",
    "rule_based": "Rule-based playbook (frozen entry)",
    "priors_without_attacker": "Same priors, attacker's reaction ignored",
    "best_fixed_known": "Best single response on the 20 known attacks",
    "nearest_known_attack": "Borrow the nearest known attack's measured best",
    "fixed_quarantine": "Always QUARANTINE",
    "allow": "Do nothing (ALLOW)",
}


def complete_blocks(rows: list[dict[str, Any]], condition: str) -> list[int]:
    counts: dict[int, int] = {}
    for row in rows:
        if row["condition"] == condition:
            counts[int(row["rep"])] = counts.get(int(row["rep"]), 0) + 1
    return sorted(rep for rep, n in counts.items() if n == BLOCK_ROWS)


def _means(table: OutcomeTable, condition: str) -> dict[str, float | None]:
    return {action.value: (table.mean(condition, action) if table.samples(condition, action) else None) for action in DefenseAction}


def _rank(means: dict[str, float], action: str) -> int:
    return 1 + sum(1 for value in means.values() if value > means[action] + 1e-9)


def frozen_decisions(spec: dict[str, Any], base_model: dict[str, Any], objective: Objective, main_table: OutcomeTable) -> dict[str, Any]:
    """What every policy chooses for each new attack, from the frozen pre-registration and the old benchmark only."""
    model = prereg.augmented_model(spec, base_model)
    best_fixed = max(DefenseAction, key=lambda a: statistics.fmean(
        main_table.mean(c, a) for c in _known_conditions(main_table)))
    decisions: dict[str, Any] = {}
    with registered(build_scenarios(prereg.playbook_actions(spec))):
        game = StackelbergGame(payoffs=build_game_payoffs(model=model, objective=objective))
        stackelberg, rule = StackelbergDefensePolicy(game=game), RuleBasedDefensePolicy()
        priors_only = ModelOutcomeTable(model=model, objective=objective)
        for key in NEW_ATTACK_KEYS:
            context = context_for_scenario(key)
            stack_decision = stackelberg.decide(context)
            analog = spec["attacks"][key]["nearest_known_attack"]
            analog_best = max(DefenseAction, key=lambda a: main_table.mean(analog, a))
            decisions[key] = {
                "stackelberg": stack_decision.action.value,
                "rule_based": rule.decide(context).action.value,
                "priors_without_attacker": priors_only.best_action(key).value,
                "best_fixed_known": best_fixed.value,
                "nearest_known_attack": analog_best.value,
                "fixed_quarantine": DefenseAction.QUARANTINE.value,
                "allow": DefenseAction.ALLOW.value,
                "class": prereg.class_of(spec, key),
                "nearest_known_attack_name": analog,
                "stackelberg_reasoning": stack_decision.context.get("stackelberg_reasoning", {}),
                "prior_utility": {a.value: priors_only.mean(key, a) for a in DefenseAction},
            }
    return decisions


def _known_conditions(table: OutcomeTable) -> list[str]:
    from iot_defense.attacks.registry import ATTACK_SCENARIOS

    return ["normal"] + [s.attack_type for s in ATTACK_SCENARIOS.values()]


def known_reference(base_model: dict[str, Any], objective: Objective, main_table: OutcomeTable) -> dict[str, Any]:
    """The same policies on the 21 known situations, graded on the benchmark: a check that this pipeline reproduces the headline
    numbers in EVALUATION.md before it is trusted on the new attacks."""
    from iot_defense.defense.ppo_env import TRAINING_SCENARIOS

    stackelberg = StackelbergDefensePolicy(game=StackelbergGame(payoffs=build_game_payoffs(model=base_model, objective=objective)))
    rule = RuleBasedDefensePolicy()
    regret = {"stackelberg": [], "rule_based": []}
    for condition in TRAINING_SCENARIOS():
        context = context_for_scenario(condition)
        best = max(main_table.mean(condition, a) for a in DefenseAction)
        for name, policy in (("stackelberg", stackelberg), ("rule_based", rule)):
            regret[name].append(best - main_table.mean(condition, policy.decide(context).action))
    return {"situations": len(regret["stackelberg"]),
            "mean_regret": {name: round(statistics.fmean(values), 4) for name, values in regret.items()}}


def grade(rows: list[dict[str, Any]], decisions: dict[str, Any], objective: Objective, reps: tuple[int, ...]) -> dict[str, Any]:
    graded: dict[str, Any] = {}
    for key in NEW_ATTACK_KEYS:
        have = [rep for rep in complete_blocks(rows, key) if rep in reps]
        usable = [r for r in rows if r["condition"] == key and int(r["rep"]) in have]
        table = OutcomeTable(usable, objective)
        entry: dict[str, Any] = {"complete_blocks": have, "valid_rows": len(usable) - table.invalid_rows, "invalid_rows": table.invalid_rows}
        if not have:
            graded[key] = {**entry, "status": "INCOMPLETE"}
            continue
        means = {a: m for a, m in _means(table, key).items() if m is not None}
        best_action = max(means, key=means.get)
        entry.update({
            "status": "OK", "mean_utility": means, "best_action": best_action, "best_mean": means[best_action],
            "tied_with_best": sorted(a for a, m in means.items() if means[best_action] - m <= TIE_BAND),
            "policies": {},
        })
        block_tables = {rep: OutcomeTable([r for r in usable if int(r["rep"]) == rep], objective) for rep in have}
        for name in POLICIES:
            chosen = decisions[key][name]
            if chosen not in means:
                entry["policies"][name] = {"action": chosen, "mean": None, "regret": None, "rank": None, "regret_by_block": []}
                continue
            by_block = []
            for rep, block in block_tables.items():
                block_means = {a: m for a, m in _means(block, key).items() if m is not None}
                by_block.append(round(max(block_means.values()) - block_means[chosen], 4))
            entry["policies"][name] = {"action": chosen, "mean": means[chosen], "regret": round(means[best_action] - means[chosen], 4),
                                       "rank": _rank(means, chosen), "regret_by_block": by_block}
        graded[key] = entry
    return graded


def evaluate_criteria(spec: dict[str, Any], graded: dict[str, Any]) -> dict[str, Any]:
    criteria = spec["success_criteria"]
    ceiling = float(criteria["stackelberg_max_regret"])
    per_attack: dict[str, Any] = {}
    for key, entry in graded.items():
        if entry["status"] != "OK" or len(entry["complete_blocks"]) < len(PRIMARY_REPS):
            per_attack[key] = {"verdict": "INCOMPLETE"}
            continue
        stack, rule = entry["policies"]["stackelberg"], entry["policies"]["rule_based"]
        under = stack["regret"] <= ceiling
        beats = (stack["regret"] <= rule["regret"] + 1e-9) if criteria["stackelberg_not_worse_than_playbook"] else None
        passed = under and (beats is not False)
        per_attack[key] = {"verdict": "PASS" if passed else "FAIL", "stackelberg_regret": stack["regret"], "regret_within_ceiling": under,
                           "not_worse_than_playbook": beats, "playbook_regret": rule["regret"]}
    verdicts = [v["verdict"] for v in per_attack.values()]
    overall = "INCOMPLETE" if "INCOMPLETE" in verdicts else ("PASS" if all(v == "PASS" for v in verdicts) else "FAIL")
    return {"stackelberg_max_regret": ceiling, "not_worse_than_playbook_required": criteria["stackelberg_not_worse_than_playbook"],
            "per_attack": per_attack, "overall": overall, "passed": verdicts.count("PASS"), "of": len(verdicts)}


def prior_accuracy(graded: dict[str, Any], decisions: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, entry in graded.items():
        if entry["status"] != "OK":
            continue
        prior = decisions[key]["prior_utility"]
        errors = {a: round(prior[a] - m, 4) for a, m in entry["mean_utility"].items()}
        out[key] = {"error_by_action": errors, "mean_absolute_error": round(statistics.fmean(abs(e) for e in errors.values()), 4),
                    "largest_error_action": max(errors, key=lambda a: abs(errors[a]))}
    return out


def analyze(rows_path: Path, prereg_path: Path | None = None, main_table_path: Path | None = None) -> dict[str, Any]:
    spec = prereg.load(prereg_path)
    base_model = load_policy_section("game_model")
    problems = prereg.validate(spec, base_model, require_ready=True)
    if problems:
        raise ValueError("the pre-registration is not valid: " + "; ".join(problems))
    objective = Objective.load()
    main_table = OutcomeTable.from_jsonl(main_table_path or common.MAIN_TABLE_PATH, objective)
    rows = common.read_jsonl(rows_path)
    decisions = frozen_decisions(spec, base_model, objective, main_table)
    primary = grade(rows, decisions, objective, PRIMARY_REPS)
    later = tuple(sorted({int(r["rep"]) for r in rows} - set(PRIMARY_REPS)))
    confirmatory = grade(rows, decisions, objective, later) if later else None
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "rows_sha256": common.sha256_file(rows_path) if rows_path.exists() else None,
        "rows": len(rows),
        "primary_reps": list(PRIMARY_REPS),
        "decisions": {k: {p: v for p, v in d.items() if p not in ("stackelberg_reasoning", "prior_utility")} for k, d in decisions.items()},
        "stackelberg_reasoning": {k: d["stackelberg_reasoning"] for k, d in decisions.items()},
        "primary": primary,
        "confirmatory": confirmatory,
        "criteria": evaluate_criteria(spec, primary),
        "prior_accuracy": prior_accuracy(primary, decisions),
        "known_reference": known_reference(base_model, objective, main_table),
        "ppo": PPO_NOTE,
        "tie_band": TIE_BAND,
    }


def render_markdown(result: dict[str, Any]) -> str:
    lines = ["# New-attack transfer experiment: results", "",
             f"Generated {result['generated_at']} from {result['rows']} measured rows (sha256 `{result['rows_sha256']}`). "
             "Regret = best measured response minus the chosen response, in utility points, on blocks 0 to 2.", ""]
    crit = result["criteria"]
    lines += [f"**Pre-registered verdict: {crit['overall']}** ({crit['passed']} of {crit['of']} attacks pass: Stackelberg regret <= "
              f"{crit['stackelberg_max_regret']}" + (" and not worse than the playbook" if crit["not_worse_than_playbook_required"] else "") + ").", ""]
    for key, entry in result["primary"].items():
        lines.append(f"## {key}")
        if entry["status"] != "OK":
            lines += ["Incomplete: no complete measured block.", ""]
            continue
        verdict = crit["per_attack"][key]["verdict"]
        lines.append(f"Class used by Stackelberg: `{result['decisions'][key]['class']}`. Blocks: {entry['complete_blocks']}. "
                     f"Best response: **{entry['best_action']}** ({entry['best_mean']:.2f}). Practically tied with it (within {result['tie_band']}): "
                     f"{', '.join(entry['tied_with_best'])}. Verdict: **{verdict}**.")
        lines += ["", "| Policy | Chose | Its utility | Regret | Rank of 10 | Regret per block |", "|---|---|---|---|---|---|"]
        for name in POLICIES:
            p = entry["policies"][name]
            lines.append(f"| {POLICY_LABELS[name]} | {p['action']} | {'-' if p['mean'] is None else format(p['mean'], '.2f')} | "
                         f"{'-' if p['regret'] is None else format(p['regret'], '.2f')} | {p['rank'] or '-'} | {p['regret_by_block']} |")
        lines += ["", "Measured mean utility per response: " + ", ".join(f"{a} {m:.2f}" for a, m in sorted(entry["mean_utility"].items(), key=lambda kv: -kv[1])), ""]
    lines += ["## Sanity check on the 21 known situations", "",
              f"The same code on the benchmark: mean regret Stackelberg {result['known_reference']['mean_regret']['stackelberg']}, "
              f"rule-based {result['known_reference']['mean_regret']['rule_based']} (EVALUATION.md reports 0.042 and 2.996).", "",
              f"PPO: {result['ppo']}", ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rows", default=str(common.ROWS_PATH))
    parser.add_argument("--no-freeze-check", action="store_true", help="analyse even if the tree differs from the freeze (marked in the output)")
    args = parser.parse_args()
    drift = [] if args.no_freeze_check else prereg.verify_freeze()
    if drift:
        raise SystemExit("The tree differs from the freeze, so the result would not be the pre-registered one:\n - " + "\n - ".join(drift))
    result = analyze(Path(args.rows))
    result["freeze_checked"] = not args.no_freeze_check
    common.RESULTS_JSON.parent.mkdir(parents=True, exist_ok=True)
    common.RESULTS_JSON.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    common.RESULTS_MD.write_text(render_markdown(result), encoding="utf-8")
    print(render_markdown(result))


if __name__ == "__main__":
    main()
