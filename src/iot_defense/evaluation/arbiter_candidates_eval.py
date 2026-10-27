"""Does letting the arbiter score every response the device can apply (not only the policies' proposals) help?

The arbiter reads the measured outcome table, so grading it on the rows it read is circular, and with more
candidates there is a second, subtler bias: the best of more noisy means looks better than it is. This evaluation
therefore holds blocks out. The table was measured in three repetitions ("blocks"); for each block b the arbiter is
built from the other two and its choice is graded on block b's own measurements. A trial's held-out utility is the
mean over the three folds.

Each harness trial supplies what the three policies proposed and the label the detector gave (so detector errors are
included). For each trial, in each setting, the arbiter is run with only the proposals ("before") and with the
proposals plus every supported action ("after"), through the same `arbitrate_for_device` the live pipeline uses:

  * live: the five responses the live defender can apply; proposals for anything else are set aside first.
  * lab:  every response (the Mininet executor can apply all ten).

What stays in-sample: the harness's proposals come from policies built or trained on the full table's situations,
and the "regret" column grades the choice against the full table, which includes the held-out block. The primary
number is the held-out utility. Intervals are bootstrap intervals over trials, which share one testbed, so they are
lower bounds on the real uncertainty.

    python -m iot_defense.evaluation.arbiter_candidates_eval
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np

from iot_defense.defense.arbiter import ArbiterPolicy
from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.objective import Objective
from iot_defense.defense.pipeline import arbitrate_for_device
from iot_defense.evaluation.outcome import OutcomeTable
from iot_defense.evaluation.outcome_report import POLICY_ARMS, bootstrap_mean_ci, load_jsonl, paired_comparison, paired_trials
from iot_defense.live.backend import SUPPORTED_ACTIONS

SETTINGS: dict[str, frozenset[DefenseAction] | None] = {"live": SUPPORTED_ACTIONS, "lab": None}
MODES = {"before": False, "after": True}
SAFE_FALLBACK = DefenseAction.ALERT  # what the live pipeline does when the arbiter has nothing to choose among
FOCUS = ("data_exfiltration", "c2_beaconing", "dns_tunneling_exfiltration", "firmware_tampering")


def _proposal(action: str) -> DefenseDecision:
    return DefenseDecision.create(
        action=DefenseAction(action), target_ip="10.0.0.10", source_ip="10.0.0.100", reason="harness proposal",
        confidence=0.0, threat_score=0.0, policy_name="harness", context={},
    )


def choose(arbiter: ArbiterPolicy, label: str, proposed: dict[str, str], available: frozenset[DefenseAction] | None) -> tuple[DefenseAction, str]:
    """The action the pipeline would execute: (action, who it came from)."""
    decision, _kept, _excluded = arbitrate_for_device(arbiter, label, {arm: _proposal(a) for arm, a in proposed.items()}, available)
    if decision is None:
        return SAFE_FALLBACK, "safe_fallback"
    return decision.action, decision.context["arbiter_reasoning"]["chosen_from"]


def _modal(counter: Counter) -> str:
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


def evaluate(table_path: str | Path, results_path: str | Path, *, risk_aversion: float = 1.0, min_samples: int = 2) -> dict[str, Any]:
    objective = Objective.load()
    rows = load_jsonl(table_path)
    blocks = sorted({r["rep"] for r in rows})
    if len(blocks) < 2:
        raise ValueError("held-out evaluation needs at least two measurement blocks")
    train = {b: OutcomeTable([r for r in rows if r["rep"] != b], objective) for b in blocks}
    held = {b: OutcomeTable([r for r in rows if r["rep"] == b], objective) for b in blocks}
    full = OutcomeTable(rows, objective)
    trials, excluded_trials = paired_trials(load_jsonl(results_path))
    if not trials:
        raise ValueError("no trial has a valid measurement for every arm")
    arbiters = {
        (mode, b): ArbiterPolicy(train[b], risk_aversion=risk_aversion, min_samples=min_samples, consider_all_supported=flag)
        for mode, flag in MODES.items()
        for b in blocks
    }

    report: dict[str, Any] = {
        "blocks": blocks, "paired_trials": len(trials), "excluded_trials": excluded_trials, "risk_aversion": risk_aversion,
        "min_samples": min_samples, "settings": {},
    }
    for setting, available in SETTINGS.items():
        pool = tuple(available) if available is not None else tuple(DefenseAction)
        per_trial = []
        for (condition, trial), arms in sorted(trials.items()):
            label = arms["rule_based"]["detected_attack_type"]
            proposed = {arm: arms[arm]["action"] for arm in POLICY_ARMS}
            usable = [a for a in pool if full.samples(condition, a)]
            best_mean = max(full.mean(condition, a) for a in usable)
            record: dict[str, Any] = {"condition": condition, "trial": trial, "label": label, "proposed": proposed,
                                      "all_proposals_unsupported": available is not None and all(DefenseAction(a) not in available for a in proposed.values())}
            for mode in MODES:
                utilities, regrets, actions, origins = [], [], [], []
                for b in blocks:
                    action, origin = choose(arbiters[(mode, b)], label, proposed, available)
                    actions.append(action.value)
                    origins.append(origin)
                    got = held[b].samples(condition, action)
                    if got:
                        utilities.append(statistics.fmean(got))
                    if full.samples(condition, action):
                        regrets.append(best_mean - full.mean(condition, action))
                record[mode] = {"actions": actions, "origins": origins, "heldout_utility": statistics.fmean(utilities) if utilities else None,
                                "in_sample_regret": statistics.fmean(regrets) if regrets else None, "folds_without_heldout_rows": len(blocks) - len(utilities)}
            per_trial.append(record)

        situations: dict[str, Any] = {}
        for condition in sorted({r["condition"] for r in per_trial}):
            group = [r for r in per_trial if r["condition"] == condition]
            entry: dict[str, Any] = {
                "trials": len(group),
                "detector_label_correct": sum(r["label"] == condition for r in group),
                "all_proposals_unsupported_trials": sum(r["all_proposals_unsupported"] for r in group),
                "modal_proposals": {arm: _modal(Counter(r["proposed"][arm] for r in group)) for arm in POLICY_ARMS},
                "trials_with_a_different_choice": sum(r["before"]["actions"] != r["after"]["actions"] for r in group),
            }
            for mode in MODES:
                counts = Counter(a for r in group for a in r[mode]["actions"])
                u = [r[mode]["heldout_utility"] for r in group if r[mode]["heldout_utility"] is not None]
                g = [r[mode]["in_sample_regret"] for r in group if r[mode]["in_sample_regret"] is not None]
                entry[mode] = {"modal_action": _modal(counts), "actions": dict(sorted(counts.items())),
                               "heldout_utility": statistics.fmean(u) if u else None, "in_sample_regret": statistics.fmean(g) if g else None}
            entry["modal_action_changed"] = entry["before"]["modal_action"] != entry["after"]["modal_action"]
            situations[condition] = entry

        def overall(mode: str, key: str) -> float:
            return statistics.fmean(s[mode][key] for s in situations.values() if s[mode][key] is not None)

        diffs = np.array([r["after"]["heldout_utility"] - r["before"]["heldout_utility"] for r in per_trial
                          if r["after"]["heldout_utility"] is not None and r["before"]["heldout_utility"] is not None])
        trial_means = {mode: float(np.mean([r[mode]["heldout_utility"] for r in per_trial if r[mode]["heldout_utility"] is not None])) for mode in MODES}
        report["settings"][setting] = {
            "available": sorted(a.value for a in pool),
            "trials": len(per_trial),
            "situations": situations,
            "mean_over_situations": {mode: {"heldout_utility": overall(mode, "heldout_utility"), "in_sample_regret": overall(mode, "in_sample_regret")} for mode in MODES},
            "mean_over_trials_heldout_utility": trial_means,
            "heldout_utility_after_minus_before": paired_comparison(diffs) if len(diffs) else None,
            "heldout_utility_ci95": {mode: list(bootstrap_mean_ci(np.array([r[mode]["heldout_utility"] for r in per_trial if r[mode]["heldout_utility"] is not None]))) for mode in MODES},
            "situations_with_a_changed_modal_action": sorted(c for c, s in situations.items() if s["modal_action_changed"]),
            "trials_with_a_different_choice": sum(s["trials_with_a_different_choice"] for s in situations.values()),
            "trials_where_every_proposal_was_unsupported": sum(r["all_proposals_unsupported"] for r in per_trial),
            "chosen_from_after": dict(Counter(o for r in per_trial for o in r["after"]["origins"])),
        }
    return report


def fresh_live_comparison(results_path: str | Path) -> dict[str, Any]:
    """Analyse a harness run made with --live-arbiter-arms: fresh live trials in which the actions the arbiter would
    execute on the live defender (proposals only vs every supported action) were applied and measured. The arbiter's
    evidence (the outcome table) does not contain these trials, so this is a held-out comparison on new measurements."""
    from collections import defaultdict

    from iot_defense.evaluation.harness import LIVE_ARBITER_ARMS
    from iot_defense.evaluation.outcome_report import rescored

    objective = Objective.load()
    before_arm, after_arm = LIVE_ARBITER_ARMS
    by_trial: dict[tuple[str, int], dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in load_jsonl(results_path):
        by_trial[(row["condition"], row["trial"])][row["arm"]] = row
    paired = {k: arms for k, arms in sorted(by_trial.items()) if all(a in arms and arms[a]["valid_measurement"] for a in LIVE_ARBITER_ARMS)}
    if not paired:
        raise ValueError(f"no trial in {results_path} has a valid measurement for both {before_arm} and {after_arm}")
    utilities = {arm: np.array([rescored(arms[arm], objective) for arms in paired.values()]) for arm in LIVE_ARBITER_ARMS}
    conditions: dict[str, Any] = {}
    for condition in sorted({c for c, _ in paired}):
        group = [arms for (c, _), arms in paired.items() if c == condition]
        entry: dict[str, Any] = {"trials": len(group), "detector_label_correct": sum(arms[before_arm]["detection_correct"] for arms in group)}
        for arm in LIVE_ARBITER_ARMS:
            entry[arm] = {"mean_utility": float(np.mean([rescored(arms[arm], objective) for arms in group])), "actions": dict(sorted(Counter(arms[arm]["action"] for arms in group).items()))}
        entry["changed_trials"] = sum(arms[before_arm]["action"] != arms[after_arm]["action"] for arms in group)
        conditions[condition] = entry
    return {
        "paired_trials": len(paired),
        "mean_utility": {arm: {"mean": float(u.mean()), "ci95": list(bootstrap_mean_ci(u))} for arm, u in utilities.items()},
        "after_minus_before": paired_comparison(utilities[after_arm] - utilities[before_arm]),
        "trials_with_a_different_action": sum(e["changed_trials"] for e in conditions.values()),
        "conditions": conditions,
    }


def render_fresh_markdown(report: dict[str, Any]) -> str:
    d = report["after_minus_before"]
    lines = [
        "# Fresh live trials: the arbiter on the live defender, proposals only vs every supported action", "",
        f"{report['paired_trials']} paired trials. Each arm's action was applied and measured live; the arbiter's evidence (the outcome table) does not contain these trials.", "",
    ]
    for arm, m in report["mean_utility"].items():
        lines.append(f"- **{arm}**: mean utility {m['mean']:.3f}, 95% CI [{m['ci95'][0]:.3f}, {m['ci95'][1]:.3f}]")
    lines.append(f"- **after minus before**: {d['mean_diff']:+.3f}, 95% CI [{d['mean_diff_ci95'][0]:+.3f}, {d['mean_diff_ci95'][1]:+.3f}]; {d['n_nonzero']} of {d['n_trials']} trials differ (Wilcoxon p = {d['wilcoxon_p']:.2g}).")
    lines += ["", "| Situation | Trials | Before: actions (mean utility) | After: actions (mean utility) | Trials that changed |", "|---|---|---|---|---|"]
    for condition, e in report["conditions"].items():
        fmt = lambda arm: ", ".join(f"{a} x{n}" for a, n in e[arm]["actions"].items()) + f" ({e[arm]['mean_utility']:.2f})"
        mark = " **(focus)**" if condition in FOCUS else ""
        lines.append(f"| {condition}{mark} | {e['trials']} | {fmt('arbiter_live_before')} | {fmt('arbiter_live_after')} | {e['changed_trials']} |")
    return "\n".join(lines) + "\n"


def _fmt(v: float | None, spec: str = ".2f") -> str:
    return "-" if v is None else format(v, spec)


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# The arbiter with and without the supported actions as candidates", "",
        "Held-out grading: for each of the measurement blocks the arbiter is built from the other blocks and graded on the held-out one "
        f"(blocks {report['blocks']}, {report['paired_trials']} harness trials, risk aversion {report['risk_aversion']}). "
        "*Held-out utility* is the primary number. *Regret* grades the choice against the best action in the full table, which includes the held-out block, "
        "so it is an in-sample reference. Intervals are bootstrap intervals over trials that share one testbed: lower bounds on the real uncertainty.", "",
    ]
    for setting, s in report["settings"].items():
        d = s["heldout_utility_after_minus_before"]
        lines += [f"## {setting}: candidates are {', '.join(s['available'])}", ""]
        for mode in MODES:
            m = s["mean_over_situations"][mode]
            ci = s["heldout_utility_ci95"][mode]
            lines.append(f"- **{mode}**: held-out utility {_fmt(m['heldout_utility'], '.3f')} per situation (trial mean {_fmt(s['mean_over_trials_heldout_utility'][mode], '.3f')}, 95% CI [{ci[0]:.3f}, {ci[1]:.3f}]); mean in-sample regret {_fmt(m['in_sample_regret'], '.3f')}.")
        if d:
            lines.append(f"- **after minus before**: {d['mean_diff']:+.3f} per trial, 95% CI [{d['mean_diff_ci95'][0]:+.3f}, {d['mean_diff_ci95'][1]:+.3f}]; {d['n_nonzero']} of {d['n_trials']} trials differ (Wilcoxon p = {d['wilcoxon_p']:.2g}).")
        lines.append(f"- Situations whose most frequent choice changed: {len(s['situations_with_a_changed_modal_action'])} of {len(s['situations'])} ({', '.join(s['situations_with_a_changed_modal_action']) or 'none'}); trials where any fold chose differently: {s['trials_with_a_different_choice']} of {s['trials']}; trials where every proposal was unsupported: {s['trials_where_every_proposal_was_unsupported']}.")
        lines += ["", "| Situation | Trials | Proposals (rule / Stackelberg / PPO) | Before | After | Held-out utility before -> after | Regret before -> after |", "|---|---|---|---|---|---|---|"]
        for c, e in s["situations"].items():
            mark = " **(focus)**" if c in FOCUS else ""
            p = e["modal_proposals"]
            lines.append(f"| {c}{mark} | {e['trials']} | {p['rule_based']} / {p['stackelberg']} / {p['ppo']} | {e['before']['modal_action']} | {e['after']['modal_action']}{' *' if e['modal_action_changed'] else ''} | "
                         f"{_fmt(e['before']['heldout_utility'])} -> {_fmt(e['after']['heldout_utility'])} | {_fmt(e['before']['in_sample_regret'])} -> {_fmt(e['after']['in_sample_regret'])} |")
        lines += ["", "\\* the most frequent choice changed.", ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--table", default="data/outcomes/outcome_table.jsonl")
    parser.add_argument("--results", default="data/evaluation/results_measured.jsonl")
    parser.add_argument("--risk-aversion", type=float, default=1.0)
    parser.add_argument("--output-dir", default="data/evaluation")
    parser.add_argument("--fresh-results", default=None,
                        help="analyse a harness run made with --live-arbiter-arms instead of the held-out-block comparison")
    args = parser.parse_args()
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    if args.fresh_results:
        fresh = fresh_live_comparison(args.fresh_results)
        (out / "arbiter_live_fresh.json").write_text(json.dumps(fresh, indent=2) + "\n", encoding="utf-8")
        (out / "arbiter_live_fresh.md").write_text(render_fresh_markdown(fresh), encoding="utf-8")
        print(render_fresh_markdown(fresh))
        return
    report = evaluate(args.table, args.results, risk_aversion=args.risk_aversion)
    (out / "arbiter_candidates_eval.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (out / "arbiter_candidates_eval.md").write_text(render_markdown(report), encoding="utf-8")
    print(render_markdown(report))


if __name__ == "__main__":
    main()
