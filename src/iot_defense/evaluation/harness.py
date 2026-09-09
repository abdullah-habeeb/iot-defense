"""Repeatable benchmark harness for the research-evaluation comparison.

Runs `trials_per_condition` real Mininet trials for every registered
condition (`normal` plus every `ATTACK_SCENARIOS` entry -- generic, no
hardcoded attack count) and evaluates five arms against the *identical*
real captured traffic per trial: our three policies (rule-based,
Stackelberg, PPO) plus two internal baselines (AlwaysAllowBaseline,
NaiveBlockAllBaseline). One real trial produces everything every arm
needs -- no separate live run per arm.

Reuses RealMininetDefenseEnv's own real-traffic-observation and real-
execute-and-verify machinery (`_observe_scenario`, `_execute_and_verify`,
`_preferred_action_verified`) rather than re-implementing it here: that
logic is already registry-driven, already live-verified across every
registered attack, and duplicating it would risk exactly the kind of
un-synced-copy bug this project has hit before (see generate_dataset.py's
own history). Each *distinct* action chosen across arms in a trial is
executed and verified for real exactly once (ALLOW is a real no-op and
never needs execution) -- so containment-effectiveness numbers are real
for every arm, not just the ones this project already exercises live.

Requires root (creates and drives a real Mininet network, same as every
other real-Mininet entry point in this project).
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from iot_defense.defense.context import build_security_context
from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.policy import RuleBasedDefensePolicy, StackelbergDefensePolicy
from iot_defense.defense.ppo_env import TRAINING_SCENARIOS, _scenario_by_attack_type
from iot_defense.defense.ppo_policy import PPODefensePolicy
from iot_defense.defense.ppo_real_env import RealMininetDefenseEnv
from iot_defense.evaluation.baselines import AlwaysAllowBaseline, NaiveBlockAllBaseline

# Conditions are attack_type strings ("normal", "reconnaissance_port_scan",
# ...), not registry keys ("reconnaissance") -- reusing TRAINING_SCENARIOS()
# directly (rather than re-deriving "normal" + ATTACK_SCENARIOS keys) keeps
# this in lockstep with what RealMininetDefenseEnv._observe_scenario()
# actually expects, since that's the exact tuple it and PPO training both
# already use.
CONDITIONS: tuple[str, ...] = TRAINING_SCENARIOS()


def _preferred_action_for(ground_truth: str) -> DefenseAction:
    if ground_truth == "normal":
        return DefenseAction.ALLOW
    return _scenario_by_attack_type()[ground_truth].preferred_action


def run_trial(env: RealMininetDefenseEnv, condition: str) -> list[dict[str, Any]]:
    """One real trial: observe real traffic for `condition` (an attack_type
    string), evaluate every arm against the identical context, execute-and-
    verify each distinct chosen action once, and return one result row per
    arm."""
    ground_truth = condition
    preferred_action = _preferred_action_for(ground_truth)

    detect_start = time.perf_counter()
    threat_event = env._observe_scenario(condition)
    detection_latency_ms = (time.perf_counter() - detect_start) * 1000
    context = build_security_context(threat_event, device_criticality="high")

    rule_decision = RuleBasedDefensePolicy().decide(context)
    stack_decision = StackelbergDefensePolicy().decide(context)
    stackelberg_info = stack_decision.context.get("stackelberg_reasoning")

    decisions: dict[str, Any] = {"rule_based": rule_decision, "stackelberg": stack_decision}
    try:
        decisions["ppo"] = PPODefensePolicy(
            model_path="models/ppo_defense", fallback=RuleBasedDefensePolicy()
        ).decide(context, stackelberg_info=stackelberg_info)
    except Exception as exc:  # noqa: BLE001 -- a policy failing to decide is a real result to record, not a crash
        print(f"[harness] ppo policy failed to decide: {exc}")
        decisions["ppo"] = None
    decisions["always_allow"] = AlwaysAllowBaseline().decide(context)
    decisions["naive_block_all"] = NaiveBlockAllBaseline().decide(context)

    # Execute-and-verify each *distinct* action chosen across arms exactly
    # once -- real time cost paid only for genuinely different responses,
    # not once per arm.
    outcomes_by_action: dict[DefenseAction, dict[str, Any]] = {}
    for decision in decisions.values():
        if decision is None or decision.action in outcomes_by_action:
            continue
        if decision.action == DefenseAction.ALLOW:
            outcomes_by_action[decision.action] = {"status": "success"}  # real no-op, nothing to verify
            continue
        outcomes_by_action[decision.action] = env._execute_and_verify(decision.action, threat_event)

    rows: list[dict[str, Any]] = []
    for arm, decision in decisions.items():
        row: dict[str, Any] = {
            "condition": condition,
            "arm": arm,
            "ground_truth_attack_type": ground_truth,
            "detected_attack_type": threat_event.attack_type,
            "detection_correct": threat_event.attack_type == ground_truth,
            "detector_name": threat_event.detector_name,
            "detection_latency_ms": round(detection_latency_ms, 2),
        }
        if decision is None:
            row.update({"action": None, "execution_ok": False, "matches_preferred_action": False, "response_verified": False})
        else:
            outcome = outcomes_by_action.get(decision.action, {})
            execution_ok = outcome.get("status") == "success"
            matches_preferred = decision.action == preferred_action
            row.update(
                {
                    "action": decision.action.value,
                    "matches_preferred_action": matches_preferred,
                    "execution_ok": execution_ok,
                    "response_verified": (
                        RealMininetDefenseEnv._preferred_action_verified(preferred_action, outcome, execution_ok)
                        if matches_preferred
                        else None
                    ),
                    "outcome": outcome,
                }
            )
        rows.append(row)
    return rows


def run_harness(
    *,
    trials_per_condition: int = 8,
    output_path: str | Path = "data/evaluation/results.jsonl",
) -> dict[str, Any]:
    """Run the full trial matrix, appending one JSON line per (trial, condition, arm)
    result to `output_path` as it goes -- so a mid-run failure still leaves every
    completed trial's real data on disk, not lost."""
    env = RealMininetDefenseEnv()
    env._ensure_network()
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    started = time.time()
    total_conditions_run = 0
    total_conditions = trials_per_condition * len(CONDITIONS)
    try:
        with output.open("w", encoding="utf-8") as fh:
            for trial in range(trials_per_condition):
                for condition in CONDITIONS:
                    rows = run_trial(env, condition)
                    for row in rows:
                        row["trial"] = trial
                        fh.write(json.dumps(row) + "\n")
                    fh.flush()
                    total_conditions_run += 1
                    print(
                        f"[harness] trial={trial} condition={condition!r} "
                        f"({total_conditions_run}/{total_conditions})",
                        flush=True,
                    )
    finally:
        env.close()

    elapsed = time.time() - started
    summary = {
        "trials_per_condition": trials_per_condition,
        "conditions": list(CONDITIONS),
        "total_condition_runs": total_conditions_run,
        "elapsed_seconds": round(elapsed, 1),
        "output_path": str(output),
    }
    output.with_suffix(".summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials-per-condition", type=int, default=8)
    parser.add_argument("--output", default="data/evaluation/results.jsonl")
    args = parser.parse_args()
    summary = run_harness(trials_per_condition=args.trials_per_condition, output_path=args.output)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
