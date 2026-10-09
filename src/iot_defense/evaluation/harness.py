"""Repeatable benchmark harness: held-out, measured-outcome policy comparison.

Runs `trials_per_condition` real Mininet trials for every registered
condition (`normal` plus every `ATTACK_SCENARIOS` entry) and evaluates five
arms against the *identical* real captured traffic per trial: our three
policies (rule-based, Stackelberg, PPO) plus two internal baselines
(AlwaysAllowBaseline, NaiveBlockAllBaseline).

The metric is realized utility computed from MEASURED outcomes (see
evaluation/outcome.py): per trial, ALLOW is measured first as the
un-responded baseline, then each other distinct action chosen by any arm is
applied for real and measured once (ALLOW before and after, whose mean is the
trial's baseline) -- how much attack traffic survived to
the receiving host's firewall counter, how much legitimate service
survived, whether intelligence was verified. Whether an arm picked a registered preferred_action is recorded
only as the diagnostic `matches_preferred_action`; it is not a performance
metric anywhere in the evaluation.

These trials are fresh: they never read the outcome table PPO trained on.

Requires root (Mininet).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import time
from pathlib import Path
from typing import Any

from iot_defense.defense.context import build_security_context
from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.objective import Objective
from iot_defense.defense.policy import RuleBasedDefensePolicy, StackelbergDefensePolicy
from iot_defense.defense.ppo_env import TRAINING_SCENARIOS, _scenario_by_attack_type
from iot_defense.defense.ppo_policy import PPODefensePolicy
from iot_defense.defense.ppo_real_env import RealMininetDefenseEnv
from iot_defense.evaluation.baselines import AlwaysAllowBaseline, NaiveBlockAllBaseline
from iot_defense.evaluation.outcome import Measurement, consensus_baseline, realized_utility, with_baseline

CONDITIONS: tuple[str, ...] = TRAINING_SCENARIOS()
ARMS_PER_TRIAL = 5
SETTLE_SECONDS = 1.0


def _preferred_action_for(ground_truth: str) -> DefenseAction:
    """Diagnostic only: the registry's expert-declared action for a condition."""
    if ground_truth == "normal":
        return DefenseAction.ALLOW
    return _scenario_by_attack_type()[ground_truth].preferred_action


def _preserve_pcap(env: RealMininetDefenseEnv, pcap_dir: str | Path | None, trial: int, condition: str) -> str | None:
    """Copy this trial's detection capture to a unique per-(trial, condition)
    path before the next condition's capture overwrites the fixed one."""
    if pcap_dir is None:
        return None
    source = env.monitor.base_dir / "sensor_capture.pcap"
    if not source.exists():
        return None
    destination = Path(pcap_dir) / f"trial{trial:03d}_{condition}.pcap"
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return str(destination)


def run_trial(
    env: RealMininetDefenseEnv,
    trial: int,
    condition: str,
    ppo_policy: PPODefensePolicy,
    objective: Objective,
    pcap_dir: str | Path | None = None,
) -> list[dict[str, Any]]:
    """One real trial: observe real traffic for `condition`, collect every
    arm's decision on the identical context, measure ALLOW then each other
    distinct chosen action once, and return one result row per arm."""
    ground_truth = condition
    preferred_action = _preferred_action_for(ground_truth)

    detect_start = time.perf_counter()
    threat_event = env._observe_scenario(condition)
    detection_latency_ms = (time.perf_counter() - detect_start) * 1000
    pcap_path = _preserve_pcap(env, pcap_dir, trial, condition)
    context = build_security_context(threat_event, device_criticality="high")

    decisions = {
        "rule_based": RuleBasedDefensePolicy().decide(context),
        "stackelberg": StackelbergDefensePolicy().decide(context),
        "ppo": ppo_policy.decide(context),
        "always_allow": AlwaysAllowBaseline().decide(context),
        "naive_block_all": NaiveBlockAllBaseline().decide(context),
    }

    to_measure = [a for a in DefenseAction if a in {d.action for d in decisions.values()} - {DefenseAction.ALLOW}]
    random.Random(f"{trial}:{condition}").shuffle(to_measure)  # no fixed order across trials
    raw: dict[DefenseAction, Measurement] = {}
    outcomes: dict[DefenseAction, dict[str, Any]] = {}
    allow_probes: list[Measurement] = []
    for action in [DefenseAction.ALLOW, *to_measure, DefenseAction.ALLOW]:
        if allow_probes:
            time.sleep(SETTLE_SECONDS)
        measurement, outcome = env.measure_response(action, threat_event, condition)
        if action == DefenseAction.ALLOW:
            allow_probes.append(measurement)
            raw.setdefault(DefenseAction.ALLOW, measurement)  # the first ALLOW probe stands for the ALLOW arms
            outcomes.setdefault(DefenseAction.ALLOW, outcome)
        else:
            raw[action], outcomes[action] = measurement, outcome
    baseline_packets = consensus_baseline(allow_probes)
    measurements = {action: with_baseline(m, baseline_packets) for action, m in raw.items()}

    rows: list[dict[str, Any]] = []
    for arm, decision in decisions.items():
        measurement = measurements[decision.action]
        outcome = outcomes[decision.action]
        valid = measurement.valid
        rows.append(
            {
                "condition": condition,
                "arm": arm,
                "ground_truth_attack_type": ground_truth,
                "detected_attack_type": threat_event.attack_type,
                "detection_correct": threat_event.attack_type == ground_truth,
                "detector_name": threat_event.detector_name,
                "detection_latency_ms": round(detection_latency_ms, 2),
                "pcap_path": pcap_path,
                "action": decision.action.value,
                "execution_ok": measurement.status == "success",
                "matches_preferred_action": decision.action == preferred_action,
                "baseline_packets": measurement.baseline_packets,
                "residual_packets": measurement.residual_packets,
                "containment": measurement.containment,
                "service_loss": measurement.service_loss,
                "intel_verified": measurement.intel_verified,
                "valid_measurement": valid,
                "utility": realized_utility(measurement, objective) if valid else None,
                "probe_error": outcome.get("probe_error"),
            }
        )
    return rows


def run_fingerprint(model_path: str | Path) -> str:
    """Identifies the setup a results file was produced under: the PPO model
    and the full policy/objective config. Resuming under a different one
    would silently mix two experiments in one file."""
    digest = hashlib.sha256()
    for path in (Path(model_path).with_suffix(".zip"), Path(__file__).resolve().parents[3] / "config" / "policies.yaml"):
        digest.update(path.read_bytes())
    return digest.hexdigest()


def prepare_output(output: Path, fingerprint: str, resume: bool) -> set[tuple[int, str]]:
    """Open a results file for (re)starting a run; returns the (trial,
    condition) blocks already complete.

    With resume and an existing file: refuses if it was written under a
    different fingerprint, and rewrites it keeping only complete blocks (all
    arms present), so a trial interrupted mid-write is redone, never
    double-counted. Otherwise starts a fresh file."""
    fingerprint_path = output.with_suffix(".fingerprint")
    if resume and output.exists() and output.stat().st_size > 0:
        recorded = fingerprint_path.read_text(encoding="utf-8").strip() if fingerprint_path.exists() else None
        if recorded != fingerprint:
            raise RuntimeError(
                f"{output} was produced under a different model/config (recorded fingerprint "
                f"{recorded!r} != current {fingerprint!r}); resuming would mix two experiments. "
                "Re-run with --restart to start over."
            )
        blocks: dict[tuple[int, str], list[str]] = {}
        arms: dict[tuple[int, str], set[str]] = {}
        for line in output.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                key = (row["trial"], row["condition"])
                blocks.setdefault(key, []).append(line)
                arms.setdefault(key, set()).add(row["arm"])
        complete = {key for key, seen in arms.items() if len(seen) == ARMS_PER_TRIAL and len(blocks[key]) == ARMS_PER_TRIAL}
        output.write_text("".join(line + "\n" for key, lines in blocks.items() if key in complete for line in lines), encoding="utf-8")
        return complete
    output.write_text("", encoding="utf-8")
    fingerprint_path.write_text(fingerprint + "\n", encoding="utf-8")
    return set()


def run_harness(
    *,
    trials_per_condition: int = 8,
    output_path: str | Path = "data/evaluation/results.jsonl",
    pcap_dir: str | Path | None = "data/evaluation/pcaps",
    model_path: str = "models/ppo_defense",
    resume: bool = True,
) -> dict[str, Any]:
    """Run the full trial matrix, appending one JSON line per (trial,
    condition, arm) as it goes so a mid-run failure keeps every completed
    trial. An existing results file is resumed by default (see
    prepare_output); pass resume=False to start over. The PPO model is
    required: a missing model raises instead of silently substituting
    another policy for the PPO arm."""
    ppo_policy = PPODefensePolicy(model_path=model_path)
    objective = Objective.load()
    env = RealMininetDefenseEnv()
    env._ensure_network()
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    done = prepare_output(output, run_fingerprint(model_path), resume)
    if done:
        print(f"[harness] resuming: {len(done)} complete trial blocks already in {output}", flush=True)

    started = time.monotonic()
    total_conditions_run = len(done)
    total_conditions = trials_per_condition * len(CONDITIONS)
    try:
        with output.open("a", encoding="utf-8") as fh:
            for trial in range(trials_per_condition):
                for condition in CONDITIONS:
                    if (trial, condition) in done:
                        continue
                    rows = run_trial(env, trial, condition, ppo_policy, objective, pcap_dir=pcap_dir)
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

    summary = {
        "trials_per_condition": trials_per_condition,
        "conditions": list(CONDITIONS),
        "total_condition_runs": total_conditions_run,
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "output_path": str(output),
        "pcap_dir": str(pcap_dir) if pcap_dir else None,
    }
    output.with_suffix(".summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials-per-condition", type=int, default=8)
    parser.add_argument("--output", default="data/evaluation/results.jsonl")
    parser.add_argument("--pcap-dir", default="data/evaluation/pcaps")
    parser.add_argument("--no-pcaps", action="store_true", help="Skip preserving raw captures.")
    parser.add_argument("--model-path", default="models/ppo_defense")
    parser.add_argument(
        "--restart", action="store_true",
        help="Discard an existing results file and start over (default: resume it).",
    )
    args = parser.parse_args()
    summary = run_harness(
        trials_per_condition=args.trials_per_condition,
        output_path=args.output,
        pcap_dir=None if args.no_pcaps else args.pcap_dir,
        model_path=args.model_path,
        resume=not args.restart,
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
