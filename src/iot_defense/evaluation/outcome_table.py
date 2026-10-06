"""Build the measured outcome table: every condition x every action, repeated.

For each (condition, rep) block: observe the condition once (live detection;
only its captured protocol and scores are used -- the response always targets
the canonical sensor/attacker pair, never the detector's IPs), measure ALLOW,
then the other actions in a seeded random order (so action order cannot be a
confound), then ALLOW again, with a settle pause between measurements. The
two ALLOW probes' mean is the block's un-responded baseline. A block is
written to the JSONL file only after ALL of its probes are measured, so an
interrupted run leaves no partial block and re-running resumes at the first
incomplete one.

PPO trains from this table (defense/ppo_env.py). The held-out evaluation
(evaluation/harness.py) re-measures on fresh trials; it never reads this file.

Requires root (Mininet). Typical run (hours -- mqtt_flood alone is ~2 minutes
per probe):

    sudo .venv/bin/python -m iot_defense.evaluation.outcome_table --reps 2
"""

from __future__ import annotations

import argparse
import json
import random
import time
from collections import Counter
from pathlib import Path
from typing import Any

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.ppo_env import TRAINING_SCENARIOS
from iot_defense.defense.ppo_real_env import RealMininetDefenseEnv
from iot_defense.evaluation.outcome import consensus_baseline, with_baseline

SETTLE_SECONDS = 1.0
# one probe per action plus the second ALLOW
BLOCK_ROWS = len(DefenseAction) + 1


def completed_blocks(path: Path) -> set[tuple[str, int]]:
    if not path.exists():
        return set()
    counts: Counter[tuple[str, int]] = Counter()
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            counts[(row["condition"], int(row["rep"]))] += 1
    return {block for block, count in counts.items() if count == BLOCK_ROWS}


def action_order(seed: int, rep: int, condition: str) -> list[DefenseAction]:
    """ALLOW first and last (the baseline probes), every other action in a
    seeded shuffle between them."""
    others = [action for action in DefenseAction if action != DefenseAction.ALLOW]
    random.Random(f"{seed}:{rep}:{condition}").shuffle(others)
    return [DefenseAction.ALLOW, *others, DefenseAction.ALLOW]


def measure_block(
    env: RealMininetDefenseEnv, condition: str, rep: int, seed: int
) -> list[dict[str, Any]]:
    threat_event = env._observe_scenario(condition)
    measured = []
    for position, action in enumerate(action_order(seed, rep, condition)):
        measurement, outcome = env.measure_response(action, threat_event, condition)
        measured.append((position, measurement, outcome.get("probe_error")))
        time.sleep(SETTLE_SECONDS)
    baseline = consensus_baseline([m for _, m, _ in measured if m.action == DefenseAction.ALLOW])
    return [
        {
            **with_baseline(m, baseline).to_row(),
            "rep": rep,
            "order_index": position,
            "seed": seed,
            "detected_condition": threat_event.attack_type,
            "probe_error": probe_error,
            "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        for position, m, probe_error in measured
    ]


def run(*, reps: int, output_path: Path, seed: int, conditions: tuple[str, ...]) -> dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    done = completed_blocks(output_path)
    env = RealMininetDefenseEnv()
    env._ensure_network()
    started = time.monotonic()
    measured_blocks = 0
    try:
        for rep in range(reps):
            for condition in conditions:
                if (condition, rep) in done:
                    continue
                rows = measure_block(env, condition, rep, seed)
                with output_path.open("a", encoding="utf-8") as fh:
                    for row in rows:
                        fh.write(json.dumps(row) + "\n")
                measured_blocks += 1
                invalid = sum(1 for row in rows if row["probe_error"] or row["service_loss"] < 0)
                print(
                    f"[outcome_table] rep={rep} condition={condition!r} done "
                    f"({measured_blocks} new blocks, {invalid}/{len(rows)} invalid probes)",
                    flush=True,
                )
    finally:
        env.close()
    return {
        "reps": reps,
        "seed": seed,
        "new_blocks": measured_blocks,
        "skipped_complete_blocks": len(done),
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "output_path": str(output_path),
    }


def summarize_table(path: Path) -> str:
    """Per (condition, action): valid/total probes and mean measured containment,
    service loss, intel rate and utility -- for sanity-checking a (smoke) run
    before trusting it. Also the ALLOW baseline's spread across reps: a noisy
    baseline makes every containment figure for that condition noisy."""
    from statistics import mean, pstdev

    from iot_defense.defense.objective import Objective
    from iot_defense.evaluation.outcome import Measurement, realized_utility

    objective = Objective.load()
    cells: dict[tuple[str, str], list[Measurement]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            m = Measurement.from_row(json.loads(line))
            cells.setdefault((m.condition, m.action.value), []).append(m)
    lines = [f"{'condition':30s} {'action':17s} valid  contain  svc_loss  intel  utility"]
    for (condition, action), ms in sorted(cells.items()):
        valid = [m for m in ms if m.valid]
        if not valid:
            lines.append(f"{condition:30s} {action:17s} 0/{len(ms)}   (no valid probe)")
            continue
        containment = [m.containment for m in valid if m.containment is not None]
        lines.append(
            f"{condition:30s} {action:17s} {len(valid)}/{len(ms)}    "
            f"{(f'{mean(containment):.2f}' if containment else '  - '):>7s}  {mean(m.service_loss for m in valid):8.2f}  "
            f"{mean(float(m.intel_verified) for m in valid):5.2f}  {mean(realized_utility(m, objective) for m in valid):7.2f}"
        )
    lines.append("")
    lines.append("ALLOW baseline packets per condition (mean +/- sd over reps):")
    for (condition, action), ms in sorted(cells.items()):
        if action == "ALLOW" and condition != "normal":
            counts = [m.residual_packets for m in ms]
            lines.append(f"  {condition:30s} {mean(counts):8.1f} +/- {pstdev(counts):.1f}  (n={len(counts)})")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reps", type=int, default=2)
    parser.add_argument("--output", default="data/outcomes/outcome_table.jsonl")
    parser.add_argument("--seed", type=int, default=11)
    parser.add_argument("--conditions", nargs="*", default=None, help="Subset of conditions (default: all).")
    parser.add_argument("--summarize", action="store_true", help="Print a summary of --output and exit.")
    args = parser.parse_args()
    if args.summarize:
        print(summarize_table(Path(args.output)))
        return
    summary = run(
        reps=args.reps,
        output_path=Path(args.output),
        seed=args.seed,
        conditions=tuple(args.conditions) if args.conditions else TRAINING_SCENARIOS(),
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
