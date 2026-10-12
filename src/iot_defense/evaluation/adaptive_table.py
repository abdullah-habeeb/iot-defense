"""Build the adaptive outcome table: each response measured against a reactive attacker.

Mirrors evaluation/outcome_table.py (blocks of one condition x rep, ALLOW first and last, the other
actions in a seeded shuffle between them, a block written only once ALL its probes are measured so
an interrupted run resumes at the first incomplete block), but each probe is the two-round
measurement of defense/ppo_real_env.py's measure_adaptive(): the attack runs twice against the same
still-active response, and a scripted attacker rotates to a fresh source address between the rounds
if round 1 was mitigated. See evaluation/adaptive_outcome.py for the threat model, and for why it is
a scripted reaction and not a finding about real attackers.

Baselines per block (every row of the block carries them):
  baseline1  packets the registered attack delivers un-responded: mean of both ALLOW probes' two rounds
  baseline2  the same, unless the attacker rotated, in which case the fresh-source attack's own
             un-responded count (two probes, one before and one after the block's responses)

Requires root (Mininet). Typical run, about 5 minutes per block:

    sudo .venv/bin/python -m iot_defense.evaluation.adaptive_table --reps 3
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from dataclasses import replace
from pathlib import Path
from statistics import fmean, pstdev
from typing import Any

from iot_defense.defense.decision import DefenseAction
from iot_defense.evaluation.adaptive_outcome import ADAPTIVE_CONDITIONS, AdaptiveMeasurement, AdaptiveOutcomeTable
from iot_defense.evaluation.outcome_table import SETTLE_SECONDS, action_order

# one probe per action plus the second ALLOW
BLOCK_ROWS = len(DefenseAction) + 1
DEFAULT_OUTPUT = "data/outcomes/adaptive_table.jsonl"


def completed_blocks(path: Path) -> set[tuple[str, int]]:
    if not path.exists():
        return set()
    counts: Counter[tuple[str, int]] = Counter()
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            counts[(row["condition"], int(row["rep"]))] += 1
    return {block for block, count in counts.items() if count == BLOCK_ROWS}


def block_baselines(measured: list[AdaptiveMeasurement], rotated_probes: list[int]) -> tuple[int, int]:
    """(baseline for rounds that repeat the registered attack, baseline for rotated rounds)."""
    allow = [m for m in measured if m.action == DefenseAction.ALLOW]
    if not allow:
        raise ValueError("a block needs its ALLOW probes to set the un-responded baseline")
    same = round(fmean([m.residual1 for m in allow] + [m.residual2 for m in allow]))
    return same, round(fmean(rotated_probes))


def measure_block(env: Any, condition: str, rep: int, seed: int) -> list[dict[str, Any]]:
    threat_event = env._observe_scenario(condition)
    rotated_probes = [env.measure_rotated_baseline(condition)]
    time.sleep(SETTLE_SECONDS)

    measured: list[tuple[int, AdaptiveMeasurement, str | None]] = []
    provisional: int | None = None  # the first ALLOW's round-1 count: lets later probes judge "mitigated"
    for position, action in enumerate(action_order(seed, rep, condition)):
        measurement, outcome = env.measure_adaptive(action, threat_event, condition, baseline1=provisional)
        measured.append((position, measurement, outcome.get("probe_error")))
        if provisional is None and action == DefenseAction.ALLOW:
            provisional = measurement.residual1
        time.sleep(SETTLE_SECONDS)

    rotated_probes.append(env.measure_rotated_baseline(condition))
    same, rotated = block_baselines([m for _, m, _ in measured], rotated_probes)
    return [
        {
            **replace(m, baseline1=same, baseline2=rotated if m.rotated else same).to_row(),
            "rep": rep,
            "order_index": position,
            "seed": seed,
            "detected_condition": threat_event.attack_type,
            "probe_error": probe_error,
            "rotated_baseline_probes": rotated_probes,
            "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        for position, m, probe_error in measured
    ]


def run(*, reps: int, output_path: Path, seed: int, conditions: tuple[str, ...], env_factory: Any = None) -> dict[str, Any]:
    from iot_defense.defense.ppo_real_env import RealMininetDefenseEnv

    output_path.parent.mkdir(parents=True, exist_ok=True)
    done = completed_blocks(output_path)
    env = (env_factory or RealMininetDefenseEnv)()
    env._ensure_network()
    started = time.monotonic()
    new_blocks = 0
    try:
        for rep in range(reps):
            for condition in conditions:
                if (condition, rep) in done:
                    continue
                rows = measure_block(env, condition, rep, seed)
                with output_path.open("a", encoding="utf-8") as fh:
                    for row in rows:
                        fh.write(json.dumps(row) + "\n")
                new_blocks += 1
                invalid = sum(1 for row in rows if row["probe_error"] or row["service_loss1"] < 0 or row["service_loss2"] < 0)
                rotated = sum(1 for row in rows if row["rotated"])
                print(
                    f"[adaptive_table] rep={rep} condition={condition!r} done ({new_blocks} new blocks, "
                    f"{invalid}/{len(rows)} invalid probes, attacker rotated in {rotated}/{len(rows)})",
                    flush=True,
                )
    finally:
        env.close()
    return {"reps": reps, "seed": seed, "new_blocks": new_blocks, "skipped_complete_blocks": len(done),
            "elapsed_seconds": round(time.monotonic() - started, 1), "output_path": str(output_path)}


def summarize_table(path: Path) -> str:
    """Per (condition, action): valid/total probes, how often the attacker rotated, containment in
    each round, and the two-round utility. Sanity-check a smoke run before trusting it."""
    from iot_defense.defense.objective import Objective

    objective = Objective.load()
    cells: dict[tuple[str, str], list[AdaptiveMeasurement]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            m = AdaptiveMeasurement.from_row(json.loads(line))
            cells.setdefault((m.condition, m.action.value), []).append(m)
    lines = [f"{'condition':18s} {'action':17s} valid  rotated  contain1  contain2  svc_loss  utility"]
    for (condition, action), ms in sorted(cells.items()):
        valid = [m for m in ms if m.valid]
        if not valid:
            lines.append(f"{condition:18s} {action:17s} 0/{len(ms)}   (no valid probe)")
            continue
        lines.append(
            f"{condition:18s} {action:17s} {len(valid)}/{len(ms)}    {fmean(float(m.rotated) for m in valid):6.2f}  "
            f"{fmean(m.containments[0] for m in valid):8.2f}  {fmean(m.containments[1] for m in valid):8.2f}  "
            f"{fmean((m.service_loss1 + m.service_loss2) / 2 for m in valid):8.2f}  {fmean(m.utility(objective) for m in valid):7.2f}"
        )
    lines.append("")
    lines.append("Un-responded baseline packets per condition (mean +/- sd over rows):")
    for condition in sorted({c for c, _ in cells}):
        base = [m.baseline1 for (c, _), ms in cells.items() if c == condition for m in ms]
        rot = [m.baseline2 for (c, _), ms in cells.items() if c == condition for m in ms if m.rotated]
        lines.append(f"  {condition:18s} same-source {fmean(base):8.1f} +/- {pstdev(base):.1f}"
                     + (f"   fresh-source {fmean(rot):8.1f} +/- {pstdev(rot):.1f}" if rot else ""))
    return "\n".join(lines)


def load_table(path: str | Path) -> AdaptiveOutcomeTable:
    return AdaptiveOutcomeTable.from_jsonl(path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reps", type=int, default=3)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--seed", type=int, default=11)
    parser.add_argument("--conditions", nargs="*", default=None, help=f"Subset of {ADAPTIVE_CONDITIONS} (default: all).")
    parser.add_argument("--summarize", action="store_true", help="Print a summary of --output and exit.")
    args = parser.parse_args()
    if args.summarize:
        print(summarize_table(Path(args.output)))
        return
    conditions = tuple(args.conditions) if args.conditions else ADAPTIVE_CONDITIONS
    unknown = [c for c in conditions if c not in ADAPTIVE_CONDITIONS]
    if unknown:
        raise SystemExit(f"not adaptive conditions: {unknown}; choose from {ADAPTIVE_CONDITIONS}")
    print(json.dumps(run(reps=args.reps, output_path=Path(args.output), seed=args.seed, conditions=conditions), indent=2))


if __name__ == "__main__":
    main()
