"""Measure every response against the two new attacks, after the freeze, and log it so the log cannot be rewritten unnoticed.

    sudo .venv/bin/python3 -m iot_defense.experiments.new_attacks.measure --reps 3

Refuses to start unless: FREEZE.json exists and every frozen file is unchanged; the pre-registration is valid; the git tree is clean;
HEAD has been pushed (so the server-side push time of the freeze exists); and no measured row exists without a log entry.

It reuses the same measurement code as the 693-row benchmark (evaluation/outcome_table.py): for each of 3 blocks per attack, ALLOW is
measured, then the other nine responses in a seeded random order, then ALLOW again; the two ALLOW probes give the block's baseline.
Rows go to data/experiments/new_attacks/rows.jsonl, never to the benchmark's own table.

Every run appends two records to run_log.jsonl (started, finished). Each carries the sha256 of the rows file before and after and
the sha256 of the previous record, so editing a row or a record later breaks the chain (evidence.py checks it).
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import time
from pathlib import Path
from typing import Any

from iot_defense.experiments.new_attacks import common, prereg
from iot_defense.experiments.new_attacks.scenarios import NEW_ATTACK_KEYS, build_scenarios, registered

DEFAULT_REPS = 3
SEED = 11  # the benchmark's own seed: the shuffle of the response order is f"{seed}:{rep}:{condition}"
GENESIS = "GENESIS"


def _command_output(*command: str) -> str:
    try:
        return subprocess.run(command, capture_output=True, text=True, check=False, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def environment_facts() -> dict[str, Any]:
    return {
        "hostname": platform.node(),
        "kernel": platform.release(),
        "python": platform.python_version(),
        "uid": os.geteuid() if hasattr(os, "geteuid") else None,
        "clock_utc": _command_output("date", "-u", "+%Y-%m-%dT%H:%M:%SZ"),
        "ntp_synchronized": _command_output("timedatectl", "show", "-p", "NTPSynchronized", "--value"),
        "time_zone": _command_output("timedatectl", "show", "-p", "Timezone", "--value"),
    }


def rows_state(rows_path: Path) -> dict[str, Any]:
    lines = common.read_jsonl(rows_path)
    return {"lines": len(lines), "sha256": common.sha256_file(rows_path) if rows_path.exists() else None}


def last_record_digest(run_log: Path) -> str:
    records = common.read_jsonl(run_log)
    return common.sha256_text(common.canonical_json(records[-1])) if records else GENESIS


def preflight(*, skip_push_check: bool = False, rows_path: Path | None = None, run_log: Path | None = None) -> list[str]:
    """Every reason a measurement must not start now (empty list = go)."""
    from iot_defense.defense.objective import load_policy_section

    rows_path = rows_path or common.ROWS_PATH
    run_log = run_log or common.RUN_LOG_PATH
    problems = list(prereg.verify_freeze())
    if not problems:
        problems += prereg.validate(prereg.load(), load_policy_section("game_model"), require_ready=True)
    dirty = common.git("status", "--porcelain")
    if dirty:
        problems.append("the git tree is not clean:\n" + dirty)
    if not common.git("log", "-1", "--format=%H", "--", str(common.FREEZE_PATH.relative_to(common.REPO_ROOT))):
        problems.append("FREEZE.json has never been committed")
    if not skip_push_check:
        head, upstream = common.git("rev-parse", "HEAD"), common.git("rev-parse", "@{u}")
        if not upstream or head != upstream:
            problems.append("HEAD has not been pushed to its upstream branch, so the freeze has no server-side push time")
    if rows_path.exists() and rows_path.stat().st_size > 0 and not common.read_jsonl(run_log):
        problems.append("measured rows exist but there is no run log: refusing to extend an unlogged file")
    if common.read_jsonl(run_log):
        before = rows_state(rows_path)["sha256"]
        recorded = [r for r in common.read_jsonl(run_log) if r.get("event") == "finished"]
        if recorded and recorded[-1]["rows_sha256_after"] != before:
            problems.append("the rows file differs from the last logged state: it was edited outside a logged run")
    return problems


def run_measurement(reps: int, *, phase: str, skip_push_check: bool, rows_path: Path, run_log: Path) -> dict[str, Any]:
    from iot_defense.evaluation import outcome_table

    spec = prereg.load()
    scenarios = build_scenarios(prereg.playbook_actions(spec))
    before = rows_state(rows_path)
    common_fields = {
        "phase": phase,
        "argv": ["measure", f"--reps={reps}", f"--phase={phase}"] + (["--skip-push-check"] if skip_push_check else []),
        "git_head": common.git("rev-parse", "HEAD"),
        "freeze_commit": common.git("log", "-1", "--format=%H", "--", str(common.FREEZE_PATH.relative_to(common.REPO_ROOT))),
        "skip_push_check": skip_push_check,
        **environment_facts(),
    }
    started = {
        "event": "started", "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "started_epoch": time.time(),
        "rows_lines_before": before["lines"], "rows_sha256_before": before["sha256"], "reps": reps,
        "prev_record_sha256": last_record_digest(run_log), **common_fields,
    }
    common.append_jsonl(run_log, started)
    summary: dict[str, Any] = {}
    error: str | None = None
    with registered(scenarios):
        try:
            summary = outcome_table.run(reps=reps, output_path=rows_path, seed=SEED, conditions=tuple(NEW_ATTACK_KEYS))
        except BaseException as exc:  # noqa: BLE001 - the failure itself must be on the record
            error = f"{type(exc).__name__}: {exc}"
    after = rows_state(rows_path)
    finished = {
        "event": "finished", "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "finished_epoch": time.time(),
        "rows_lines_after": after["lines"], "rows_sha256_after": after["sha256"], "new_rows": after["lines"] - before["lines"],
        "summary": summary, "error": error, "prev_record_sha256": last_record_digest(run_log),
    }
    common.append_jsonl(run_log, finished)
    if error:
        raise RuntimeError(error)
    return finished


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reps", type=int, default=DEFAULT_REPS, help="blocks per attack (3 = the primary table; 6 adds 3 confirmatory blocks)")
    parser.add_argument("--phase", choices=["primary", "confirmatory"], default="primary")
    parser.add_argument("--skip-push-check", action="store_true", help="measure with an unpushed HEAD (recorded in the log)")
    args = parser.parse_args()
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise SystemExit("Mininet needs root: sudo .venv/bin/python3 -m iot_defense.experiments.new_attacks.measure")
    problems = preflight(skip_push_check=args.skip_push_check)
    if problems:
        print("NOT measuring; fix these first:")
        for problem in problems:
            print(" -", problem)
        raise SystemExit(2)
    finished = run_measurement(args.reps, phase=args.phase, skip_push_check=args.skip_push_check,
                               rows_path=common.ROWS_PATH, run_log=common.RUN_LOG_PATH)
    print(json.dumps({k: finished[k] for k in ("new_rows", "rows_lines_after", "rows_sha256_after")}, indent=2))
    print("Next: commit the rows and the log, push, then record the time (docs/NEW_ATTACKS_PROTOCOL.md step 7).")


if __name__ == "__main__":
    main()
