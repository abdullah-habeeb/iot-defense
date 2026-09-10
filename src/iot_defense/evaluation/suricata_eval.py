"""Offline Suricata analysis of the evaluation harness's saved pcaps.

Runs two rulesets against every trial's saved capture and compares whether
Suricata alerted against the harness's own ground truth for that trial:
ET-Open (real-world community threat signatures -- expected to
under-perform on this lab's synthetic traffic, since it was never built to
recognize it) and this project's own lab-tailored rules
(config/suricata/lab.rules -- the same shape knowledge detection/
detector.py's own rule-based detectors use, encoded as real Suricata
signatures, so Suricata is judged on a fair version of that knowledge
too, not only on a strawman).

Two different execution strategies, not one, and this was found by
running it for real, not assumed up front: ET-Open runs once in
directory-replay mode (`-r <pcap_dir>`) against every pcap, since loading
and compiling its ~68,000 rules costs several real minutes almost
independent of how much traffic is processed -- paying that cost once
instead of once per pcap is the difference between minutes and hours.
lab.rules runs once *per pcap* instead: a real run showed directory-replay
mode does not reset `threshold`/`detection_filter` state between files,
so a rule like "50+ packets to the same destination within 2 seconds"
ends up tracking cumulative state *across unrelated captures* that happen
to share a destination IP (every attack in this lab targets the same
sensor) -- a pcap that reliably alerted in isolation silently didn't in
the 120-file batch, purely because of which other files were processed
near it. lab.rules is small enough (a handful of signatures) that its own
compile cost is negligible, so per-pcap isolation is cheap and correct
here in a way it isn't for ET-Open.

Requires Suricata installed (`sudo apt install suricata`, outside this
project's scoped sudo access -- a manual one-time step) and a fetched
ruleset (`suricata-update --output <user-writable dir>`, since the
default /var/lib/suricata/rules is root-owned in this environment).
"""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any

_LAB_RULES_DEFAULT = Path(__file__).resolve().parents[3] / "config" / "suricata" / "lab.rules"


def _patched_config(work_dir: Path, system_config: str | Path = "/etc/suricata/suricata.yaml") -> Path:
    """Suricata's eve-log `pcap-file` option -- needed to attribute
    batch-mode alerts back to the specific pcap they came from -- defaults
    to false in the system config, which is root-owned and not writable
    in this environment. Rather than committing a large, fragile
    near-duplicate of the system config to the repo, patch just that one
    line into a scratch copy at runtime."""
    system_config = Path(system_config)
    text = system_config.read_text(encoding="utf-8")
    patched_text = text.replace("pcap-file: false", "pcap-file: true", 1)
    if patched_text == text:
        raise RuntimeError(f"Expected to find 'pcap-file: false' in {system_config} to patch -- not found.")
    patched = work_dir / "suricata.yaml"
    patched.write_text(patched_text, encoding="utf-8")
    return patched


def _run_suricata(cmd: list[str], eve_path: Path, timeout: int) -> list[dict[str, Any]]:
    if eve_path.exists():
        eve_path.unlink()
    subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    events: list[dict[str, Any]] = []
    if eve_path.exists():
        with eve_path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    events.append(event)
    return events


def run_suricata_batch(
    pcap_dir: str | Path, config_path: str | Path, rules_path: str | Path, out_dir: str | Path
) -> dict[str, list[dict[str, Any]]]:
    """Run Suricata once, in directory-replay mode, against every pcap in
    pcap_dir with one ruleset. Returns {pcap_filename: [alert_event, ...]}.

    Only appropriate for rulesets without cross-file-sensitive stateful
    keywords (threshold/detection_filter) that share a tracker key across
    otherwise-unrelated pcaps -- see the module docstring. ET-Open's rules
    are predominantly per-packet/per-flow content matches, not the kind of
    small, shared-destination stateful counters this lab's own rules use,
    so batch mode's lack of per-file state reset does not meaningfully
    affect it the same way.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    events = _run_suricata(
        [
            "suricata",
            "-c", str(config_path),
            "-r", str(pcap_dir),
            "-S", str(rules_path),
            "-l", str(out_dir),
            "-k", "none",  # Mininet's virtual interfaces often produce packets with
                           # unset/invalid checksums; without this Suricata silently
                           # drops them as corrupt before any rule ever sees them.
        ],
        out_dir / "eve.json",
        timeout=1800,
    )
    alerts_by_pcap: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        # Suricata reports pcap_filename as the path it was invoked with
        # (here, a relative path under pcap_dir), not a bare basename --
        # normalize to the basename so this matches _distinct_pcaps()'s
        # keys regardless of what directory Suricata was run from.
        name = Path(event.get("pcap_filename", "")).name
        alerts_by_pcap[name].append(event)
    return alerts_by_pcap


def run_suricata_per_pcap(
    pcaps: dict[str, dict[str, Any]], config_path: str | Path, rules_path: str | Path, out_dir: str | Path
) -> dict[str, list[dict[str, Any]]]:
    """Run Suricata once per pcap, a fresh process (and fresh detection
    state) each time -- see the module docstring for why this matters for
    a small, stateful ruleset like lab.rules."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    alerts_by_pcap: dict[str, list[dict[str, Any]]] = {}
    for pcap_name, meta in pcaps.items():
        pcap_out_dir = out_dir / Path(pcap_name).stem
        pcap_out_dir.mkdir(parents=True, exist_ok=True)
        alerts_by_pcap[pcap_name] = _run_suricata(
            [
                "suricata",
                "-c", str(config_path),
                "-r", str(meta["pcap_path"]),
                "-S", str(rules_path),
                "-l", str(pcap_out_dir),
                "-k", "none",
            ],
            pcap_out_dir / "eve.json",
            timeout=60,
        )
    return alerts_by_pcap


def _distinct_pcaps(results_path: str | Path) -> dict[str, dict[str, Any]]:
    """One entry per distinct pcap referenced in the harness's results
    file (every arm's row for one trial shares the same pcap -- only
    need it once), keyed by the pcap's basename (matching how Suricata
    reports pcap_filename in directory-replay mode)."""
    seen: dict[str, dict[str, Any]] = {}
    with open(results_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            pcap_path = row.get("pcap_path")
            if not pcap_path:
                continue
            name = Path(pcap_path).name
            if name not in seen:
                seen[name] = {
                    "pcap_path": pcap_path,
                    "trial": row["trial"],
                    "condition": row["condition"],
                    "ground_truth_attack_type": row["ground_truth_attack_type"],
                }
    return seen


def evaluate_pcaps(
    results_path: str | Path,
    batch_rulesets: dict[str, str | Path],
    per_pcap_rulesets: dict[str, str | Path],
    pcap_dir: str | Path,
    work_dir: str | Path,
    system_config: str | Path = "/etc/suricata/suricata.yaml",
) -> list[dict[str, Any]]:
    pcaps = _distinct_pcaps(results_path)
    # run_suricata_batch() scans every file physically present in pcap_dir,
    # not specifically the pcaps referenced by results_path -- if pcap_dir
    # doesn't actually match the run that produced results_path (a stale
    # or wrong --pcap-dir), every batch-mode alert lookup below silently
    # falls back to "no alert" (dict.get(name, [])) rather than erroring,
    # making every ruleset look like it detected nothing instead of
    # surfacing the real mismatch. Fail loud here instead.
    missing = [meta["pcap_path"] for meta in pcaps.values() if not Path(meta["pcap_path"]).exists()]
    if missing:
        raise FileNotFoundError(
            f"{len(missing)} pcap(s) referenced by {results_path} are missing on disk "
            f"(first: {missing[0]!r}) -- pcap_dir likely doesn't match the harness run "
            f"that produced this results file."
        )
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    config_path = _patched_config(work_dir, system_config)

    alerts_by_ruleset: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for ruleset_name, rules_path in batch_rulesets.items():
        print(f"[suricata_eval] running Suricata (batch) with ruleset {ruleset_name!r} against {len(pcaps)} pcaps...", flush=True)
        alerts_by_ruleset[ruleset_name] = run_suricata_batch(pcap_dir, config_path, rules_path, work_dir / ruleset_name)
    for ruleset_name, rules_path in per_pcap_rulesets.items():
        print(f"[suricata_eval] running Suricata (per-pcap) with ruleset {ruleset_name!r} against {len(pcaps)} pcaps...", flush=True)
        alerts_by_ruleset[ruleset_name] = run_suricata_per_pcap(pcaps, config_path, rules_path, work_dir / ruleset_name)

    ruleset_names = list(batch_rulesets) + list(per_pcap_rulesets)
    rows: list[dict[str, Any]] = []
    for pcap_name, meta in pcaps.items():
        row = dict(meta)
        ground_truth_is_attack = meta["ground_truth_attack_type"] != "normal"
        for ruleset_name in ruleset_names:
            alerts = alerts_by_ruleset[ruleset_name].get(pcap_name, [])
            alerted = len(alerts) > 0
            row[f"{ruleset_name}_alert_count"] = len(alerts)
            row[f"{ruleset_name}_alerted"] = alerted
            row[f"{ruleset_name}_correct"] = alerted == ground_truth_is_attack
            row[f"{ruleset_name}_signatures"] = sorted({a.get("alert", {}).get("signature", "") for a in alerts})
        rows.append(row)
    return rows


def summarize(rows: list[dict[str, Any]], ruleset_names: list[str]) -> dict[str, Any]:
    summary: dict[str, Any] = {"total_pcaps": len(rows)}
    attack_rows = [r for r in rows if r["ground_truth_attack_type"] != "normal"]
    normal_rows = [r for r in rows if r["ground_truth_attack_type"] == "normal"]
    for ruleset_name in ruleset_names:
        n = len(rows)
        correct = sum(1 for r in rows if r[f"{ruleset_name}_correct"])
        tpr = sum(1 for r in attack_rows if r[f"{ruleset_name}_alerted"]) / len(attack_rows) if attack_rows else 0.0
        fpr = sum(1 for r in normal_rows if r[f"{ruleset_name}_alerted"]) / len(normal_rows) if normal_rows else 0.0
        summary[ruleset_name] = {
            "accuracy": round(correct / n, 4) if n else 0.0,
            "true_positive_rate": round(tpr, 4),
            "false_positive_rate": round(fpr, 4),
        }
    return summary


def generate_suricata_report(
    *,
    results_path: str | Path = "data/evaluation/results.jsonl",
    pcap_dir: str | Path = "data/evaluation/pcaps",
    et_open_rules: str | Path,
    lab_rules: str | Path = _LAB_RULES_DEFAULT,
    work_dir: str | Path = "data/evaluation/suricata",
    output_path: str | Path = "data/evaluation/suricata_results.jsonl",
    summary_path: str | Path = "data/evaluation/suricata_summary.json",
) -> dict[str, Any]:
    rows = evaluate_pcaps(
        results_path,
        batch_rulesets={"et_open": et_open_rules},
        per_pcap_rulesets={"lab": lab_rules},
        pcap_dir=pcap_dir,
        work_dir=work_dir,
    )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")

    summary = summarize(rows, ["et_open", "lab"])
    Path(summary_path).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", default="data/evaluation/results.jsonl")
    parser.add_argument("--pcap-dir", default="data/evaluation/pcaps")
    parser.add_argument("--et-open-rules", required=True, help="Path to a fetched ET-Open suricata.rules file.")
    parser.add_argument("--lab-rules", default=str(_LAB_RULES_DEFAULT))
    parser.add_argument("--work-dir", default="data/evaluation/suricata")
    parser.add_argument("--output", default="data/evaluation/suricata_results.jsonl")
    parser.add_argument("--summary-output", default="data/evaluation/suricata_summary.json")
    args = parser.parse_args()
    summary = generate_suricata_report(
        results_path=args.results,
        pcap_dir=args.pcap_dir,
        et_open_rules=args.et_open_rules,
        lab_rules=args.lab_rules,
        work_dir=args.work_dir,
        output_path=args.output,
        summary_path=args.summary_output,
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
