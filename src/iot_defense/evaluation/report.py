"""Aggregate evaluation-harness results into summary tables.

Reads the JSONL results file harness.py writes (one row per trial x
condition x arm) and produces both a machine-readable JSON summary and a
human-readable Markdown table -- the numbers EVALUATION.md is built from,
not hand-copied.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

ARM_ORDER = ("rule_based", "stackelberg", "ppo", "naive_block_all", "always_allow")
ARM_LABELS = {
    "rule_based": "Rule-based (ours)",
    "stackelberg": "Stackelberg (ours, deployed)",
    "ppo": "PPO (ours)",
    "naive_block_all": "NaiveBlockAllBaseline",
    "always_allow": "AlwaysAllowBaseline",
}


def load_results(path: str | Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _wilson_ci(numerator: int, denominator: int, z: float = 1.96) -> tuple[float, float] | None:
    """95% Wilson score confidence interval for a binomial proportion --
    added after a review found this evaluation reported bare
    percentages with no uncertainty measure at all, misleading at the
    small per-condition sample sizes this harness actually uses (a
    single trial swings a per-condition rate by an entire
    1/trials_per_condition step). Wilson, not the naive normal
    approximation (p +/- z*sqrt(p(1-p)/n)), because the naive interval
    is a known poor approximation exactly in this small-n, extreme-p
    regime (it can even fall outside [0, 1]) -- see Wilson (1927),
    the standard fix and what most modern statistics texts recommend
    for binomial proportions at small n.
    """
    if denominator == 0:
        return None
    p = numerator / denominator
    n = denominator
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = (z / denom) * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5)
    return (round(max(0.0, center - margin), 4), round(min(1.0, center + margin), 4))


def summarize_by_arm(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """One row of metrics per arm, across every trial and condition.

    detection_accuracy is expected to be near-identical across arms --
    detection runs once per trial and every arm sees the same result --
    so it's reported per arm mainly as a sanity check, not because arms
    are expected to differ on it. response_verified_rate (matched the
    ground truth's preferred action AND had that response independently,
    really verified for real) is the real comparison metric this
    evaluation exists to produce.
    """
    by_arm: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_arm[row["arm"]].append(row)

    summary: dict[str, dict[str, Any]] = {}
    for arm, sub in by_arm.items():
        n = len(sub)
        attack_rows = [r for r in sub if r["ground_truth_attack_type"] != "normal"]
        detection_correct_n = sum(r["detection_correct"] for r in sub)
        response_verified_n = sum(1 for r in sub if r["response_verified"])
        matches_preferred_n = sum(1 for r in attack_rows if r["matches_preferred_action"])
        summary[arm] = {
            "trials": n,
            "detection_accuracy": _rate(detection_correct_n, n),
            "detection_accuracy_ci95": _wilson_ci(detection_correct_n, n),
            "response_verified_rate": _rate(response_verified_n, n),
            "response_verified_rate_ci95": _wilson_ci(response_verified_n, n),
            "matches_preferred_action_rate_on_attacks": _rate(matches_preferred_n, len(attack_rows)),
            "matches_preferred_action_rate_on_attacks_ci95": _wilson_ci(matches_preferred_n, len(attack_rows)),
            "execution_ok_rate": _rate(sum(r["execution_ok"] for r in sub), n),
            "mean_detection_latency_ms": round(sum(r["detection_latency_ms"] for r in sub) / n, 1) if n else 0.0,
        }
    return summary


def summarize_by_condition(rows: list[dict[str, Any]], arm: str) -> dict[str, dict[str, Any]]:
    """Per-condition breakdown for one arm -- used for the deployed
    (Stackelberg) policy, to show where the aggregate number comes from
    rather than hiding condition-to-condition variation behind one mean."""
    sub = [r for r in rows if r["arm"] == arm]
    by_cond: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in sub:
        by_cond[row["condition"]].append(row)

    result: dict[str, dict[str, Any]] = {}
    for cond, cond_rows in by_cond.items():
        n = len(cond_rows)
        detection_correct_n = sum(r["detection_correct"] for r in cond_rows)
        response_verified_n = sum(1 for r in cond_rows if r["response_verified"])
        result[cond] = {
            "trials": n,
            "detection_accuracy": _rate(detection_correct_n, n),
            "detection_accuracy_ci95": _wilson_ci(detection_correct_n, n),
            "response_verified_rate": _rate(response_verified_n, n),
            "response_verified_rate_ci95": _wilson_ci(response_verified_n, n),
        }
    return result


_SURICATA_RULESET_LABELS = {
    "et_open": "Suricata + ET-Open (real-world community rules)",
    "lab": "Suricata + lab-tailored rules (this project's own signatures)",
}


def load_suricata_summary(path: str | Path) -> dict[str, Any] | None:
    """Suricata analysis is optional -- returns None if the summary file
    (written by suricata_eval.py) doesn't exist, so callers can render a
    report with or without it rather than failing outright."""
    summary_path = Path(path)
    if not summary_path.exists():
        return None
    return json.loads(summary_path.read_text(encoding="utf-8"))


def render_markdown(
    rows: list[dict[str, Any]],
    arm_summary: dict[str, dict[str, Any]],
    condition_summary: dict[str, dict[str, Any]],
    source_path: str | Path,
    suricata_summary: dict[str, Any] | None = None,
) -> str:
    n_trials = len({r["trial"] for r in rows})
    n_conditions = len({r["condition"] for r in rows})
    n_arms = len({r["arm"] for r in rows})

    def _fmt_ci(ci: tuple[float, float] | None) -> str:
        return f"[{ci[0] * 100:.1f}, {ci[1] * 100:.1f}]" if ci else "--"

    lines = [
        "# Evaluation results",
        "",
        f"Source: `{source_path}` -- {len(rows)} rows from {n_trials} trials x "
        f"{n_conditions} conditions x {n_arms} arms, all against real Mininet traffic.",
        "",
        "All rates are proportions of a finite trial count; the bracketed range next to",
        "each one is a 95% Wilson score confidence interval, not a second measurement --",
        "at this harness's own real trial counts a single trial can swing a reported",
        "percentage by a full step, and the interval is how wide that uncertainty",
        "genuinely is, not just the point estimate.",
        "",
        "## Comparison summary",
        "",
        "| Arm | Detection accuracy | Verified response rate | Matches preferred action (attacks only) | Mean detection latency |",
        "|---|---|---|---|---|",
    ]
    for arm in ARM_ORDER:
        if arm not in arm_summary:
            continue
        s = arm_summary[arm]
        lines.append(
            f"| {ARM_LABELS[arm]} | {s['detection_accuracy'] * 100:.1f}% {_fmt_ci(s.get('detection_accuracy_ci95'))} | "
            f"{s['response_verified_rate'] * 100:.1f}% {_fmt_ci(s.get('response_verified_rate_ci95'))} | "
            f"{s['matches_preferred_action_rate_on_attacks'] * 100:.1f}% {_fmt_ci(s.get('matches_preferred_action_rate_on_attacks_ci95'))} | "
            f"{s['mean_detection_latency_ms']:.0f} ms |"
        )
    lines += [
        "",
        "## Per-condition breakdown (Stackelberg -- the policy actually deployed)",
        "",
        "| Condition | Trials | Detection accuracy | Verified response rate |",
        "|---|---|---|---|",
    ]
    for cond, s in condition_summary.items():
        lines.append(
            f"| `{cond}` | {s['trials']} | "
            f"{s['detection_accuracy'] * 100:.1f}% {_fmt_ci(s.get('detection_accuracy_ci95'))} | "
            f"{s['response_verified_rate'] * 100:.1f}% {_fmt_ci(s.get('response_verified_rate_ci95'))} |"
        )

    if suricata_summary:
        lines += [
            "",
            "## External detection comparison (Suricata, offline pcap analysis)",
            "",
            f"{suricata_summary.get('total_pcaps', 0)} pcaps analyzed -- see EVALUATION.md for methodology and honest",
            "caveats about run-to-run variance in this section specifically.",
            "",
            "| Detector | Accuracy | True positive rate | False positive rate |",
            "|---|---|---|---|",
        ]
        for ruleset_name, label in _SURICATA_RULESET_LABELS.items():
            s = suricata_summary.get(ruleset_name)
            if not s:
                continue
            lines.append(
                f"| {label} | {s['accuracy'] * 100:.1f}% | "
                f"{s['true_positive_rate'] * 100:.1f}% | {s['false_positive_rate'] * 100:.1f}% |"
            )

    lines.append("")
    return "\n".join(lines)


def generate_report(
    *,
    results_path: str | Path = "data/evaluation/results.jsonl",
    json_output_path: str | Path = "data/evaluation/summary.json",
    markdown_output_path: str | Path = "data/evaluation/summary.md",
    suricata_summary_path: str | Path = "data/evaluation/suricata_summary.json",
) -> dict[str, Any]:
    rows = load_results(results_path)
    arm_summary = summarize_by_arm(rows)
    condition_summary = summarize_by_condition(rows, "stackelberg")
    suricata_summary = load_suricata_summary(suricata_summary_path)
    summary = {
        "source": str(results_path),
        "total_rows": len(rows),
        "by_arm": arm_summary,
        "by_condition_stackelberg": condition_summary,
        "suricata": suricata_summary,
    }

    json_output = Path(json_output_path)
    json_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    markdown_output = Path(markdown_output_path)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.write_text(
        render_markdown(rows, arm_summary, condition_summary, results_path, suricata_summary), encoding="utf-8"
    )

    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", default="data/evaluation/results.jsonl")
    parser.add_argument("--json-output", default="data/evaluation/summary.json")
    parser.add_argument("--markdown-output", default="data/evaluation/summary.md")
    parser.add_argument("--suricata-summary", default="data/evaluation/suricata_summary.json")
    args = parser.parse_args()
    summary = generate_report(
        results_path=args.results,
        json_output_path=args.json_output,
        markdown_output_path=args.markdown_output,
        suricata_summary_path=args.suricata_summary,
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
