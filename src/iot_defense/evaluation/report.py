"""Detection and external-detector summary tables from the harness results.

Policy performance is NOT reported here: it is reported on measured
outcomes by evaluation/outcome_report.py. Detection is shared by every arm
(one detection per trial), so it is a property of the detector, not of any
response policy.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def load_results(path: str | Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def _wilson_ci(numerator: int, denominator: int, z: float = 1.96) -> tuple[float, float] | None:
    """95% Wilson score interval for a binomial proportion (small-n safe,
    unlike the normal approximation, which can leave [0, 1])."""
    if denominator == 0:
        return None
    p = numerator / denominator
    n = denominator
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = (z / denom) * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5)
    return (round(max(0.0, center - margin), 4), round(min(1.0, center + margin), 4))


def summarize_detection(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Detection accuracy per condition. Every arm shares one detection per
    trial, so one arm's rows carry each trial's detection result."""
    sub = [r for r in rows if r["arm"] == "rule_based"]
    by_cond: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in sub:
        by_cond[row["condition"]].append(row)
    per_condition = {}
    for cond, cond_rows in by_cond.items():
        correct = sum(r["detection_correct"] for r in cond_rows)
        per_condition[cond] = {
            "trials": len(cond_rows),
            "detection_accuracy": round(correct / len(cond_rows), 4),
            "detection_accuracy_ci95": _wilson_ci(correct, len(cond_rows)),
        }
    correct_total = sum(r["detection_correct"] for r in sub)
    return {
        "trials": len(sub),
        "detection_accuracy": round(correct_total / len(sub), 4) if sub else 0.0,
        "detection_accuracy_ci95": _wilson_ci(correct_total, len(sub)),
        "mean_detection_latency_ms": round(sum(r["detection_latency_ms"] for r in sub) / len(sub), 1) if sub else 0.0,
        "per_condition": per_condition,
    }


_SURICATA_RULESET_LABELS = {
    "et_open": "Suricata + ET-Open (real-world community rules)",
    "lab": "Suricata + lab-tailored rules (this project's own signatures)",
}


def load_suricata_summary(path: str | Path) -> dict[str, Any] | None:
    summary_path = Path(path)
    if not summary_path.exists():
        return None
    return json.loads(summary_path.read_text(encoding="utf-8"))


def render_markdown(detection: dict[str, Any], source_path: str | Path, suricata_summary: dict[str, Any] | None = None) -> str:
    def fmt(ci: tuple[float, float] | None) -> str:
        return f"[{ci[0] * 100:.1f}, {ci[1] * 100:.1f}]" if ci else "--"

    lines = [
        "# Detection results",
        "",
        f"Source: `{source_path}`. Policy performance is in `outcome_report.md` (measured outcomes).",
        "",
        f"Overall detection accuracy: {detection['detection_accuracy'] * 100:.1f}% "
        f"{fmt(detection.get('detection_accuracy_ci95'))} over {detection['trials']} trials; "
        f"mean detection latency {detection['mean_detection_latency_ms']:.0f} ms.",
        "",
        "| Condition | Trials | Detection accuracy |",
        "|---|---|---|",
    ]
    for cond, s in detection["per_condition"].items():
        lines.append(f"| `{cond}` | {s['trials']} | {s['detection_accuracy'] * 100:.1f}% {fmt(s.get('detection_accuracy_ci95'))} |")
    if suricata_summary:
        lines += ["", "## External detection comparison (Suricata, offline pcap analysis)", "",
                  "| Detector | Accuracy | True positive rate | False positive rate |", "|---|---|---|---|"]
        for ruleset_name, label in _SURICATA_RULESET_LABELS.items():
            s = suricata_summary.get(ruleset_name)
            if s:
                lines.append(
                    f"| {label} | {s['accuracy'] * 100:.1f}% | {s['true_positive_rate'] * 100:.1f}% | "
                    f"{s['false_positive_rate'] * 100:.1f}% |"
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
    detection = summarize_detection(rows)
    suricata_summary = load_suricata_summary(suricata_summary_path)
    summary = {"source": str(results_path), "total_rows": len(rows), "detection": detection, "suricata": suricata_summary}
    Path(json_output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(json_output_path).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    Path(markdown_output_path).write_text(render_markdown(detection, results_path, suricata_summary), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", default="data/evaluation/results.jsonl")
    parser.add_argument("--json-output", default="data/evaluation/summary.json")
    parser.add_argument("--markdown-output", default="data/evaluation/summary.md")
    parser.add_argument("--suricata-summary", default="data/evaluation/suricata_summary.json")
    args = parser.parse_args()
    print(json.dumps(generate_report(
        results_path=args.results, json_output_path=args.json_output,
        markdown_output_path=args.markdown_output, suricata_summary_path=args.suricata_summary,
    ), indent=2))


if __name__ == "__main__":
    main()
