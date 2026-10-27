"""How good is the detector, measured honestly: per-attack precision and recall with intervals, false alarms on
normal traffic, and time to detect.

Three independent looks, none of which trains on what it is scored on:

  * Saved captures (data/evaluation/pcaps): every Mininet capture the harness kept, re-classified offline with the
    deployed UnifiedRuleBasedDetector. The label is the scenario that generated the traffic.
  * The labelled flow table (data/ml/controlled_flows_17class.csv): the rule-based detector and a Random Forest
    cross-validated by run, so every row is scored by a model that never saw it.
  * Time to detect: each saved attack capture replayed through the live defender's rolling-window logic
    (evaluation/pcap_replay.py), measuring seconds from the first packet to the defender acting.

The harness's own `detection_latency_ms` is NOT a time-to-detect: it times the whole observation (generating the
traffic, capturing it, classifying it), so it is reported only as what it is.

    python -m iot_defense.evaluation.detection_report
"""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from iot_defense.detection.detector import UnifiedRuleBasedDetector
from iot_defense.detection.flow_features import FeatureAggregator
from iot_defense.evaluation.pcap_replay import protected_from_subnet, read_events, replay

# The capturing sensor and the attacker host in the lab topology (see demo / ppo_real_env): used only to label
# direction and to leave the attacker out of the protected set.
SENSOR_IP = "10.0.0.10"
ATTACKER_IP = "10.0.0.100"
LAB_SUBNET = "10.0.0.0/24"
PCAP_NAME = re.compile(r"trial(\d+)_(.+)\.pcap$")


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion; (0, 1) when there is nothing to measure."""
    if total <= 0:
        return (0.0, 1.0)
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def per_class(pairs: Iterable[tuple[str, str]], labels: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Precision, recall and F1 per label from (truth, prediction) pairs, each with a 95% interval."""
    pairs = list(pairs)
    out: dict[str, dict[str, Any]] = {}
    for label in labels:
        tp = sum(1 for t, p in pairs if t == label and p == label)
        fp = sum(1 for t, p in pairs if t != label and p == label)
        fn = sum(1 for t, p in pairs if t == label and p != label)
        support = tp + fn
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / support if support else None
        f1 = 2 * precision * recall / (precision + recall) if precision and recall else (0.0 if support else None)
        out[label] = {
            "support": support,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": precision,
            "precision_ci": wilson(tp, tp + fp) if tp + fp else None,
            "recall": recall,
            "recall_ci": wilson(tp, support) if support else None,
            "f1": f1,
        }
    return out


def false_alarm_summary(pairs: Iterable[tuple[str, str]]) -> dict[str, Any]:
    """Of the benign samples, how many were flagged as some attack. With few samples the interval is wide: say so."""
    benign = [(t, p) for t, p in pairs if t == "normal"]
    flagged = sum(1 for _, p in benign if p != "normal")
    low, high = wilson(flagged, len(benign))
    return {"benign_samples": len(benign), "flagged": flagged, "rate": flagged / len(benign) if benign else None, "ci": (low, high)}


# ── Saved captures ───────────────────────────────────────────────────────────
def classify_capture(path: Path, detector: UnifiedRuleBasedDetector, aggregator: FeatureAggregator) -> tuple[str, list[dict[str, Any]]]:
    """What the batch pipeline (the one the harness uses) says about one saved capture."""
    events = read_events(path, SENSOR_IP)
    flows = aggregator.aggregate(events)
    if flows:
        return detector.detect_flows(flows).attack_type, events
    return "normal", events


def evaluate_captures(pcap_dir: str | Path) -> dict[str, Any]:
    detector = UnifiedRuleBasedDetector()
    aggregator = FeatureAggregator()
    rows: list[dict[str, Any]] = []
    unreadable: list[str] = []
    for path in sorted(Path(pcap_dir).glob("*.pcap")):
        match = PCAP_NAME.search(path.name)
        if not match:
            continue
        truth = match.group(2)
        try:
            predicted, events = classify_capture(path, detector, aggregator)
        except Exception:  # noqa: BLE001 - an empty or truncated capture is a dry observation, not a detector result
            unreadable.append(path.name)
            continue
        protected = {ip for ip in protected_from_subnet(events, LAB_SUBNET) if ip != ATTACKER_IP}
        timing = replay(events, protected) if protected else None
        rows.append({
            "file": path.name,
            "truth": truth,
            "predicted": predicted,
            "windowed_delay_seconds": None if timing is None else timing["first_action_delay_seconds"],
            "windowed_acted_on": [] if timing is None else [r["attack_type"] for r in timing["acted_on"]],
        })
    labels = sorted({r["truth"] for r in rows} | {r["predicted"] for r in rows})
    pairs = [(r["truth"], r["predicted"]) for r in rows]
    correct = sum(1 for t, p in pairs if t == p)
    delays: dict[str, list[float]] = defaultdict(list)
    missed: Counter[str] = Counter()
    for r in rows:
        if r["truth"] == "normal":
            continue
        if r["windowed_delay_seconds"] is None:
            missed[r["truth"]] += 1
        else:
            delays[r["truth"]].append(r["windowed_delay_seconds"])
    return {
        "captures": len(rows),
        "unreadable_captures": unreadable,
        "accuracy": correct / len(rows) if rows else None,
        "accuracy_ci": wilson(correct, len(rows)),
        "per_class": per_class(pairs, labels),
        "false_alarms": false_alarm_summary(pairs),
        "confusions": {f"{t} -> {p}": n for (t, p), n in Counter((t, p) for t, p in pairs if t != p).items()},
        "time_to_detect": {
            label: {
                "captures": len(delays[label]) + missed[label],
                "detected_by_windowed_defender": len(delays[label]),
                "median_seconds": statistics.median(delays[label]) if delays[label] else None,
                "max_seconds": max(delays[label]) if delays[label] else None,
            }
            for label in sorted(set(delays) | set(missed))
        },
        "windowed_false_alarms_on_normal": sum(1 for r in rows if r["truth"] == "normal" and r["windowed_acted_on"]),
    }


CONFIGS: tuple[tuple[str, str, float], ...] = (
    ("before", "inbound", 5.0),   # the live demo as first built: only traffic arriving at the host, last 5 s
    ("after", "both", 60.0),      # traffic in both directions, last 60 s
)


def label_timeline(pcap_dir: str | Path, configs: tuple[tuple[str, str, float], ...] = CONFIGS, per_class: int | None = None) -> dict[str, Any]:
    """What the live defender says about each attack, second by second, under each configuration.

    The defender acts on the label current at its second consecutive flagged check, so that is `at_action`. Early
    evidence often resembles a different attack and the right name appears later, so the time until the label is
    right (`time_to_correct`) is the real measure of how soon an attack is *understood*, as opposed to noticed."""
    by_class: dict[str, list[Path]] = defaultdict(list)
    for path in sorted(Path(pcap_dir).glob("*.pcap")):
        match = PCAP_NAME.search(path.name)
        if match and (per_class is None or len(by_class[match.group(2)]) < per_class):
            by_class[match.group(2)].append(path)
    table: dict[str, dict[str, Any]] = {}
    for label, paths in by_class.items():
        stats: dict[str, dict[str, Any]] = {
            name: {"acted": 0, "right_at_action": 0, "ever_right": 0, "to_act": [], "to_correct": [], "first_names": Counter()}
            for name, _, _ in configs
        }
        scored = 0
        for path in paths:
            try:
                events = read_events(path, SENSOR_IP)
            except Exception:  # noqa: BLE001 - an empty capture carries no information
                continue
            protected = {ip for ip in protected_from_subnet(events, LAB_SUBNET) if ip != ATTACKER_IP}
            if not protected:
                continue
            scored += 1
            for name, directions, window in configs:
                outcome = replay(events, protected, window_seconds=window, directions=directions)
                st = stats[name]
                alarms = outcome["alarms"]
                if outcome["acted_on"]:
                    st["acted"] += 1
                    first_run = min(outcome["acted_on"], key=lambda r: r["start"])
                    # the label at the confirming check, which is what the defender's decision is built on
                    confirm_at = first_run["start"] + 1.0 - outcome["start_epoch"]
                    at_action = min(alarms, key=lambda a: abs(a["t"] - confirm_at))["attack_type"] if alarms else None
                    st["right_at_action"] += int(at_action == label)
                    st["to_act"].append(confirm_at)
                    st["first_names"][alarms[0]["attack_type"]] += 1
                correct = [a["t"] for a in alarms if a["attack_type"] == label]
                if correct:
                    st["ever_right"] += 1
                    st["to_correct"].append(correct[0])
        table[label] = {
            "captures": scored,
            "by_config": {
                name: {
                    "acted_on": st["acted"],
                    "right_at_action": st["right_at_action"],
                    "ever_right": st["ever_right"],
                    "median_seconds_to_act": statistics.median(st["to_act"]) if st["to_act"] else None,
                    "median_seconds_to_correct": statistics.median(st["to_correct"]) if st["to_correct"] else None,
                    "max_seconds_to_correct": max(st["to_correct"]) if st["to_correct"] else None,
                    "first_names": dict(st["first_names"]),
                }
                for name, st in stats.items()
            },
        }
    return {"configs": [{"name": n, "directions": d, "window_seconds": w} for n, d, w in configs], "classes": dict(sorted(table.items()))}


# ── Labelled flow table ──────────────────────────────────────────────────────
def evaluate_flow_table(csv_path: str | Path, folds: int = 5, seed: int = 7) -> dict[str, Any]:
    import pandas as pd
    from sklearn.model_selection import GroupKFold

    from iot_defense.ml.random_forest import build_random_forest_pipeline
    from iot_defense.ml.schema import FEATURE_COLUMNS

    data = pd.read_csv(csv_path)
    truth = data["label_name"].tolist()
    detector = UnifiedRuleBasedDetector()
    rule_pred = [detector.detect(row).attack_type for row in data.to_dict("records")]

    forest_pred = [""] * len(data)
    splitter = GroupKFold(n_splits=min(folds, data["run_id"].nunique()))
    for train_idx, test_idx in splitter.split(data, groups=data["run_id"]):
        pipeline = build_random_forest_pipeline(seed=seed)
        pipeline.fit(data.iloc[train_idx][list(FEATURE_COLUMNS)], data.iloc[train_idx]["label_name"])
        predictions = pipeline.predict(data.iloc[test_idx][list(FEATURE_COLUMNS)])
        for position, value in zip(test_idx, predictions):
            forest_pred[position] = value

    labels = sorted(set(truth))
    result: dict[str, Any] = {"rows": len(data), "folds": folds}
    for name, predicted in (("rule_based", rule_pred), ("random_forest_cv", forest_pred)):
        pairs = list(zip(truth, predicted))
        correct = sum(1 for t, p in pairs if t == p)
        result[name] = {
            "accuracy": correct / len(pairs),
            "accuracy_ci": wilson(correct, len(pairs)),
            "per_class": per_class(pairs, labels),
            "false_alarms": false_alarm_summary(pairs),
        }
    return result


# ── Live harness trials ──────────────────────────────────────────────────────
def evaluate_harness(results_path: str | Path) -> dict[str, Any]:
    """The 8-trials-per-condition live run (includes the distributed attacks). One row per trial: the arms share a
    detector, so only one arm's rows are used."""
    rows = [json.loads(line) for line in Path(results_path).read_text(encoding="utf-8").splitlines() if line.strip()]
    first_arm = rows[0]["arm"]
    rows = [r for r in rows if r["arm"] == first_arm]
    pairs = [(r["ground_truth_attack_type"], r["detected_attack_type"]) for r in rows]
    labels = sorted({t for t, _ in pairs} | {p for _, p in pairs})
    correct = sum(1 for t, p in pairs if t == p)
    latencies = [float(r["detection_latency_ms"]) for r in rows]
    return {
        "trials": len(rows),
        "accuracy": correct / len(rows),
        "accuracy_ci": wilson(correct, len(rows)),
        "per_class": per_class(pairs, labels),
        "false_alarms": false_alarm_summary(pairs),
        "confusions": {f"{t} -> {p}": n for (t, p), n in Counter((t, p) for t, p in pairs if t != p).items()},
        "whole_observation_ms": {
            "note": "times generating the traffic, capturing it and classifying it; not a time-to-detect",
            "median": statistics.median(latencies),
            "max": max(latencies),
        },
    }


def build_report(pcap_dir: str, csv_path: str, harness_path: str, robustness_path: str | None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "captures": evaluate_captures(pcap_dir),
        "flow_table": evaluate_flow_table(csv_path),
        "live_harness": evaluate_harness(harness_path),
        "label_timeline": label_timeline(pcap_dir),
    }
    if robustness_path and Path(robustness_path).exists():
        report["threshold_margin"] = json.loads(Path(robustness_path).read_text(encoding="utf-8"))
    return report


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.0f}%"


def _ci(interval: Any) -> str:
    return "n/a" if not interval else f"[{interval[0] * 100:.0f}-{interval[1] * 100:.0f}%]"


def _class_table(block: dict[str, Any]) -> list[str]:
    lines = ["| Class | n | Recall | 95% CI | Precision | 95% CI | Missed (FN) | Wrongly flagged (FP) |", "|---|---|---|---|---|---|---|---|"]
    for label, v in block["per_class"].items():
        if not v["support"] and not v["fp"]:
            continue
        lines.append(f"| {label} | {v['support']} | {_pct(v['recall'])} | {_ci(v['recall_ci'])} | {_pct(v['precision'])} | {_ci(v['precision_ci'])} | {v['fn']} | {v['fp']} |")
    return lines


def render_markdown(report: dict[str, Any]) -> str:
    c, t, h = report["captures"], report["flow_table"], report["live_harness"]
    fa = c["false_alarms"]
    lines = [
        "# Detector evaluation",
        "",
        "Offline scoring of the deployed rule-based detector (and a cross-validated Random Forest) on lab traffic. "
        "Intervals are 95% Wilson intervals; with few samples they are wide, and that width is the honest result.",
        "",
        "## 1. Saved captures (Mininet pcaps, batch pipeline)",
        "",
        f"{c['captures']} captures scored ({len(c['unreadable_captures'])} empty or unreadable captures skipped). Accuracy {_pct(c['accuracy'])} {_ci(c['accuracy_ci'])}.",
        f"False alarms on normal traffic: {fa['flagged']} of {fa['benign_samples']} benign captures flagged ({_pct(fa['rate'])}, 95% interval {_ci(fa['ci'])}). "
        "A rate cannot be pinned down from this few benign samples; see `pcap_replay` for hours of benign traffic.",
        "",
        *_class_table(c),
        "",
    ]
    if c["confusions"]:
        lines += ["Mistakes (truth -> predicted): " + "; ".join(f"{k} x{v}" for k, v in c["confusions"].items()), ""]
    lines += ["### Time to detect (live defender's rolling window, replayed on the saved attack captures)", "",
              "Seconds from the first packet to the defender acting (5 s window, 2 consecutive flagged checks). "
              "A capture the window never acted on counts as missed. Captures are truncated at a packet limit, so slow attacks can look worse than they are.", "",
              "| Attack | Captures | Acted on | Median s | Max s |", "|---|---|---|---|---|"]
    for label, v in c["time_to_detect"].items():
        median = "n/a" if v["median_seconds"] is None else f"{v['median_seconds']:.1f}"
        top = "n/a" if v["max_seconds"] is None else f"{v['max_seconds']:.1f}"
        lines.append(f"| {label} | {v['captures']} | {v['detected_by_windowed_defender']} | {median} | {top} |")
    lines += ["", f"Windowed false alarms on the normal captures: {c['windowed_false_alarms_on_normal']}.", "",
              "## 2. Labelled flow table (260 single flows, by run)", "",
              f"Rule-based accuracy {_pct(t['rule_based']['accuracy'])} {_ci(t['rule_based']['accuracy_ci'])}; "
              f"Random Forest, {t['folds']}-fold cross-validated by run, {_pct(t['random_forest_cv']['accuracy'])} {_ci(t['random_forest_cv']['accuracy_ci'])}. "
              "This table has no inter-arrival column, so the rule-based beacon detector cannot fire on it; read its C2 row accordingly.", "",
              "### Rule-based", "", *_class_table(t["rule_based"]), "", "### Random Forest (cross-validated)", "", *_class_table(t["random_forest_cv"]), "",
              "## 3. Live harness trials (includes distributed attacks)", "",
              f"{h['trials']} trials. Accuracy {_pct(h['accuracy'])} {_ci(h['accuracy_ci'])}. "
              f"Normal trials flagged: {h['false_alarms']['flagged']} of {h['false_alarms']['benign_samples']}.", "",
              *_class_table(h), ""]
    if h["confusions"]:
        lines += ["Mistakes: " + "; ".join(f"{k} x{v}" for k, v in h["confusions"].items()), ""]
    lines += [f"The harness's `detection_latency_ms` (median {h['whole_observation_ms']['median']:.0f} ms) times the whole observation, "
              "including generating and capturing the traffic. It is not a time-to-detect.", ""]
    timeline = report.get("label_timeline")
    if timeline:
        names = [c["name"] for c in timeline["configs"]]
        lines += ["## 4. Is the attack named correctly, and how soon?", "",
                  "The defender acts at its second consecutive flagged check, using the label current at that moment. "
                  "Early evidence often looks like a different attack, so the table also gives how long until the label is right. "
                  + " ".join(f"**{c['name']}**: {c['directions']} traffic, last {c['window_seconds']:.0f} s." for c in timeline["configs"]),
                  "",
                  "Each cell: captures acted on / label right when it acted / label right at some point, then median seconds to act and to the right label.", "",
                  "| Class | Captures | " + " | ".join(names) + " |", "|---|---|" + "---|" * len(names)]
        for label, v in timeline["classes"].items():
            cells = []
            for name in names:
                r = v["by_config"][name]
                ttc = "-" if r["median_seconds_to_correct"] is None else f"{r['median_seconds_to_correct']:.0f}s"
                tta = "-" if r["median_seconds_to_act"] is None else f"{r['median_seconds_to_act']:.0f}s"
                if label == "normal":
                    cells.append(f"false alarms: {r['acted_on']}/{v['captures']}")
                else:
                    cells.append(f"{r['acted_on']} / {r['right_at_action']} / {r['ever_right']} of {v['captures']} (act {tta}, right {ttc})")
            lines.append(f"| {label} | {v['captures']} | " + " | ".join(cells) + " |")
        lines.append("")
    margin = report.get("threshold_margin")
    if margin:
        lines += ["## 5. Margin around the calibrated thresholds", "",
                  "Share of perturbed copies of each attack's own signature (each feature moved by up to +/-30%) that the detector still classifies correctly. Low values mean the rule sits close to a boundary.", "",
                  "| Attack | Perturbed copies | Still correct |", "|---|---|---|"]
        for label, v in margin.items():
            if isinstance(v, dict) and "robust_rate" in v:
                lines.append(f"| {label} | {v['perturbations_tested']} | {_pct(v['robust_rate'])} |")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap-dir", default="data/evaluation/pcaps")
    parser.add_argument("--flow-table", default="data/ml/controlled_flows_17class.csv")
    parser.add_argument("--harness", default="data/evaluation/results_measured.jsonl")
    parser.add_argument("--robustness", default="data/evaluation/detector_robustness.summary.json")
    parser.add_argument("--output-dir", default="data/evaluation")
    args = parser.parse_args()
    report = build_report(args.pcap_dir, args.flow_table, args.harness, args.robustness)
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "detection_report.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    (out / "detection_report.md").write_text(render_markdown(report), encoding="utf-8")
    print(render_markdown(report))


if __name__ == "__main__":
    main()
