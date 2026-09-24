"""Detector robustness sweep: does each attack's own signature survive
realistic measurement variance, or does it only classify correctly at
the exact single point it was calibrated against?

This is a real, but PARTIAL, answer to a real validity concern: every
detector's numeric window was hand-placed to be clear of every other
detector's window for THIS system's own registered attacks (see
detector.py's own docstrings and the 432-combination sweep that found
c2_beacon's window). That is calibrating the test to the system under
test -- it says nothing about how the detectors would perform against
attack traffic this project didn't generate and tune against. This
module does NOT fix that (only an independent, external dataset would);
it answers the narrower, adjacent question of whether the calibration
is a brittle single point or has real margin -- perturbing each
attack's own real feature values by realistic percentages (matching the
scale of framing/measurement variance this project has already
documented directly, e.g. a 570-byte payload measuring
average_packet_size=612) and checking whether UnifiedRuleBasedDetector
still classifies it correctly, not just the individual detector in
isolation.
"""
from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path
from typing import Any

from iot_defense.attacks.registry import ATTACK_SCENARIOS
from iot_defense.detection.detector import UnifiedRuleBasedDetector

# Percentage perturbations applied independently to every numeric
# feature in a scenario's own real signature (ppo_example_features plus
# packet_count=200 baseline, matching test_attack_registry.py's own
# established construction). 0.0 is the exact calibrated point.
PERTURBATION_PCTS: tuple[float, ...] = (-0.3, -0.2, -0.1, 0.0, 0.1, 0.2, 0.3)

_NUMERIC_FIELDS = ("packet_count", "packets_per_second", "average_packet_size", "unique_destination_ports")

# Mirrors test_attack_registry.py's own DETECTION_FEATURE_OVERRIDES --
# duplicated deliberately rather than imported from a test module (this
# is a real evaluation artifact, not test-only code).
DETECTION_FEATURE_OVERRIDES: dict[str, dict[str, float]] = {
    "exfiltration": {"packet_count": 10, "average_packet_size": 1200.0},
    "exploit": {"packet_count": 4, "average_packet_size": 442.0},
    "syn_flood": {"protocol": "TCP", "tcp_syn_count": 15, "tcp_ack_count": 0},
    "icmp_flood": {"protocol": "ICMP", "icmp_packet_count": 30, "average_packet_size": 220.0},
    "slow_loris": {"protocol": "TCP", "unique_source_ports": 20, "tcp_ack_count": 20, "average_packet_size": 225.0},
    "dns_amplification": {"protocol": "UDP", "average_packet_size": 570.0},
    "dns_tunneling": {"protocol": "UDP", "average_packet_size": 220.0},
    "mqtt_flood": {"protocol": "TCP", "tcp_ack_count": 20, "average_packet_size": 80.0},
    "firmware_tampering": {"protocol": "UDP", "average_packet_size": 570.0},
    "buffer_overflow": {"protocol": "TCP", "average_packet_size": 675.6},
    "replay_attack": {"protocol": "UDP", "average_packet_size": 100.0},
    "rogue_beacon": {"protocol": "UDP", "average_packet_size": 220.0},
    "c2_beacon": {"protocol": "UDP", "average_packet_size": 380.0, "inter_arrival_cv": 0.05},
}


def _base_features(key: str, scenario) -> dict[str, Any]:
    return {
        "source_ip": "10.0.0.100",
        "destination_ip": "10.0.0.10",
        "packet_count": 200,
        **scenario.ppo_example_features,
        **DETECTION_FEATURE_OVERRIDES.get(key, {}),
    }


def run() -> list[dict[str, Any]]:
    detector = UnifiedRuleBasedDetector()
    rows: list[dict[str, Any]] = []
    for key, scenario in ATTACK_SCENARIOS.items():
        base = _base_features(key, scenario)
        present_fields = [f for f in _NUMERIC_FIELDS if f in base and isinstance(base[f], (int, float))]
        for combo in itertools.product(PERTURBATION_PCTS, repeat=len(present_fields)):
            features = dict(base)
            for field, pct in zip(present_fields, combo):
                features[field] = base[field] * (1 + pct)
                if field in ("packet_count", "unique_destination_ports"):
                    features[field] = max(0, round(features[field]))
            event = detector.detect(features)
            rows.append({
                "attack_key": key,
                "perturbation": dict(zip(present_fields, combo)),
                "correctly_classified": event.attack_type == scenario.attack_type,
                "actual_classification": event.attack_type,
            })
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_key: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_key.setdefault(row["attack_key"], []).append(row)
    summary = {}
    for key, sub in by_key.items():
        n = len(sub)
        correct = sum(1 for r in sub if r["correctly_classified"])
        exact_point = next(r for r in sub if all(v == 0.0 for v in r["perturbation"].values()))
        summary[key] = {
            "perturbations_tested": n,
            "robust_rate": round(correct / n, 4) if n else None,
            "calibrated_point_correct": exact_point["correctly_classified"],
        }
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="data/evaluation/detector_robustness.jsonl")
    parser.add_argument("--summary-output", default="data/evaluation/detector_robustness.summary.json")
    args = parser.parse_args()

    rows = run()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")

    summary = summarize(rows)
    Path(args.summary_output).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
