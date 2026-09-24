"""Stackelberg payoff-sensitivity ablation: does the SPECIFIC hand-tuned
payoff table matter, or would any reasonable table converge to the same
registry preferred_action? Perturbs every payoff value by random noise
across many trials and re-solves, measuring what fraction of
(trial, threat) pairs still match the registry -- a direct, cheap answer
to "is the structure of the problem doing the real work, or the precise
tuning," a real ablation this evaluation didn't have before.
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any

from iot_defense.attacks.registry import ATTACK_SCENARIOS
from iot_defense.defense.stackelberg import StackelbergGame, _load_game_config
from iot_defense.evaluation.report import _wilson_ci

# Perturbation magnitudes tested, as a fraction of each payoff's own
# absolute value (plus a small additive floor so a payoff of exactly
# 0.0 still gets perturbed) -- multiple magnitudes to characterize a
# real sensitivity curve, not just one arbitrary noise level.
NOISE_LEVELS: tuple[float, ...] = (0.05, 0.10, 0.20, 0.35, 0.50)
TRIALS_PER_NOISE_LEVEL = 30


def _perturb_payoffs(raw_payoffs: dict, noise_frac: float, rng: random.Random) -> dict:
    perturbed: dict[str, Any] = {}
    for threat, actions in raw_payoffs.items():
        perturbed[threat] = {}
        for action, responses in actions.items():
            perturbed[threat][action] = {}
            for response, values in responses.items():
                new_values = {}
                for perspective, value in values.items():
                    value = float(value)
                    magnitude = abs(value) * noise_frac + 0.05
                    new_values[perspective] = value + rng.uniform(-magnitude, magnitude)
                perturbed[threat][action][response] = new_values
    return perturbed


def run(seed: int = 7) -> list[dict[str, Any]]:
    raw_payoffs = _load_game_config().get("payoffs", {})
    rng = random.Random(seed)
    rows: list[dict[str, Any]] = []
    for noise_frac in NOISE_LEVELS:
        for trial in range(TRIALS_PER_NOISE_LEVEL):
            perturbed = _perturb_payoffs(raw_payoffs, noise_frac, rng)
            game = StackelbergGame(payoffs=perturbed)
            for key, scenario in ATTACK_SCENARIOS.items():
                solution = game.solve(scenario.observed_threat_key)
                rows.append({
                    "noise_frac": noise_frac,
                    "trial": trial,
                    "attack_key": key,
                    "matches_preferred_action": solution.selected_action == scenario.preferred_action,
                })
            normal_solution = game.solve("NORMAL")
            from iot_defense.defense.decision import DefenseAction
            rows.append({
                "noise_frac": noise_frac,
                "trial": trial,
                "attack_key": "normal",
                "matches_preferred_action": normal_solution.selected_action == DefenseAction.ALLOW,
            })
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_noise: dict[float, list[dict[str, Any]]] = {}
    for row in rows:
        by_noise.setdefault(row["noise_frac"], []).append(row)
    summary = {}
    for noise_frac, sub in by_noise.items():
        n = len(sub)
        matches = sum(1 for r in sub if r["matches_preferred_action"])
        summary[str(noise_frac)] = {
            "n": n,
            "match_rate": round(matches / n, 4) if n else None,
            "match_rate_ci95": _wilson_ci(matches, n),
        }
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="data/evaluation/stackelberg_sensitivity.jsonl")
    parser.add_argument("--summary-output", default="data/evaluation/stackelberg_sensitivity.summary.json")
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
