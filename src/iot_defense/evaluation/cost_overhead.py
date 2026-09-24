"""Decision-latency cost/overhead analysis: what does it actually cost,
in wall-clock time, to run all three policies against one security
context instead of just one? This evaluation's own harness reports
per-trial detection latency (dominated by real packet capture, seconds)
but never isolated the policy-comparison overhead itself -- this
measures that directly, in isolation, with repeated real calls to the
real policy classes (no Mininet, no mocking).
"""
from __future__ import annotations

import json
import statistics
import time
from pathlib import Path
from typing import Any

from iot_defense.attacks.registry import ATTACK_SCENARIOS
from iot_defense.defense.policy import RuleBasedDefensePolicy, StackelbergDefensePolicy
from iot_defense.defense.ppo_env import context_for_scenario
from iot_defense.defense.ppo_policy import PPODefensePolicy

REPEATS_PER_SCENARIO = 50


def _time_calls(fn, context, n: int) -> list[float]:
    timings = []
    for _ in range(n):
        start = time.perf_counter()
        fn(context)
        timings.append((time.perf_counter() - start) * 1000)
    return timings


def run() -> dict[str, Any]:
    rule_policy = RuleBasedDefensePolicy()
    stack_policy = StackelbergDefensePolicy()
    ppo_policy = PPODefensePolicy(model_path="models/ppo_defense", fallback=rule_policy)

    all_timings: dict[str, list[float]] = {"rule_based": [], "stackelberg": [], "ppo": []}
    scenarios = list(ATTACK_SCENARIOS.values())[:6]  # a representative subset is enough to characterize latency
    for scenario in scenarios:
        context = context_for_scenario(scenario.attack_type)
        all_timings["rule_based"].extend(_time_calls(rule_policy.decide, context, REPEATS_PER_SCENARIO))
        all_timings["stackelberg"].extend(_time_calls(stack_policy.decide, context, REPEATS_PER_SCENARIO))
        all_timings["ppo"].extend(_time_calls(ppo_policy.decide, context, REPEATS_PER_SCENARIO))

    def _stats(values: list[float]) -> dict[str, float]:
        sorted_values = sorted(values)
        p95_idx = int(len(sorted_values) * 0.95)
        return {
            "n": len(values),
            "mean_ms": round(statistics.mean(values), 4),
            "median_ms": round(statistics.median(values), 4),
            "p95_ms": round(sorted_values[min(p95_idx, len(sorted_values) - 1)], 4),
            "max_ms": round(max(values), 4),
        }

    per_policy = {name: _stats(values) for name, values in all_timings.items()}
    all_three_sequential_mean_ms = sum(s["mean_ms"] for s in per_policy.values())
    slowest_single_policy_mean_ms = max(s["mean_ms"] for s in per_policy.values())

    return {
        "per_policy": per_policy,
        "all_three_sequential_mean_ms": round(all_three_sequential_mean_ms, 4),
        "slowest_single_policy_mean_ms": round(slowest_single_policy_mean_ms, 4),
        "overhead_of_comparing_vs_deploying_one_ms": round(
            all_three_sequential_mean_ms - slowest_single_policy_mean_ms, 4
        ),
        "note": (
            "For scale: this project's own harness measured mean real "
            "detection latency (packet capture, not decision-making) at "
            "thousands of milliseconds per trial -- see EVALUATION.md. "
            "Policy decision cost is reported here to show it is not the "
            "bottleneck, not because it competes with capture time."
        ),
    }


def main() -> None:
    result = run()
    Path("data/evaluation").mkdir(parents=True, exist_ok=True)
    Path("data/evaluation/cost_overhead.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
