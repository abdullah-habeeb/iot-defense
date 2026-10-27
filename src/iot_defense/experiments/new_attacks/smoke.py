"""A blind-safe smoke test: does each new attack's traffic reach its receiver at all?

It applies NO response. It runs each attack twice with the ALLOW (do-nothing) probe, which reads the attack's un-responded packet
count and the legitimate-service ping loss. That tells the operator the generators work and that the baseline is large enough to
be a valid denominator (at least 3 packets), and it reveals nothing about how any response performs, so it can safely run before
the priors are frozen. It never calls any other action (a test enforces this), and every run is logged to smoke_log.jsonl.

    sudo .venv/bin/python3 -m iot_defense.experiments.new_attacks.smoke
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from iot_defense.defense.decision import DefenseAction
from iot_defense.evaluation.outcome import MIN_BASELINE_PACKETS
from iot_defense.experiments.new_attacks import common
from iot_defense.experiments.new_attacks.scenarios import NEW_ATTACK_KEYS, build_scenarios, registered

PROBES_PER_ATTACK = 2


def smoke_attack(env: Any, condition: str) -> dict[str, Any]:
    event = env._observe_scenario(condition)
    probes = []
    for _ in range(PROBES_PER_ATTACK):
        measurement, outcome = env.measure_response(DefenseAction.ALLOW, event, condition)
        probes.append(
            {"baseline_packets": measurement.residual_packets, "service_loss": measurement.service_loss,
             "probe_error": outcome.get("probe_error")}
        )
        time.sleep(1.0)
    return {
        "condition": condition,
        "captured_protocol": env.last_attack_protocol,
        "probes": probes,
        "baseline_ok": all(p["baseline_packets"] >= MIN_BASELINE_PACKETS and not p["probe_error"] and p["service_loss"] >= 0 for p in probes),
    }


def main() -> None:
    from iot_defense.defense.ppo_real_env import RealMininetDefenseEnv

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise SystemExit("Mininet needs root: sudo .venv/bin/python3 -m iot_defense.experiments.new_attacks.smoke")
    results = []
    with registered(build_scenarios()):
        env = RealMininetDefenseEnv()
        env._ensure_network()
        try:
            for condition in NEW_ATTACK_KEYS:
                results.append(smoke_attack(env, condition))
        finally:
            env.close()
    record = {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "blind_safe": True, "actions_applied": ["ALLOW"],
              "git_head": common.git("rev-parse", "HEAD"), "results": results}
    common.append_jsonl(common.SMOKE_LOG_PATH, record)
    print(json.dumps(record, indent=2))
    print("PASS: both attacks produce a usable baseline" if all(r["baseline_ok"] for r in results)
          else "FAIL: at least one attack's baseline is below 3 packets or a probe failed; fix the generator before the freeze")


if __name__ == "__main__":
    main()
