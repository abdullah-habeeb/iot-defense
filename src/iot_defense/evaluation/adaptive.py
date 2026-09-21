"""Adaptive-attacker evaluation: does per-source blocking actually stop a
persistent attacker, or only the one source it happened to catch?

Every other evaluation in this project (harness.py, generate_dataset.py,
the live demo) treats one attack attempt as one independent event: detect,
decide, respond, done. That is the right model for measuring detection and
response-execution correctness, but it cannot answer a different, real
question -- when the deployed policy's own registered response is
per-source (BLOCK_SOURCE, the preferred_action for both brute_force and
replay_attack), does a *repeat* attacker actually get contained across
multiple attempts, or does each new source IP simply start over unblocked?

This module runs one real, multi-round campaign against a single, persistent
Mininet network: replay_attack's own registered traffic generator for round
0 (a real, unspoofed attempt), then simulation/traffic.py's existing
distributed-spoofing generator (built for item 6, reused here rather than
duplicated) for every later round, each time with exactly one source IP so
every round is a clean single-source event. Two modes:

- "fixed": every round reuses the *same* source IP. This is the control --
  it should show the block taking effect after round 0 and holding for
  every later round (near-zero packets captured, since the block operates
  at the network layer before traffic ever reaches the sensor).
- "rotate": every round uses a source IP not yet blocked in this campaign.
  This is the actual adaptive-attacker test -- it measures whether the
  system's current, real architecture (each detection event evaluated and
  responded to independently, no cross-event attacker identity beyond raw
  source IP) lets a rotating attacker get through every single round.

Deliberately does NOT call MininetResponseExecutor.restore() between
rounds (unlike _execute_and_verify(), which restores after every step by
design, so RealMininetDefenseEnv's synthetic/real-Mininet training loop
always starts the next step clean) -- restoring here would erase exactly
the cross-round containment state this module exists to measure. Cleanup
runs once, at the end of the whole campaign.

Requires root (creates and drives a real Mininet network, same as every
other real-Mininet entry point in this project).
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Literal

from iot_defense.attacks.registry import ATTACK_SCENARIOS
from iot_defense.defense.context import build_security_context
from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.policy import StackelbergDefensePolicy
from iot_defense.defense.ppo_real_env import ATTACKER_IP, TARGET_IP, RealMininetDefenseEnv
from iot_defense.simulation.traffic import TrafficGenerator

_ATTACK_KEY = "replay_attack"
_SOURCE_POOL: tuple[str, ...] = (ATTACKER_IP, "10.0.0.121", "10.0.0.122", "10.0.0.123", "10.0.0.124", "10.0.0.125")

Mode = Literal["fixed", "rotate"]


def _traffic_for_source(source_ip: str):
    """A zero-arg-net traffic generator bound to one source IP.

    Round 0 (source_ip == ATTACKER_IP, the attacker host's own real
    address) reuses replay_attack's real, unspoofed registered generator --
    a genuinely different attempt should look exactly like the live demo's
    own replay_attack traffic, not a degenerate one-source case of the
    spoofing path. Every later round reuses generate_replay_attack_
    distributed_mininet_traffic (built for item 6) with a single-element
    spoofed_source_ips tuple, so every packet in that round carries the
    same chosen source -- the existing generator already treats a 1-tuple
    as "always this source", so no new traffic-generation code is needed.
    """
    if source_ip == ATTACKER_IP:
        return ATTACK_SCENARIOS[_ATTACK_KEY].generate_traffic
    generator = TrafficGenerator()
    return lambda net: generator.generate_replay_attack_distributed_mininet_traffic(
        net, duration_seconds=20, spoofed_source_ips=(source_ip,)
    )


def run_round(
    env: RealMininetDefenseEnv,
    round_num: int,
    source_ip: str,
    policy: StackelbergDefensePolicy,
    already_blocked: bool = False,
) -> dict[str, Any]:
    """One real round: generate this round's traffic from source_ip,
    capture and classify it, decide with the actually-deployed policy, and
    -- if the decision is BLOCK_SOURCE -- execute it for real without
    restoring afterward, so the block persists into later rounds.

    already_blocked tells this round whether source_ip was already
    blocked *before* it ran. That distinction matters for reading a
    zero-packet capture: for an already-blocked source it is the real,
    expected signal that containment is holding. For a source not yet
    blocked, a genuinely empty capture is ambiguous -- it could mean the
    attacker's traffic never reached the sensor for an unrelated reason
    (this project's own documented Mininet/tcpdump timing flakiness under
    real, repeated capture cycling; see monitor.py's read_capture retry
    and generate_dataset.py's own tolerance for the same failure mode),
    not that the source was somehow blocked. Rather than silently record
    that ambiguity as "not detected" -- which would misreport measurement
    noise as an evasion or containment finding -- this retries exactly
    once, mirroring read_capture()'s own established one-retry pattern
    for this exact failure class, and marks the row `capture_reliable`
    so a genuinely still-empty second attempt is visible, not hidden.
    """
    threat_event = env._observe_scenario("credential_replay", traffic_override=_traffic_for_source(source_ip))
    capture_reliable = True
    if not already_blocked and not threat_event.features.get("packet_count"):
        threat_event = env._observe_scenario("credential_replay", traffic_override=_traffic_for_source(source_ip))
        capture_reliable = bool(threat_event.features.get("packet_count"))

    context = build_security_context(threat_event, device_criticality="high")
    decision = policy.decide(context)

    execution_ok = False
    outcome: dict[str, Any] = {"status": "not_executed"}
    if decision.action != DefenseAction.ALLOW:
        real_decision = DefenseDecision.create(
            action=decision.action,
            target_ip=threat_event.destination_ip if threat_event.destination_ip != "unknown" else TARGET_IP,
            source_ip=source_ip,
            reason="adaptive-attacker evaluation round",
            confidence=threat_event.confidence,
            threat_score=threat_event.threat_score,
            policy_name="StackelbergDefensePolicy",
            context={},
        )
        result = env.executor.execute(real_decision)
        outcome = {"status": result.status, "details": result.details}
        execution_ok = result.status == "success"

    return {
        "round": round_num,
        "source_ip": source_ip,
        "already_blocked_before_round": already_blocked,
        "capture_reliable": capture_reliable,
        "packets_captured": threat_event.features.get("packet_count"),
        "detected_attack_type": threat_event.attack_type,
        "detected": threat_event.attack_type == "credential_replay",
        "action": decision.action.value,
        "matches_preferred_action": decision.action == ATTACK_SCENARIOS[_ATTACK_KEY].preferred_action,
        "execution_ok": execution_ok,
        "outcome": outcome,
    }


def run_campaign(env: RealMininetDefenseEnv, rounds: int, mode: Mode) -> list[dict[str, Any]]:
    policy = StackelbergDefensePolicy()
    blocked_sources: set[str] = set()
    rows: list[dict[str, Any]] = []
    for round_num in range(rounds):
        if mode == "fixed":
            source_ip = _SOURCE_POOL[0]
        else:
            remaining = [ip for ip in _SOURCE_POOL if ip not in blocked_sources]
            source_ip = remaining[0] if remaining else _SOURCE_POOL[round_num % len(_SOURCE_POOL)]
        row = run_round(env, round_num, source_ip, policy, already_blocked=source_ip in blocked_sources)
        row["mode"] = mode
        if row["execution_ok"] and row["action"] == DefenseAction.BLOCK_SOURCE.value:
            blocked_sources.add(source_ip)
        row["cumulative_blocked_sources"] = sorted(blocked_sources)
        rows.append(row)
        print(
            f"[adaptive:{mode}] round={round_num} source={source_ip} "
            f"detected={row['detected']} action={row['action']} blocked={sorted(blocked_sources)}",
            flush=True,
        )
    return rows


def run_evaluation(
    *, rounds: int = 5, modes: tuple[Mode, ...] = ("fixed", "rotate"), output_path: str | Path = "data/evaluation/adaptive_results.jsonl"
) -> dict[str, Any]:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()  # monotonic: immune to wall-clock jumps (VM suspend/NTP resync), unlike time.time()
    all_rows: list[dict[str, Any]] = []
    for mode in modes:
        env = RealMininetDefenseEnv()
        env._ensure_network()
        try:
            all_rows.extend(run_campaign(env, rounds, mode))
        finally:
            try:
                env.executor.restore(TARGET_IP)
            except Exception:  # noqa: BLE001
                pass
            env.close()

    with output.open("w", encoding="utf-8") as fh:
        for row in all_rows:
            fh.write(json.dumps(row) + "\n")

    summary = {
        "rounds": rounds,
        "modes": list(modes),
        "total_rounds_run": len(all_rows),
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "output_path": str(output),
        "per_mode": {
            mode: {
                "rounds_detected": sum(1 for r in all_rows if r["mode"] == mode and r["detected"]),
                "rounds_matching_preferred_action": sum(
                    1 for r in all_rows if r["mode"] == mode and r["matches_preferred_action"]
                ),
                "distinct_sources_blocked": len(
                    {s for r in all_rows if r["mode"] == mode for s in r["cumulative_blocked_sources"]}
                ),
            }
            for mode in modes
        },
    }
    output.with_suffix(".summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--modes", default="fixed,rotate")
    parser.add_argument("--output", default="data/evaluation/adaptive_results.jsonl")
    args = parser.parse_args()
    modes = tuple(args.modes.split(","))
    summary = run_evaluation(rounds=args.rounds, modes=modes, output_path=args.output)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
