"""Drive the whole live defender over recorded attacks and check what it finally decides.

For each saved lab capture the real LiveDefender (detection window, policy pipeline, response executor) is run on
the packets' own clock against a recording firewall: nothing touches a network. For every decision it makes we keep
the name it gave the attack and the response it chose, and score the response against the measured outcome table
among the responses the live defender can actually apply.

Two configurations are compared:

  * before: only traffic arriving at the host, last 5 s, never decides twice about a source.
  * after:  traffic in both directions, last 60 s, decides again when the attack's name changes and stays changed.

    python -m iot_defense.evaluation.defender_replay --per-class 5
"""

from __future__ import annotations

import argparse
import json
import statistics
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.pipeline import PolicyPipeline
from iot_defense.evaluation.detection_report import ATTACKER_IP, LAB_SUBNET, PCAP_NAME, SENSOR_IP
from iot_defense.evaluation.outcome import OutcomeTable
from iot_defense.evaluation.pcap_replay import protected_from_subnet, read_events
from iot_defense.live.backend import SUPPORTED_ACTIONS, IptablesBackend
from iot_defense.live.defender import LiveDefender, LiveState, replay_events
from iot_defense.live.window import WindowedDetector

CONFIGS = (
    ("before", {"directions": "inbound", "window_seconds": 5.0, "relabel": False}),
    ("after", {"directions": "both", "window_seconds": 60.0, "relabel": True}),
)


class RecordingRunner:
    """A firewall that accepts every command and remembers them."""

    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def __call__(self, args: list[str]) -> tuple[int, str]:
        self.commands.append(args)
        return 0, ""


def run_capture(path: Path, policy: str, config: dict[str, Any], scratch: Path) -> dict[str, Any] | None:
    events = read_events(path, SENSOR_IP)
    protected = sorted(ip for ip in protected_from_subnet(events, LAB_SUBNET) if ip != ATTACKER_IP)
    if not protected or not events:
        return None
    clock = [0.0]
    runner = RecordingRunner()
    backend = IptablesBackend("lab0", protected, allowlist=[], runner=runner, clock=lambda: clock[0], ttl_seconds=60,
                              evidence_dir=scratch / "evidence")
    backend.setup()
    live = {"mode": "replay", "iface": "lab0", "box_ip": protected[0], "static_allow": [], "supported_actions": [], "blocks": [],
            "trusted": [], "served_recent": 0, "dry_run": True, "kernel_expiry": True, "policy_mode": policy}
    state = LiveState(scratch / "state.json", live)
    pipeline = PolicyPipeline(policy, supported_actions=SUPPORTED_ACTIONS)
    window = WindowedDetector(protected, window_seconds=config["window_seconds"], directions=config["directions"])
    defender = LiveDefender(box_ip=protected[0], backend=backend, pipeline=pipeline, state=state, window=window,
                            relabel=config["relabel"])
    first = min(float(e["timestamp"]) for e in events)
    decisions: list[dict[str, Any]] = []
    decide = pipeline.decide

    def recording_decide(context: Any) -> Any:
        evaluation = decide(context)
        decisions.append({"at": round(defender.clock() - first, 2), "label": context.beliefs.threat_type, "action": evaluation.selected.action.value})
        return evaluation

    pipeline.decide = recording_decide  # type: ignore[method-assign]
    replay_events(defender, events, tail=config["window_seconds"])
    return {"decisions": decisions}


EPISODE_SECONDS = 60.0  # one block's lifetime: after it lapses an attacker still sending is a new episode, blocked afresh


def score(table: OutcomeTable, truth: str, decisions: list[dict[str, Any]]) -> dict[str, Any]:
    """How the decisions of the first episode compare with the best response the defender could have applied for the
    true attack. Decisions after the first block has expired are a second episode, counted but not scored: by then an
    attack that has been going on for a minute is judged on a window that has moved past its beginning."""
    if not decisions:
        return {"decided": False}
    total = len(decisions)
    decisions = [d for d in decisions if d["at"] - decisions[0]["at"] < EPISODE_SECONDS]
    live_actions = sorted(SUPPORTED_ACTIONS, key=lambda a: a.value)
    best = max(live_actions, key=lambda a: table.mean(truth, a))
    best_value = table.mean(truth, best)
    first, final = decisions[0], decisions[-1]
    value = lambda d: table.mean(truth, DefenseAction(d["action"]))
    right = [d for d in decisions if d["label"] == truth]
    return {
        "decided": True,
        "decisions": len(decisions),
        "later_episode_decisions": total - len(decisions),
        "first_label": first["label"],
        "first_label_right": first["label"] == truth,
        "final_label": final["label"],
        "final_label_right": final["label"] == truth,
        "first_regret": best_value - value(first),
        "final_regret": best_value - value(final),
        "first_time": first["at"],
        "final_time": final["at"],
        "time_to_right_label": right[0]["at"] if right else None,
        "best_live_action": best.value,
        "final_action": final["action"],
    }


def evaluate(pcap_dir: str | Path, table_path: str | Path, policy: str, per_class: int | None) -> dict[str, Any]:
    table = OutcomeTable.from_jsonl(table_path)
    by_class: dict[str, list[Path]] = defaultdict(list)
    for path in sorted(Path(pcap_dir).glob("*.pcap")):
        match = PCAP_NAME.search(path.name)
        if match and (per_class is None or len(by_class[match.group(2)]) < per_class):
            by_class[match.group(2)].append(path)
    # Load the policies once, before timing anything, as the live defender does at start-up.
    with tempfile.TemporaryDirectory() as warm:
        PolicyPipeline(policy, supported_actions=SUPPORTED_ACTIONS)
    result: dict[str, Any] = {"policy": policy, "configs": {}}
    for name, config in CONFIGS:
        classes: dict[str, Any] = {}
        for truth, paths in sorted(by_class.items()):
            scored, silent, false_alarms, example = [], 0, 0, None
            for path in paths:
                with tempfile.TemporaryDirectory() as scratch:
                    try:
                        outcome = run_capture(path, policy, config, Path(scratch))
                    except Exception:  # noqa: BLE001 - an empty capture carries no information
                        continue
                if outcome is None:
                    continue
                if truth == "normal":
                    false_alarms += bool(outcome["decisions"])
                    continue
                s = score(table, truth, outcome["decisions"])
                if s["decided"]:
                    scored.append(s)
                    example = example or outcome["decisions"]
                else:
                    silent += 1
            if truth == "normal":
                classes[truth] = {"captures": len(paths), "false_alarms": false_alarms}
                continue
            n = len(scored) + silent
            classes[truth] = {
                "captures": n,
                "decided": len(scored),
                "first_label_right": sum(s["first_label_right"] for s in scored),
                "final_label_right": sum(s["final_label_right"] for s in scored),
                "mean_first_regret": statistics.mean(s["first_regret"] for s in scored) if scored else None,
                "mean_final_regret": statistics.mean(s["final_regret"] for s in scored) if scored else None,
                "median_first_time": statistics.median(s["first_time"] for s in scored) if scored else None,
                "median_final_time": statistics.median(s["final_time"] for s in scored) if scored else None,
                "best_live_action": scored[0]["best_live_action"] if scored else None,
                "final_actions": sorted({s["final_action"] for s in scored}),
                "example_decisions": example,
            }
        result["configs"][name] = {"settings": config, "classes": classes}
    return result


def _fmt(v: float | None, spec: str = ".2f") -> str:
    return "-" if v is None else format(v, spec)


def render_markdown(result: dict[str, Any]) -> str:
    names = list(result["configs"])
    lines = ["# The whole live defender, replayed on saved lab attacks", "",
             f"Policy: {result['policy']}. Each capture drives the real defender (detection, policy pipeline, response executor) against a recording firewall. "
             "Regret is how far the response chosen falls below the best response *the live defender can apply* for the true attack, "
             "by the measured outcome table (0 = the best available). 'First' is the response decided at the first confirmed alarm; 'final' is the last one decided "
             "within one block lifetime (60 s) of it.", ""]
    for name in names:
        cfg = result["configs"][name]["settings"]
        lines.append(f"- **{name}**: {cfg['directions']} traffic, last {cfg['window_seconds']:.0f} s, "
                     f"{'decides again when the name changes' if cfg['relabel'] else 'decides once per source'}.")
    lines += ["", "| Attack | Captures | " + " | ".join(f"{n}: acted / name right at first / name right at last / regret first -> final / seconds to final" for n in names) + " |",
              "|---|---|" + "---|" * len(names)]
    classes = sorted({c for n in names for c in result["configs"][n]["classes"]})
    for c in classes:
        cells, caps = [], 0
        for n in names:
            r = result["configs"][n]["classes"].get(c)
            if r is None:
                cells.append("-")
                continue
            caps = r["captures"]
            if c == "normal":
                cells.append(f"false alarms {r['false_alarms']}/{r['captures']}")
            else:
                cells.append(f"{r['decided']} / {r['first_label_right']} / {r['final_label_right']} / {_fmt(r['mean_first_regret'])} -> {_fmt(r['mean_final_regret'])} / {_fmt(r['median_final_time'], '.0f')}")
        lines.append(f"| {c} | {caps} | " + " | ".join(cells) + " |")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap-dir", default="data/evaluation/pcaps")
    parser.add_argument("--table", default="data/outcomes/outcome_table.jsonl")
    parser.add_argument("--policy", default="arbiter", choices=["arbiter", "stackelberg", "rule_based", "ppo"])
    parser.add_argument("--per-class", type=int, default=5)
    parser.add_argument("--output-dir", default="data/evaluation")
    args = parser.parse_args()
    result = evaluate(args.pcap_dir, args.table, args.policy, args.per_class)
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "defender_replay.json").write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    (out / "defender_replay.md").write_text(render_markdown(result), encoding="utf-8")
    print(render_markdown(result))


if __name__ == "__main__":
    main()
