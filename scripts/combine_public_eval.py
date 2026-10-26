"""Run from the repository root after scripts/launch_public_eval.sh. Summarise the corrected public-data runs: like-for-like before/after, named recall, firewall actions."""
import json
from pathlib import Path

E = Path("data/evaluation")


def load(*dirs):
    out = {"benign": [], "malicious": []}
    for d in dirs:
        f = E / d / "public_eval.json"
        if f.exists():
            j = json.loads(f.read_text())
            out["benign"] += j.get("benign", [])
            out["malicious"] += j.get("malicious", [])
    return out


after = load("pub3_after_benign", "pub3_after_small", "pub3_after_large")
before = load("pub3_before_benign", "pub3_before_small", "pub3_before_large")
(E / "public_final.json").write_text(json.dumps({"before": before, "after": after}, default=str))


def pct(v):
    return "n/a" if v is None else f"{v * 100:.0f}%"


L = ["# IoT-23 results, corrected (one 60 s scoring window for both configurations)", "",
     "## Benign Amazon Echo (5.5 h)", "", "| Setting | Flagged s/h | Sustained alarms/h | Firewall actions (60 s block) | Actions/h | Called |", "|---|---|---|---|---|---|"]
for name, rep in (("original (5 s, inbound)", before), ("60 s, both", after)):
    for b in rep["benign"]:
        called = ", ".join(f"{k} x{v}" for k, v in sorted(b["actions_by_attack"].items(), key=lambda kv: -kv[1]))
        L.append(f"| {name} | {b['flagged_checks_per_hour']} | {b['acted_on_per_hour']} | {b['actions']} | {b['actions_per_hour']} | {called} |")
L += ["", "## Malware captures", "",
      "| Capture | Setting | Conn. | Noticed | Named | Alarms | Precision | Alarm-s/h with nothing malicious open | Actions |", "|---|---|---|---|---|---|---|---|---|"]
order = ["m03.pcap", "m34.pcap", "m08.pcap", "m20.pcap", "m21.pcap", "m42.pcap"]
for cap in order:
    for name, rep in (("original", before), ("60 s, both", after)):
        for m in rep["malicious"]:
            if m["capture"] != cap:
                continue
            prec = m["justified_alarms"] / m["flagged_checks"] if m["flagged_checks"] else None
            L.append(f"| {cap} | {name} | {m['malicious_connections_in_capture']} | {pct(m['recall_by_connection'])} | "
                     f"{pct(m['recall_named_by_connection'])} ({m['named_hits']}/{m['named_connections']}) | {m['flagged_checks']} | {pct(prec)} | {m['false_alarm_checks_per_hour']} | {m['actions']} |")
(E / "public_final.md").write_text("\n".join(L), encoding="utf-8")
print("\n".join(L))
