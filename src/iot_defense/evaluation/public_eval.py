"""Score the detector on public IoT traffic it was never tuned on (the IoT-23 dataset).

IoT-23 (Stratosphere Laboratory, CTU Prague) is real IoT traffic: three benign captures of real devices and
malware captures of Raspberry Pis infected with botnets such as Mirai, each with a Zeek connection log whose rows
are labelled Benign or Malicious plus a detailed label (a port scan, a DDoS, C&C traffic, ...). This replays a
capture through the live defender's detection (evaluation/pcap_replay.py) and compares each alarm with what the
labelled connections were doing at that moment.

Questions it answers:
  * On benign traffic: how many false alarms per hour?
  * On malicious traffic: how much of the labelled malicious activity did the detector notice, and how often was
    an alarm raised when nothing labelled malicious was happening?
  * Where a detailed label has a plausible equivalent among our 20 attacks, did the alarm carry that name?

Nothing here was used to tune a threshold. The label mapping below is a judgement, stated so it can be argued with.

    python -m iot_defense.evaluation.public_eval --benign data/external/iot23/benign_echo.pcap ...
"""

from __future__ import annotations

import argparse
import bisect
import ipaddress
import json
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np

from iot_defense.evaluation.detection_report import wilson
from iot_defense.evaluation.pcap_replay import busiest_private_address, stream_replay

DOS_FAMILY = (
    "dos_flood", "tcp_syn_flood", "icmp_ping_flood", "slow_loris_exhaustion", "mqtt_message_flood",
    "dos_flood_distributed", "tcp_syn_flood_distributed", "icmp_ping_flood_distributed",
)
# IoT-23 detailed label -> the attack names of ours that describe it. A judgement, not ground truth: IoT-23 labels
# what the malware was doing in broad strokes and none of our 20 attacks was built from it.
LABEL_MAP: dict[str, tuple[str, ...]] = {
    "PartOfAHorizontalPortScan": ("reconnaissance_port_scan",),
    "DDoS": DOS_FAMILY,
    "C&C": ("c2_beaconing", "rogue_config_beacon"),
    "C&C-HeartBeat": ("c2_beaconing", "rogue_config_beacon"),
    "C&C-HeartBeat-Attack": ("c2_beaconing", "rogue_config_beacon"),
    "C&C-Mirai": ("c2_beaconing", "rogue_config_beacon"),
    "C&C-Torii": ("c2_beaconing", "rogue_config_beacon"),
    "C&C-FileDownload": ("firmware_tampering", "rogue_config_beacon", "data_exfiltration"),
    "C&C-HeartBeat-FileDownload": ("firmware_tampering", "rogue_config_beacon", "data_exfiltration"),
    "C&C-PartOfAHorizontalPortScan": ("reconnaissance_port_scan", "c2_beaconing"),
    "FileDownload": ("firmware_tampering", "exploit_payload_injection"),
    "Attack": ("brute_force", "exploit_payload_injection", "credential_replay", "buffer_overflow_probe"),
}


def read_conn_labels(path: str | Path) -> list[dict[str, Any]]:
    """The rows of a Zeek conn.log.labeled: start, end, endpoints, label and detailed label."""
    rows: list[dict[str, Any]] = []
    fields: list[str] = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#") or not line.strip() or not fields:
            continue
        cells = line.split("\t")
        values = dict(zip(fields, cells))
        try:
            start = float(values["ts"])
        except (KeyError, ValueError):
            continue
        duration = values.get("duration", "-")
        end = start + (float(duration) if duration not in ("-", "") else 0.0)
        label = values.get("label")
        detail = values.get("det_label", values.get("detailed-label"))
        if label is None:
            # Many IoT-23 logs end with one cell holding "tunnel_parents   label   detailed-label", the three
            # joined by runs of spaces (the header does the same), so the last cell is split on those.
            parts = re.split(r"\s{2,}", cells[-1].strip())
            label = parts[1] if len(parts) >= 2 else "-"
            detail = parts[2] if len(parts) >= 3 else "-"
        rows.append({
            "start": start, "end": end, "orig": values.get("id.orig_h", ""), "resp": values.get("id.resp_h", ""),
            "label": label, "detail": detail or "-",
        })
    return rows


def busiest_in_conns(rows: list[dict[str, Any]]) -> str | None:
    counts: Counter[str] = Counter()
    for r in rows:
        for key in ("orig", "resp"):
            try:
                if ipaddress.ip_address(r[key]).is_private:
                    counts[r[key]] += 1
            except ValueError:
                continue
    return counts.most_common(1)[0][0] if counts else None


def evaluate_malicious(pcap: str | Path, conn_log: str | Path, *, protected: str | None = None, window_seconds: float = 60.0,
                       directions: str = "both", max_seconds: float | None = None, match_window: float = 60.0) -> dict[str, Any]:
    """Replay one capture and score the alarms against the labelled connections of the protected device.

    `window_seconds` is the detector's own window. `match_window` is how far an alarm may lag a malicious connection
    and still count for it, and how far back a malicious connection may reach and still justify an alarm. It is a
    property of the scoring, not of the detector, so every configuration is scored with the same value."""
    conns = read_conn_labels(conn_log)
    device = protected or busiest_in_conns(conns) or busiest_private_address(pcap)
    began = time.perf_counter()
    result = stream_replay(pcap, {device}, window_seconds=window_seconds, directions=directions, max_seconds=max_seconds, full=True)
    start = float(result["start_epoch"])
    end = start + float(result["duration_seconds"])
    mine = [r for r in conns if device in (r["orig"], r["resp"]) and r["end"] >= start and r["start"] <= end + match_window]
    malicious = [r for r in mine if r["label"].lower() == "malicious"]
    starts = np.array([r["start"] for r in malicious]) if malicious else np.array([])
    ends = np.array([r["end"] for r in malicious]) if malicious else np.array([])

    def active(t0: float, t1: float) -> np.ndarray:
        if not len(starts):
            return np.zeros(0, dtype=bool)
        return (starts <= t1) & (ends >= t0)

    alarm_times = [a["at"] for a in result["all_alarms"]]
    justified = 0
    agree = unmapped = disagree = 0
    for a in result["all_alarms"]:
        mask = active(a["at"] - match_window, a["at"])
        if mask.any():
            justified += 1
            wanted: set[str] = set()
            for r in (malicious[i] for i in np.nonzero(mask)[0]):
                wanted.update(LABEL_MAP.get(r["detail"], ()))
            if not wanted:
                unmapped += 1
            elif a["attack_type"] in wanted:
                agree += 1
            else:
                disagree += 1
    false_alarms = len(alarm_times) - justified

    # recall by second: a malicious second counts as noticed if any alarm fired within the window after it
    sorted_alarms = sorted(alarm_times)
    noticed = total = 0
    by_detail: dict[str, list[int]] = {}
    seconds = {}
    for r in malicious:
        for s in range(int(max(r["start"], start)), int(min(r["end"], end)) + 1):
            seconds.setdefault(s, set()).add(r["detail"])
    for s, details in seconds.items():
        i = bisect.bisect_left(sorted_alarms, s)
        hit = i < len(sorted_alarms) and sorted_alarms[i] <= s + match_window
        total += 1
        noticed += int(hit)
        for d in details:
            tally = by_detail.setdefault(d, [0, 0])
            tally[1] += 1
            tally[0] += int(hit)
    # recall by connection: did an alarm fire within the window after the malicious connection BEGAN? Counting
    # the seconds a connection stays open instead lets one connection that lasts for hours dominate the result.
    started = noticed_conn = 0
    named_total = named_hits = 0
    conn_by_detail: dict[str, list[int]] = {}
    ordered_alarms = sorted(result["all_alarms"], key=lambda a: a["at"])
    for r in malicious:
        if r["start"] < start or r["start"] > end:
            continue
        i = bisect.bisect_left(sorted_alarms, r["start"])
        hit = i < len(sorted_alarms) and sorted_alarms[i] <= r["start"] + match_window
        started += 1
        noticed_conn += int(hit)
        # named: some alarm in the same window carried a name that fits this connection's IoT-23 label
        plausible = LABEL_MAP.get(r["detail"], ())
        if plausible:
            named_total += 1
            j = i
            while j < len(ordered_alarms) and ordered_alarms[j]["at"] <= r["start"] + match_window:
                if ordered_alarms[j]["attack_type"] in plausible:
                    named_hits += 1
                    break
                j += 1
        tally = conn_by_detail.setdefault(r["detail"], [0, 0])
        tally[1] += 1
        tally[0] += int(hit)
    duration_hours = max(result["duration_seconds"], 1.0) / 3600.0
    return {
        "capture": Path(pcap).name,
        "protected": device,
        "packets": result["packets"],
        "duration_seconds": result["duration_seconds"],
        "labelled_connections": len(mine),
        "malicious_connections": len(malicious),
        "malicious_connections_in_capture": started,
        "malicious_connections_noticed": noticed_conn,
        "recall_by_connection": noticed_conn / started if started else None,
        "recall_by_connection_ci": wilson(noticed_conn, started) if started else None,
        "named_connections": named_total,
        "named_hits": named_hits,
        "recall_named_by_connection": named_hits / named_total if named_total else None,
        "recall_named_ci": wilson(named_hits, named_total) if named_total else None,
        "match_window": match_window,
        "actions": result["actions"],
        "actions_per_hour": result["actions_per_hour"],
        "alarm_list": [[round(a["at"] - start, 1), a["source_ip"], a["attack_type"]] for a in result["all_alarms"]],
        "connections_by_label": {d: {"connections": t, "noticed": n, "recall": n / t if t else None} for d, (n, t) in sorted(conn_by_detail.items())},
        "malicious_labels": dict(Counter(r["detail"] for r in malicious)),
        "flagged_checks": len(alarm_times),
        "justified_alarms": justified,
        "false_alarm_checks": false_alarms,
        "false_alarm_checks_per_hour": round(false_alarms / duration_hours, 2),
        "acted_on": len(result["all_acted_on"]),
        "malicious_seconds": total,
        "malicious_seconds_noticed": noticed,
        "recall_by_second": noticed / total if total else None,
        "recall_ci": wilson(noticed, total) if total else None,
        "recall_by_label": {d: {"seconds": t, "noticed": n, "recall": n / t if t else None} for d, (n, t) in sorted(by_detail.items())},
        "name_agrees": agree, "name_disagrees": disagree, "name_unmapped": unmapped,
        "alarm_names": dict(Counter(a["attack_type"] for a in result["all_alarms"])),
        "replay_seconds": round(time.perf_counter() - began, 1),
        "window_seconds": window_seconds,
        "directions": directions,
    }


def evaluate_benign(pcap: str | Path, *, protected: str | None = None, window_seconds: float = 60.0,
                    directions: str = "both", max_seconds: float | None = None, match_window: float = 60.0) -> dict[str, Any]:
    """Replay a capture of ordinary device traffic: every alarm is a false alarm."""
    device = protected or busiest_private_address(pcap)
    began = time.perf_counter()
    result = stream_replay(pcap, {device}, window_seconds=window_seconds, directions=directions, max_seconds=max_seconds, full=True)
    hours = max(result["duration_seconds"], 1.0) / 3600.0
    return {
        "capture": Path(pcap).name,
        "protected": device,
        "packets": result["packets"],
        "duration_seconds": result["duration_seconds"],
        "duration_hours": round(hours, 2),
        "flagged_checks": result["flagged_checks"],
        "flagged_checks_per_hour": round(result["flagged_checks"] / hours, 2),
        "acted_on": len(result["acted_on"]),
        "acted_on_per_hour": round(len(result["acted_on"]) / hours, 3),
        "acted_on_by_attack": result["acted_on_by_attack"],
        "actions": result["actions"],
        "actions_per_hour": round(result["actions"] / hours, 3),
        "actions_by_attack": dict(Counter(r["attack_type"] for r in result["all_actions"])),
        "alarm_names": dict(Counter(a["attack_type"] for a in result["all_alarms"])),
        "alarm_list": [[round(a["at"] - result["start_epoch"], 1), a["source_ip"], a["attack_type"]] for a in result["all_alarms"]],
        "replay_seconds": round(time.perf_counter() - began, 1),
        "window_seconds": window_seconds,
        "directions": directions,
    }


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def render_markdown(report: dict[str, Any]) -> str:
    lines = ["# Detector on public IoT traffic (IoT-23)", "",
             "Real IoT captures from the Stratosphere Laboratory's IoT-23 dataset, which the detector was never tuned on. "
             f"Detection used a {report['window_seconds']:.0f} s window over traffic in {report['directions']} directions. "
             "Every alarm on a benign capture is a false alarm. On malware captures an alarm is *justified* if a connection labelled "
             "Malicious overlapped the window, and a malicious second counts as *noticed* if an alarm fired within the window after it.", ""]
    if report["benign"]:
        lines += ["## Benign traffic: false alarms", "",
                  "| Capture | Device | Packets | Duration | Flagged checks | Per hour | Acted on (2 in a row) | Per hour | What it was called |", "|---|---|---|---|---|---|---|---|---|"]
        for b in report["benign"]:
            lines.append(f"| {b['capture']} | {b['protected']} | {b['packets']:,} | {b['duration_hours']} h | {b['flagged_checks']} | {b['flagged_checks_per_hour']} | "
                         f"{b['acted_on']} | {b['acted_on_per_hour']} | {', '.join(f'{k} x{v}' for k, v in b['alarm_names'].items()) or '-'} |")
        lines.append("")
    if report["malicious"]:
        lines += ["## Malware traffic: what it noticed", "",
                  "Noticed at start = an alarm fired within the window after a malicious connection began. Alarm precision = share of alarms raised while a malicious connection was open. "
                  "Seconds noticed counts every second a malicious connection stays open, so long-lived connections dominate it; treat it as secondary.", "",
                  "| Capture | Device | Packets | Malicious connections | Noticed at start | 95% CI | Alarms | Alarm precision | False-alarm checks per hour | Seconds noticed |", "|---|---|---|---|---|---|---|---|---|---|"]
        for m in report["malicious"]:
            ci = m["recall_by_connection_ci"]
            precision = m["justified_alarms"] / m["flagged_checks"] if m["flagged_checks"] else None
            lines.append(f"| {m['capture']} | {m['protected']} | {m['packets']:,} | {m['malicious_connections_in_capture']} | {_pct(m['recall_by_connection'])} | "
                         f"{'n/a' if not ci else f'[{ci[0]*100:.0f}-{ci[1]*100:.0f}%]'} | {m['flagged_checks']} | {_pct(precision)} | {m['false_alarm_checks_per_hour']} | {_pct(m['recall_by_second'])} |")
        lines += ["", "### By what the malware was doing (IoT-23's detailed label)", "",
                  "| Capture | Detailed label | Connections | Noticed at start | Plausible names of ours |", "|---|---|---|---|---|"]
        for m in report["malicious"]:
            for d, v in m["connections_by_label"].items():
                lines.append(f"| {m['capture']} | {d} | {v['connections']} | {_pct(v['recall'])} | {', '.join(LABEL_MAP.get(d, ())) or '(no equivalent)'} |")
        lines += ["", "### Did the alarm carry a plausible name?", "",
                  "| Capture | Named a plausible equivalent | Named something else | Label has no equivalent | Names raised |", "|---|---|---|---|---|"]
        for m in report["malicious"]:
            lines.append(f"| {m['capture']} | {m['name_agrees']} | {m['name_disagrees']} | {m['name_unmapped']} | {', '.join(f'{k} x{v}' for k, v in m['alarm_names'].items()) or '-'} |")
        lines.append("")
    lines += ["## Label mapping used", "", "| IoT-23 detailed label | Our names |", "|---|---|"]
    lines += [f"| {k} | {', '.join(v)} |" for k, v in LABEL_MAP.items()]
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benign", nargs="*", default=[], help="pcaps of ordinary device traffic")
    parser.add_argument("--malicious", nargs="*", default=[], help="pairs capture.pcap=conn.log.labeled")
    parser.add_argument("--window", type=float, default=60.0)
    parser.add_argument("--directions", choices=("inbound", "both"), default="both")
    parser.add_argument("--max-seconds", type=float, default=None)
    parser.add_argument("--match-window", type=float, default=60.0, help="seconds an alarm may lag a malicious connection and still count; the same for every configuration")
    parser.add_argument("--output-dir", default="data/evaluation")
    args = parser.parse_args()
    report: dict[str, Any] = {"window_seconds": args.window, "directions": args.directions, "benign": [], "malicious": []}
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    for path in args.benign:
        report["benign"].append(evaluate_benign(path, window_seconds=args.window, directions=args.directions, max_seconds=args.max_seconds, match_window=args.match_window))
        print("benign", report["benign"][-1]["capture"], report["benign"][-1]["flagged_checks"], flush=True)
    for pair in args.malicious:
        pcap, log = pair.split("=", 1)
        report["malicious"].append(evaluate_malicious(pcap, log, window_seconds=args.window, directions=args.directions, max_seconds=args.max_seconds, match_window=args.match_window))
        print("malicious", report["malicious"][-1]["capture"], report["malicious"][-1]["recall_by_second"], flush=True)
    (out / "public_eval.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    (out / "public_eval.md").write_text(render_markdown(report), encoding="utf-8")
    print(render_markdown(report))


if __name__ == "__main__":
    main()
