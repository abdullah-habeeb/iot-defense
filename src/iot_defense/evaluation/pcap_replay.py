"""Replay a recorded capture through the live defender's rolling-window detection.

The live defender (live/defender.py) watches a stream of packets and asks the detectors, every second, whether the
last stretch of traffic looks like an attack, acting only after two flagged checks in a row. This runs the same logic
over a pcap file, so a recording of any network can be asked two questions without sending a single packet:

  * on benign traffic: how often would the defender have raised a false alarm? (alarms per hour)
  * on an attack recording: how long until it acts, and what does it call the attack along the way?

Nothing here knows which attack to expect; it uses UnifiedRuleBasedDetector exactly as the defender does.

    python -m iot_defense.evaluation.pcap_replay capture.pcap --protected-subnet 192.168.1.0/24
    python -m iot_defense.evaluation.pcap_replay big.pcap --stream --auto-protect
"""

from __future__ import annotations

import argparse
import ipaddress
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Iterator

from scapy.all import PcapReader

from iot_defense.live.window import WindowedDetector, sustained_alarms
from iot_defense.monitoring.monitor import packet_to_event

MAX_REPORTED_ALARMS = 500
BLOCK_SECONDS = 60.0  # how long a response keeps a source blocked in the live defender


def dedupe_actions(runs: list[dict[str, Any]], confirm_ticks: int, step: float, block_seconds: float = BLOCK_SECONDS) -> list[dict[str, Any]]:
    """The sustained alarm runs the live defender would turn into firewall actions. It does not act again on a source
    whose block is still in force, so a run that confirms within `block_seconds` of the previous action on the same
    source is not a new action."""
    last: dict[str, float] = {}
    kept: list[dict[str, Any]] = []
    for run in sorted(runs, key=lambda r: r["start"]):
        at = run["start"] + (confirm_ticks - 1) * step
        if at < last.get(run["source_ip"], float("-inf")) + block_seconds:
            continue
        last[run["source_ip"]] = at
        kept.append(run)
    return kept


def read_events(path: str | Path, host_ip: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
    """The packets of a pcap as the event dicts the pipeline consumes. `limit` caps how many packets are read."""
    events: list[dict[str, Any]] = []
    reader = PcapReader(str(path))
    try:
        for index, packet in enumerate(reader):
            if limit is not None and index >= limit:
                break
            event = packet_to_event(packet, host_ip)
            if event is not None:
                events.append(event)
    finally:
        reader.close()
    return events


def light_event(packet: Any) -> dict[str, Any] | None:
    """An IPv4 packet reduced to the fields the feature aggregator reads. Much cheaper than packet_to_event
    (no display labels), which matters on captures of millions of packets; the detectors see the same numbers."""
    ip_layer = packet.getlayer("IP")
    if ip_layer is None:
        return None
    tcp = packet.getlayer("TCP")
    udp = packet.getlayer("UDP")
    layer4 = tcp or udp
    protocol = "TCP" if tcp is not None else "UDP" if udp is not None else "ICMP" if packet.haslayer("ICMP") else "UNKNOWN"
    return {
        "timestamp": float(packet.time),
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "protocol": protocol,
        "src_port": getattr(layer4, "sport", None),
        "dst_port": getattr(layer4, "dport", None),
        "packet_length": len(packet),
        "tcp_flags": int(tcp.flags) if tcp is not None else 0,
    }


def iter_light_events(path: str | Path, limit: int | None = None) -> Iterator[dict[str, Any]]:
    reader = PcapReader(str(path))
    try:
        for index, packet in enumerate(reader):
            if limit is not None and index >= limit:
                break
            event = light_event(packet)
            if event is not None:
                yield event
    finally:
        reader.close()


def protected_from_subnet(events: Iterable[dict[str, Any]], subnet: str) -> set[str]:
    """Every destination address in `subnet` that received traffic: the devices a defender there would protect."""
    network = ipaddress.ip_network(subnet, strict=False)
    found: set[str] = set()
    for event in events:
        try:
            if ipaddress.ip_address(str(event.get("dst_ip"))) in network:
                found.add(str(event["dst_ip"]))
        except ValueError:
            continue
    return found


def busiest_private_address(path: str | Path, sample_packets: int = 200_000) -> str | None:
    """The private address that sends or receives the most packets in the first part of a capture: in a recording
    of one device, that device."""
    counts: Counter[str] = Counter()
    for event in iter_light_events(path, limit=sample_packets):
        for key in ("src_ip", "dst_ip"):
            try:
                if ipaddress.ip_address(event[key]).is_private:
                    counts[event[key]] += 1
            except ValueError:
                continue
    return counts.most_common(1)[0][0] if counts else None


def _summarise(alarms: list[dict[str, Any]], *, first: float, last: float, packets: int, protected: set[str],
               window_seconds: float, confirm_ticks: int, step: float, directions: str, full: bool = False) -> dict[str, Any]:
    runs = sustained_alarms(alarms, confirm_ticks, step)
    duration = max(last - first, 0.0)
    summary: dict[str, Any] = {
        "packets": packets,
        "protected": sorted(protected),
        "window_seconds": window_seconds,
        "confirm_ticks": confirm_ticks,
        "directions": directions,
        "duration_seconds": round(duration, 3),
        "checks": int(duration / step) + 1,
        "flagged_checks": len(alarms),
        "alarms": [{"t": round(a["at"] - first, 2), "source_ip": a["source_ip"], "attack_type": a["attack_type"]} for a in alarms[:MAX_REPORTED_ALARMS]],
        "acted_on": runs,
        "acted_on_by_attack": dict(Counter(run["attack_type"] for run in runs)),
        "acted_on_per_hour": round(len(runs) / (duration / 3600.0), 3) if duration > 0 else 0.0,
        "first_action_delay_seconds": None,
        "start_epoch": first,
    }
    actions = dedupe_actions(runs, confirm_ticks, step)
    summary["actions"] = len(actions)
    summary["actions_per_hour"] = round(len(actions) / (duration / 3600.0), 3) if duration > 0 else 0.0
    if full:
        summary["all_alarms"] = [{"at": a["at"], "source_ip": a["source_ip"], "attack_type": a["attack_type"]} for a in alarms]
        summary["all_acted_on"] = runs
        summary["all_actions"] = actions
    if runs:
        earliest = min(run["start"] for run in runs)
        summary["first_action_delay_seconds"] = round(earliest + (confirm_ticks - 1) * step - first, 3)
    return summary


def replay(
    events: list[dict[str, Any]],
    protected_ips: Iterable[str],
    *,
    window_seconds: float = 5.0,
    confirm_ticks: int = 2,
    step: float = 1.0,
    directions: str = "inbound",
) -> dict[str, Any]:
    """What the live defender would have flagged, and acted on, over these events."""
    protected = set(protected_ips)
    if not events:
        return _summarise([], first=0.0, last=0.0, packets=0, protected=protected, window_seconds=window_seconds,
                          confirm_ticks=confirm_ticks, step=step, directions=directions)
    first = min(float(e["timestamp"]) for e in events)
    last = max(float(e["timestamp"]) for e in events)
    detector = WindowedDetector(protected, window_seconds=window_seconds, directions=directions)
    # The live defender keeps checking for as long as the last packets are still inside its window. A recording ends
    # when the capture stopped, so without this a short burst would be judged on one check only. The marker is
    # addressed to nobody, so the detector ignores it; it only extends the clock.
    marker = {"timestamp": last + window_seconds, "src_ip": "0.0.0.0", "dst_ip": "0.0.0.0"}
    alarms = detector.scan_for_false_alarms([*events, marker], step=step)
    return _summarise(alarms, first=first, last=last, packets=len(events), protected=protected,
                      window_seconds=window_seconds, confirm_ticks=confirm_ticks, step=step, directions=directions)


def stream_replay(
    path: str | Path,
    protected_ips: Iterable[str],
    *,
    window_seconds: float = 60.0,
    confirm_ticks: int = 2,
    step: float = 1.0,
    directions: str = "both",
    limit: int | None = None,
    max_seconds: float | None = None,
    full: bool = False,
) -> dict[str, Any]:
    """The same replay for captures too large to hold in memory: packets are read once, in order, and only the
    current window is kept. Quiet stretches are skipped (an empty window cannot raise an alarm)."""
    protected = set(protected_ips)
    detector = WindowedDetector(protected, window_seconds=window_seconds, directions=directions, max_events=200_000)
    alarms: list[dict[str, Any]] = []
    first = last = None
    clock = None
    packets = 0

    def check(at: float) -> None:
        threat = detector.evaluate(at)
        if threat is not None:
            alarms.append({"at": at, "source_ip": threat.source_ip, "attack_type": threat.attack_type})

    for event in iter_light_events(path, limit=limit):
        ts = float(event["timestamp"])
        if first is None:
            first = clock = ts
        if max_seconds is not None and ts - first > max_seconds:
            break
        while clock < ts:
            check(clock)
            clock += step
            if not detector.has_events():  # nothing in the window: jump to the next packet
                clock = ts
        detector.ingest(event)
        packets += 1
        last = ts
    if first is None:
        return _summarise([], first=0.0, last=0.0, packets=0, protected=protected, window_seconds=window_seconds,
                          confirm_ticks=confirm_ticks, step=step, directions=directions)
    for _ in range(int(window_seconds / step) + 2):  # let the last packets age out of the window
        check(clock)
        clock += step
    return _summarise(alarms, first=first, last=last, packets=packets, protected=protected,
                      window_seconds=window_seconds, confirm_ticks=confirm_ticks, step=step, directions=directions, full=full)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap")
    parser.add_argument("--protected", nargs="*", default=[], help="addresses of the devices being protected")
    parser.add_argument("--protected-subnet", help="protect every address in this subnet that received traffic")
    parser.add_argument("--auto-protect", action="store_true", help="protect the busiest private address (a one-device recording)")
    parser.add_argument("--stream", action="store_true", help="read the capture once without loading it into memory")
    parser.add_argument("--limit", type=int, default=None, help="read at most this many packets")
    parser.add_argument("--max-seconds", type=float, default=None, help="stop after this many seconds of capture")
    parser.add_argument("--window", type=float, default=None)
    parser.add_argument("--directions", choices=("inbound", "both"), default=None)
    parser.add_argument("--confirm-ticks", type=int, default=2)
    parser.add_argument("--json", action="store_true", help="print the full summary as JSON")
    args = parser.parse_args()
    protected = set(args.protected)
    if args.auto_protect:
        busiest = busiest_private_address(args.pcap)
        if busiest:
            protected.add(busiest)
    if args.stream:
        if args.protected_subnet:
            parser.error("--protected-subnet needs the whole capture in memory; use --auto-protect or --protected with --stream")
        if not protected:
            parser.error("name the devices to protect with --protected or --auto-protect")
        result = stream_replay(args.pcap, protected, window_seconds=args.window or 60.0, confirm_ticks=args.confirm_ticks,
                               directions=args.directions or "both", limit=args.limit, max_seconds=args.max_seconds)
    else:
        events = read_events(args.pcap, limit=args.limit)
        if args.protected_subnet:
            protected |= protected_from_subnet(events, args.protected_subnet)
        if not protected:
            parser.error("name the devices to protect with --protected, --protected-subnet or --auto-protect")
        result = replay(events, protected, window_seconds=args.window or 5.0, confirm_ticks=args.confirm_ticks,
                        directions=args.directions or "inbound")
    if args.json:
        print(json.dumps(result, indent=2))
        return
    hours = result["duration_seconds"] / 3600.0
    print(f"{result['packets']} packets over {result['duration_seconds']:.0f} s ({hours:.2f} h), protecting {', '.join(result['protected'])}")
    print(f"window {result['window_seconds']:.0f} s, {result['directions']} directions; flagged checks: {result['flagged_checks']} of {result['checks']}")
    print(f"alarms the defender would have acted on: {len(result['acted_on'])}  ({result['acted_on_per_hour']} per hour)")
    for attack, count in sorted(result["acted_on_by_attack"].items(), key=lambda kv: -kv[1]):
        print(f"  {attack}: {count}")
    if result["first_action_delay_seconds"] is not None:
        print(f"first action {result['first_action_delay_seconds']} s after the first packet")


if __name__ == "__main__":
    main()
