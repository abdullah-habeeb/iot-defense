"""Always-on defender for a real network interface.

Watches traffic addressed to this machine, runs the same detectors, policies
and arbiter as the lab, and applies the chosen response as a real firewall
rule. Everything it learns is published to the dashboard's state file, so the
same page that shows the lab shows this.

    sudo .venv/bin/python3 -m iot_defense.live.defender calibrate --iface enp0s8
    sudo .venv/bin/python3 -m iot_defense.live.defender run --iface enp0s8
    sudo .venv/bin/python3 -m iot_defense.live.defender restore --iface enp0s8
"""

from __future__ import annotations

import argparse
import json
import queue
import re
import signal
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from iot_defense.attacks.registry import ATTACK_SCENARIOS
from iot_defense.agents.decision_agent import DecisionAgent
from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.pipeline import PolicyPipeline
from iot_defense.defense.result import ResponseResult
from iot_defense.detection.threat_event import ThreatEvent
from iot_defense.live.backend import SUPPORTED_ACTIONS, IptablesBackend, UnsafeTargetError, run_command
from iot_defense.live.service import LegitService
from iot_defense.live.window import WindowedDetector, sustained_alarms

REPO_ROOT = Path(__file__).resolve().parents[3]
# Its own file: the simulation dashboard owns state.json (see dashboard/server.py).
STATE_PATH = REPO_ROOT / "data" / "dashboard" / "live_state.json"
ATTACK_KEY_BY_TYPE = {scenario.attack_type: key for key, scenario in ATTACK_SCENARIOS.items()}

POST_PHASE = {
    DefenseAction.BLOCK_SOURCE: "BLOCKED_SOURCE",
    DefenseAction.THROTTLE: "THROTTLED",
    DefenseAction.FORENSIC_CAPTURE: "FORENSICS_CAPTURED",
    DefenseAction.ALLOW: "OBSERVING",
    DefenseAction.ALERT: "OBSERVING",
}
NODE_STATUS = {
    DefenseAction.BLOCK_SOURCE: "SOURCE BLOCKED",
    DefenseAction.THROTTLE: "THROTTLED",
    DefenseAction.FORENSIC_CAPTURE: "MONITORED",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class LiveState:
    """Publishes the same state document the lab demo does, plus a `live` block."""

    def __init__(self, path: str | Path, live: dict[str, Any]) -> None:
        from iot_defense.demo.controller import _initial_state

        self.path = Path(path)
        self.state: dict[str, Any] = _initial_state()
        self.state["live"] = live
        self.state["phase"] = "OBSERVING"
        self.state["nodes"] = self._nodes(live)
        self._last_written = ""

    @staticmethod
    def _nodes(live: dict[str, Any]) -> dict[str, Any]:
        def node(ip: str, role: str, status: str) -> dict[str, Any]:
            return {"ip": ip, "role": role, "status": status}

        return {
            "sensor": node(live["box_ip"], "Protected box", "ONLINE"),
            "camera": node("trusted client", "Normal user (phone)", "OFFLINE"),
            "attacker": node("—", "Attacker", "OFFLINE"),
        }

    def set_nodes(self, statuses: dict[str, str], ips: dict[str, str] | None = None) -> dict[str, Any]:
        nodes = dict(self.state["nodes"])
        for name, status in statuses.items():
            if name in nodes:
                nodes[name] = {**nodes[name], "status": status}
        for name, ip in (ips or {}).items():
            if name in nodes:
                nodes[name] = {**nodes[name], "ip": ip}
        return nodes

    def update(self, data: dict[str, Any], message: str | None = None) -> None:
        self.state.update(data)
        self.state["timestamp"] = time.time()
        if message:
            self.state["timeline"].append({"timestamp": _now_iso(), "phase": self.state["phase"], "message": message})
        self.write()

    def write(self) -> None:
        text = json.dumps(self.state, default=str)
        if text == self._last_written:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(text, encoding="utf-8")
            tmp.replace(self.path)  # readers (the SSE poller) never see a half-written file
            self._last_written = text
        except OSError:
            pass


class LiveDefender:
    def __init__(
        self,
        *,
        box_ip: str,
        backend: IptablesBackend,
        pipeline: PolicyPipeline,
        state: LiveState,
        window: WindowedDetector,
        service: LegitService | None = None,
        clock: Callable[[], float] = time.time,
        confirm_ticks: int = 2,
    ) -> None:
        self.confirm_ticks = max(1, int(confirm_ticks))
        self._streak: dict[str, int] = {}
        self.box_ip = box_ip
        self.backend = backend
        self.pipeline = pipeline
        self.state = state
        self.window = window
        self.service = service
        self.clock = clock
        self.decision_agent = DecisionAgent()
        self.feed: deque[dict[str, Any]] = deque(maxlen=200)
        self.packets_seen = 0
        self._last_publish = 0.0
        self._attacker_ip: str | None = None
        self._cooldown: dict[str, float] = {}

    # ── the loop body ─────────────────────────────────────────────────────────
    def step(self, events: Iterable[dict[str, Any]], now: float) -> ThreatEvent | None:
        for event in events:
            if self.window.ingest(event):
                self.packets_seen += 1
                self.feed.append(event)

        if self.service is not None:
            for address in self.service.trusted_clients():
                self.backend.trust(address)

        released = self.backend.expire_due()
        if released:
            self._on_release(released)

        ignore = (
            self.backend.active_sources()
            | self.backend.allowlist
            | self.window.protected_ips
            | {source for source, until in self._cooldown.items() if until > now}
        )
        threat = self.window.evaluate(now, ignore)
        # Act only on a source flagged on consecutive checks: a one-off coincidence of
        # ordinary traffic does not trigger a firewall change. The window keeps a short
        # attack visible for several checks, so a real scan still qualifies.
        flagged = {threat.source_ip} if threat is not None else set()
        self._streak = {source: self._streak.get(source, 0) + 1 for source in flagged}
        acted = None
        if threat is not None and self._streak[threat.source_ip] >= self.confirm_ticks:
            self.respond(threat, now)
            self._streak.pop(threat.source_ip, None)
            acted = threat
        self.publish(now)
        return acted

    def respond(self, threat: ThreatEvent, now: float) -> None:
        key = ATTACK_KEY_BY_TYPE.get(threat.attack_type)
        label = ATTACK_SCENARIOS[key].label if key else threat.attack_type
        source = threat.source_ip
        self._attacker_ip = source
        first_seen = min(
            (float(e["timestamp"]) for e in self.window.window_events(now, {source})), default=now
        )
        detection_ms = max(0.0, (now - first_seen) * 1000)
        feed, hidden = self._feed()
        self.state.update(
            {
                "phase": "THREAT_DETECTED",
                "threat_status": "THREAT_DETECTED",
                "attack_mode": key,
                "threat_event": threat.to_dict(),
                "traffic": feed,
                "traffic_background": hidden,
                "nodes": self.state.set_nodes({"sensor": "ATTACKED", "attacker": "ATTACKED"}, {"attacker": source}),
                "metrics": {
                    **self.state.state["metrics"],
                    "packets_observed": self.packets_seen,
                    "detection_latency_ms": round(detection_ms, 1),
                },
            },
            message=f"{label} detected from {source} (threat score {threat.threat_score:.2f})",
        )

        context = self.decision_agent.build_context(threat, device_criticality="high")
        self.decision_agent.record(threat)
        evaluation = self.pipeline.decide(context)
        selected = evaluation.selected
        excluded = ", ".join(f"{name} proposed {action}" for name, action in evaluation.excluded.items())
        self.state.update(
            {
                "phase": "DECIDING",
                "security_context": context.to_dict(),
                "policy_comparison": evaluation.comparison,
                "selected_decision": selected.to_dict(),
            },
            message=(
                f"Policies evaluated. Selected ({selected.policy_name}): {selected.action.value}"
                + (f". Not available on this device: {excluded}" if excluded else "")
            ),
        )

        self.state.update({"phase": "RESPONDING"}, message=f"Applying {selected.action.value} to {source}")
        result = self.execute(selected, now)
        # Whatever was chosen, do not re-run the whole pipeline for this source every second
        # (an ALERT-only response never adds a block that would silence it).
        self._cooldown[source] = now + self.backend.ttl
        action = selected.action
        metrics = dict(self.state.state["metrics"])
        metrics["threats_detected"] = metrics.get("threats_detected", 0) + 1
        metrics["response_latency_ms"] = round(result.latency_ms, 1)
        if result.status == "success":
            if action == DefenseAction.BLOCK_SOURCE:
                metrics["blocks"] = metrics.get("blocks", 0) + 1
            elif action == DefenseAction.THROTTLE:
                metrics["throttles"] = metrics.get("throttles", 0) + 1
            elif action == DefenseAction.FORENSIC_CAPTURE:
                metrics["forensic_captures"] = metrics.get("forensic_captures", 0) + 1
        status_for_node = NODE_STATUS.get(action) if result.status == "success" else None
        self.state.update(
            {
                "phase": POST_PHASE.get(action, "OBSERVING") if result.status == "success" else "ERROR",
                "response_result": result.to_dict(),
                "metrics": metrics,
                "nodes": self.state.set_nodes({"sensor": status_for_node} if status_for_node else {}),
            },
            message=f"{action.value}: {result.message}",
        )

    def execute(self, decision: DefenseDecision, now: float) -> ResponseResult:
        started = _now_iso()
        began = time.perf_counter()
        action, source = decision.action, decision.source_ip
        try:
            if action == DefenseAction.ALLOW:
                details, message = {"operation": "none"}, "No network enforcement was necessary."
            elif action == DefenseAction.ALERT:
                details, message = {"operation": "log_only"}, "Security event recorded; the firewall was not changed."
            elif action == DefenseAction.BLOCK_SOURCE:
                details = self.backend.block_source(source)
                message = f"Traffic from {source} is dropped by a real firewall rule on this machine."
            elif action == DefenseAction.THROTTLE:
                details = self.backend.throttle(source)
                message = f"Traffic from {source} is rate-limited by a real firewall rule on this machine."
            elif action == DefenseAction.FORENSIC_CAPTURE:
                details = self.backend.save_evidence(source, self.window.window_events(now, {source}))
                message = "Evidence from the offending source was saved; the network was not changed."
            else:
                raise UnsafeTargetError(f"{action.value} is not available on this device")
            status = "success"
        except (UnsafeTargetError, RuntimeError, OSError) as exc:
            details, message, status = {"error": str(exc)}, f"{action.value} was not applied: {exc}", "failed"
        return ResponseResult.from_timing(
            action=action, target_ip=decision.target_ip, source_ip=source, status=status, started_at=started,
            latency_ms=(time.perf_counter() - began) * 1000, message=message, details=details,
        )

    def warm_up(self) -> float:
        """Run the whole policy pipeline once on a made-up port scan and discard the result.

        The first evaluation imports the RL library and loads the PPO model and the measured
        outcome table, which took about 13 s on the demo VM, long enough for a scan to finish
        before the response and for the protected page to stall. Doing it before any traffic is
        watched moves that cost to start-up. Uses its own history so the real log is untouched.
        Returns the seconds it took."""
        began = time.perf_counter()
        probe = ThreatEvent.from_result(
            source_ip="192.0.2.1", destination_ip=self.box_ip, attack_type="reconnaissance_port_scan",
            threat_score=0.9, confidence=0.88, detection_reason="start-up warm-up",
            features={"packets_per_second": 90.0, "unique_destination_ports": 300}, detector_name="warm-up",
        )
        self.pipeline.decide(DecisionAgent().build_context(probe, device_criticality="high"))
        return time.perf_counter() - began

    # ── reporting ─────────────────────────────────────────────────────────────
    def _feed(self) -> tuple[list[dict[str, Any]], int]:
        return list(self.feed)[-20:], 0

    def _on_release(self, released: list[str]) -> None:
        self.state.update(
            {
                "phase": "RESTORED",
                "threat_status": "NORMAL",
                "nodes": self.state.set_nodes({"sensor": "ONLINE", "attacker": "RESTORED"}),
                "metrics": {**self.state.state["metrics"], "restorations": self.state.state["metrics"].get("restorations", 0) + len(released)},
            },
            message=f"Block on {', '.join(released)} expired; traffic from it is allowed again unless it attacks again",
        )

    def publish(self, now: float, every: float = 1.0) -> None:
        if now - self._last_publish < every:
            return
        self._last_publish = now
        live = dict(self.state.state["live"])
        blocks = self.backend.snapshot()
        live["blocks"] = blocks
        live["trusted"] = sorted(self.backend.allowlist - set(live.get("static_allow", [])) - self.window.protected_ips)
        if self.service is not None:
            live["served_recent"] = self.service.served_since(10.0, exclude=self.backend.active_sources())
        live["packets_seen"] = self.packets_seen
        update: dict[str, Any] = {"live": live}
        if live["trusted"]:
            update["nodes"] = self.state.set_nodes({"camera": "ONLINE"}, {"camera": live["trusted"][0]})
        if self.state.state["phase"] in ("OBSERVING", "RESTORED") or blocks:
            update["traffic"] = list(self.feed)[-20:]
        self.state.update(update)


# ── environment helpers ───────────────────────────────────────────────────────
def interface_ip(iface: str, runner: Callable[[list[str]], tuple[int, str]] = run_command) -> str:
    code, out = runner(["ip", "-4", "-o", "addr", "show", "dev", iface])
    match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", out)
    if code != 0 or not match:
        raise SystemExit(f"could not find an IPv4 address on {iface!r}; is it connected (bridged adapter up)?")
    return match.group(1)


def default_gateway(iface: str, runner: Callable[[list[str]], tuple[int, str]] = run_command) -> str | None:
    _, out = runner(["ip", "-4", "route", "show", "default", "dev", iface])
    match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
    return match.group(1) if match else None


def start_sniffer(iface: str, box_ip: str, sink: "queue.SimpleQueue[dict[str, Any]]"):
    from scapy.all import AsyncSniffer

    from iot_defense.monitoring.monitor import packet_to_event

    def handle(packet: Any) -> None:
        event = packet_to_event(packet, box_ip)
        if event is not None:
            sink.put(event)

    sniffer = AsyncSniffer(iface=iface, filter=f"ip and dst host {box_ip}", store=False, prn=handle)
    sniffer.start()
    return sniffer


def replay_events(defender: LiveDefender, events: list[dict[str, Any]], step: float = 1.0) -> list[ThreatEvent]:
    """Drive the defender from recorded packets (a pcap or a calibration file) on
    the packets' own clock, so a capture can be rehearsed without a network."""
    ordered = sorted(events, key=lambda e: float(e["timestamp"]))
    threats: list[ThreatEvent] = []
    if not ordered:
        return threats
    clock = float(ordered[0]["timestamp"])
    end = float(ordered[-1]["timestamp"])
    cursor = 0
    fake = defender.backend.clock
    while clock <= end + step:
        batch = []
        while cursor < len(ordered) and float(ordered[cursor]["timestamp"]) <= clock:
            batch.append(ordered[cursor])
            cursor += 1
        defender.clock = defender.backend.clock = lambda c=clock: c
        threat = defender.step(batch, clock)
        if threat is not None:
            threats.append(threat)
        clock += step
    defender.backend.clock = fake
    return threats


# ── command line ──────────────────────────────────────────────────────────────
def _build(args: argparse.Namespace, *, dry_run: bool):
    box_ip = args.box_ip or interface_ip(args.iface)
    allow = set(args.allow or [])
    gateway = default_gateway(args.iface)
    if gateway:
        allow.add(gateway)
    runner = (lambda cmd: (print("[dry-run]", " ".join(cmd), flush=True) or 0, "")) if dry_run else None
    backend = IptablesBackend(args.iface, [box_ip], allowlist=allow, runner=runner, ttl_seconds=args.ttl)
    live = {
        "mode": "live", "iface": args.iface, "box_ip": box_ip, "static_allow": sorted(allow), "ttl_s": args.ttl,
        "supported_actions": sorted(a.value for a in SUPPORTED_ACTIONS), "policy_mode": args.policy,
        "blocks": [], "trusted": [], "served_recent": 0, "dry_run": dry_run, "kernel_expiry": False,
    }
    return box_ip, backend, live


def cmd_run(args: argparse.Namespace) -> int:
    box_ip, backend, live = _build(args, dry_run=args.dry_run)
    # Publish "starting" first: the policies take a while to load, and the dashboard should say so
    # rather than look as if nothing was started.
    state = LiveState(args.state, {**live, "warming": True, "service_port": args.port})
    state.update({"phase": "OBSERVING"}, message="Starting: loading the policies (slow the first time)")
    service = LegitService(port=args.port)
    defender = LiveDefender(
        box_ip=box_ip, backend=backend, pipeline=PolicyPipeline(args.policy, supported_actions=SUPPORTED_ACTIONS),
        state=state, window=WindowedDetector([box_ip], window_seconds=args.window), service=service,
    )
    print("[live] warming up the policies (loads the PPO model; slow the first time)...", flush=True)
    print(f"[live] warm-up took {defender.warm_up():.1f}s", flush=True)
    # Only now touch the network: hook the firewall chain, serve the page, start watching.
    backend.setup()
    port = service.start()
    state.state["live"].update({"kernel_expiry": backend.kernel_expiry, "warming": False, "service_port": port})
    state.update({}, message=f"Live defender watching {args.iface} ({box_ip}); page at http://{box_ip}:{port}")
    events: "queue.SimpleQueue[dict[str, Any]]" = queue.SimpleQueue()
    sniffer = start_sniffer(args.iface, box_ip, events)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    print(f"[live] protecting {box_ip} on {args.iface}; legit page http://{box_ip}:{port}; Ctrl+C to stop", flush=True)
    print(f"[live] never blocked: {sorted(backend.allowlist | {box_ip})}; blocks expire after {args.ttl:.0f}s; kernel expiry: {backend.kernel_expiry}", flush=True)
    try:
        while not stop.is_set():
            batch = []
            while True:
                try:
                    batch.append(events.get_nowait())
                except queue.Empty:
                    break
            defender.step(batch, time.time())
            stop.wait(1.0)
    finally:
        try:
            sniffer.stop()
        except Exception:  # noqa: BLE001
            pass
        service.stop()
        backend.teardown()
        state.update({"phase": "IDLE", "threat_status": "NORMAL"}, message="Live defender stopped; every firewall rule it added was removed")
        print("[live] stopped; firewall rules removed", flush=True)
    return 0


def cmd_calibrate(args: argparse.Namespace) -> int:
    box_ip = args.box_ip or interface_ip(args.iface)
    events: "queue.SimpleQueue[dict[str, Any]]" = queue.SimpleQueue()
    # Serve the page exactly as `run` does: the phone needs something to load, and its polling is the traffic to calibrate on.
    service = LegitService(port=args.port)
    port = service.start()
    sniffer = start_sniffer(args.iface, box_ip, events)
    print(f"[calibrate] recording {args.seconds}s of NORMAL traffic to {box_ip} on {args.iface}.", flush=True)
    print(f"[calibrate] NOW open http://{box_ip}:{port} on the phone and leave it open, as in the demo. No attack.", flush=True)
    recorded: list[dict[str, Any]] = []
    deadline = time.time() + args.seconds
    try:
        while time.time() < deadline:
            time.sleep(0.5)
            while True:
                try:
                    recorded.append(events.get_nowait())
                except queue.Empty:
                    break
    finally:
        sniffer.stop()
        trusted = service.trusted_clients()
        service.stop()
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(e, default=str) + "\n" for e in recorded), encoding="utf-8")
    probe = WindowedDetector([box_ip], window_seconds=args.window)
    alarms = probe.scan_for_false_alarms(recorded)
    sources = sorted({e["src_ip"] for e in recorded})
    print(f"[calibrate] {len(recorded)} packets from {len(sources)} sources: {sources}")
    print(f"[calibrate] devices that completed real requests to the page (trusted): {sorted(trusted) or 'none: did the phone open the page?'}")
    if not trusted:
        print("[calibrate] NO TRUSTED DEVICE: the phone never loaded the page, so this recording says nothing about it. Run again with the page open on the phone.")
        return 2
    # Judge alarms the way the defender acts on them: only runs of consecutive checks count, and a trusted device is never acted on.
    runs = sustained_alarms(alarms, args.confirm_ticks)
    ignored = [r for r in runs if r["source_ip"] in trusted]
    real = [r for r in runs if r["source_ip"] not in trusted]
    transient = len(alarms) - sum(r["checks"] for r in runs)
    print(f"[calibrate] {len(alarms)} flagged checks: {transient} one-off (never acted on), {len(ignored)} sustained from trusted devices (ignored), {len(real)} sustained from others.")
    if real:
        print(f"[calibrate] FALSE ALARM from an untrusted source (first: {real[0]}). Do not demo until this is explained.")
        return 1
    print("[calibrate] OK: nothing the defender would act on. Normal traffic is not mistaken for an attack.")
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    box_ip, backend, _ = _build(args, dry_run=False)
    backend.teardown()
    print(f"[restore] removed the {backend.iface} firewall hook and chain; nothing of ours remains")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--iface", required=True, help="the bridged (Wi-Fi side) interface to protect, e.g. enp0s8")
        p.add_argument("--box-ip", default=None, help="this machine's address on that interface (default: detected)")
        p.add_argument("--allow", nargs="*", default=[], help="addresses that must never be blocked (phone, teammate laptops)")
        p.add_argument("--window", type=float, default=5.0)
        p.add_argument("--ttl", type=float, default=60.0, help="seconds a block lasts")
        p.add_argument("--policy", default="arbiter", choices=["arbiter", "stackelberg", "rule_based", "ppo"])

    run_p = sub.add_parser("run", help="watch, decide and respond")
    common(run_p)
    run_p.add_argument("--port", type=int, default=8080)
    run_p.add_argument("--state", default=str(STATE_PATH))
    run_p.add_argument("--dry-run", action="store_true", help="print the firewall commands instead of running them")
    run_p.set_defaults(func=cmd_run)
    cal_p = sub.add_parser("calibrate", help="record normal traffic and confirm it raises no alarm")
    common(cal_p)
    cal_p.add_argument("--seconds", type=float, default=120.0)
    cal_p.add_argument("--port", type=int, default=8080, help="port of the page the phone opens (same as `run`)")
    cal_p.add_argument("--confirm-ticks", type=int, default=2, help="consecutive flagged checks the defender needs before acting")
    cal_p.add_argument("--output", default=str(REPO_ROOT / "data" / "live" / "calibration.jsonl"))
    cal_p.set_defaults(func=cmd_calibrate)
    res_p = sub.add_parser("restore", help="remove every firewall rule this tool added")
    common(res_p)
    res_p.set_defaults(func=cmd_restore)
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
