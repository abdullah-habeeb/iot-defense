"""Demo orchestration controller with full pipeline integration and SSE event bus."""

from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime, timezone
from typing import Any

from iot_defense.attacks.registry import ATTACK_SCENARIOS
from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.policy import (
    RuleBasedDefensePolicy,
    StackelbergDefensePolicy,
    compare_policies,
)
from iot_defense.detection.flow_features import FeatureAggregator
from iot_defense.detection.threat_event import ThreatEvent
from iot_defense.observability.logger import StructuredLogger
from iot_defense.observability.metrics import MetricsCollector
from iot_defense.agents.decision_agent import DecisionAgent
from iot_defense.agents.detection_agent import DetectionAgent
from iot_defense.agents.monitoring_agent import MonitoringAgent


# ─── Public phase names ────────────────────────────────────────────────────────
PHASES = (
    "IDLE",
    "STARTING_NETWORK",
    "BASELINE",
    "OBSERVING",
    "THREAT_DETECTED",
    "DECIDING",
    "RESPONDING",
    "DECOY_ACTIVE",
    "ISOLATED",
    "THROTTLED",
    "BLOCKED_SOURCE",
    "QUARANTINED",
    "SESSIONS_RESET",
    "FORENSICS_CAPTURED",
    "BANDWIDTH_CAPPED",
    "RESTORING",
    "RESTORED",
    "COMPLETE",
    "ERROR",
    "CLEANUP",
)

# ─── Node IP map (matches topology.yaml) ──────────────────────────────────────
NODE_IPS = {
    "sensor": "10.0.0.10",
    "camera": "10.0.0.20",
    "smart_plug": "10.0.0.30",
    "attacker": "10.0.0.100",
    "decoy": "10.0.0.200",
}

NODE_ROLES = {
    "sensor": "IoT Sensor",
    "camera": "Smart Camera",
    "smart_plug": "Smart Plug",
    "attacker": "Attacker",
    "decoy": "Decoy",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _initial_nodes() -> dict[str, Any]:
    return {
        name: {
            "ip": ip,
            "role": NODE_ROLES[name],
            "status": "OFFLINE",
        }
        for name, ip in NODE_IPS.items()
    }


def _initial_state() -> dict[str, Any]:
    return {
        "phase": "IDLE",
        "nodes": _initial_nodes(),
        "threat_status": "NORMAL",
        "timeline": [],
        "traffic": [],
        "threat_event": None,
        "security_context": None,
        "policy_comparison": None,
        "selected_decision": None,
        "response_result": None,
        "attack_mode": None,
        "observability": None,
        "metrics": {
            "packets_observed": 0,
            "flows_analyzed": 0,
            "threats_detected": 0,
            "decoy_interactions": 0,
            "isolations": 0,
            "throttles": 0,
            "blocks": 0,
            "quarantines": 0,
            "session_resets": 0,
            "forensic_captures": 0,
            "bandwidth_caps": 0,
            "restorations": 0,
            "detection_latency_ms": None,
            "response_latency_ms": None,
        },
        "timestamp": time.time(),
    }


class DemoController:
    """Orchestrate the full IoT defense pipeline and publish state/events via SSE."""

    def __init__(self) -> None:
        self.state: dict[str, Any] = _initial_state()
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self.data_dir = "/home/abdullah/iot-defense/data/dashboard"
        os.makedirs(self.data_dir, exist_ok=True)
        self.state_file = f"{self.data_dir}/state.json"
        self.net: Any = None
        self.executor: Any = None
        self.event_logger = StructuredLogger(log_dir="/home/abdullah/iot-defense/data/logs")
        self.metrics_collector = MetricsCollector()
        # DecisionAgent owns real cross-event history for this run: every
        # threat_event recorded through it becomes available as
        # previous_relevant_events on later BDI contexts, which the
        # dashboard's Security Context panel actually displays.
        self.decision_agent = DecisionAgent()
        # DetectionAgent wraps the original packet-level heuristic detector
        # (protocol/port/direction/length thresholds) -- a different, coarser
        # signal than the flow-based UnifiedRuleBasedDetector that makes the
        # actual ALLOW/ALERT/DECOY/ISOLATE decision. It runs over every
        # captured packet as a secondary, visible annotation, not as the
        # authoritative detector.
        self.detection_agent = DetectionAgent()
        # MonitoringAgent normalizes every captured packet into a fixed
        # schema before it's stored or aggregated -- real, defensive use on
        # every packet the dashboard shows.
        self.monitoring_agent = MonitoringAgent()
        # Persist initial state so /state always returns valid JSON
        self._persist()

    # ─── State management ─────────────────────────────────────────────────────

    def _persist(self) -> None:
        """Write current state to disk for /state endpoint."""
        try:
            with open(self.state_file, "w", encoding="utf-8") as fh:
                json.dump(self.state, fh, default=str)
        except OSError:
            pass

    def _add_timeline_entry(self, message: str) -> None:
        entry = {
            "timestamp": _now_iso(),
            "phase": self.state["phase"],
            "message": message,
        }
        self.state["timeline"].append(entry)

    async def update_state(self, new_data: dict[str, Any], timeline_message: str | None = None) -> None:
        """Merge new_data into state, persist to disk, and push SSE event."""
        self.state.update(new_data)
        self.state["timestamp"] = time.time()
        if timeline_message:
            self._add_timeline_entry(timeline_message)
        self._persist()
        # Broadcast to all SSE listeners
        snapshot = dict(self.state)
        await self.event_queue.put(snapshot)
        print(f"[DemoController] phase={self.state['phase']}", flush=True)

    def _set_node_status(self, statuses: dict[str, str]) -> dict[str, Any]:
        """Return an updated nodes dict with merged status changes."""
        nodes = dict(self.state["nodes"])
        for name, status in statuses.items():
            if name in nodes:
                nodes[name] = {**nodes[name], "status": status}
        return nodes

    # ─── Cleanup ──────────────────────────────────────────────────────────────

    def cleanup(self) -> None:
        """Tear down Mininet and executor in a safe order."""
        try:
            if self.executor:
                self.executor.cleanup()
        except Exception as exc:  # noqa: BLE001
            print(f"[DemoController] executor cleanup error: {exc}")
        try:
            if self.net:
                self.net.stop()
        except Exception as exc:  # noqa: BLE001
            print(f"[DemoController] mininet stop error: {exc}")
        self.executor = None
        self.net = None

    # ─── Policy evaluation ────────────────────────────────────────────────────

    def _build_policy_comparison(
        self,
        threat_event: ThreatEvent,
        context: Any,
    ) -> dict[str, Any]:
        """Evaluate all three policies against the same security context."""
        from iot_defense.defense.policy import RuleBasedDefensePolicy, StackelbergDefensePolicy

        rule_policy = RuleBasedDefensePolicy()
        stack_policy = StackelbergDefensePolicy()

        # rule_decision is the actual fallback target when Stackelberg
        # fails (see the selection logic below) -- deliberately not
        # wrapped in its own try/except, since there is nothing further
        # to fall back to if the fallback itself raises.
        rule_decision = rule_policy.decide(context)
        stack_decision = None
        stackelberg_reasoning: dict[str, Any] = {}
        stackelberg_fallback_used = False
        try:
            stack_decision = stack_policy.decide(context)
            stackelberg_reasoning = stack_decision.context.get("stackelberg_reasoning", {})
        except Exception as exc:  # noqa: BLE001
            # A real fallback, not just a comment claiming one exists --
            # found during a system review that this branch never
            # existed: selected decision was unconditionally
            # stack_decision, so a raising StackelbergDefensePolicy would
            # abort the whole run instead of actually falling back.
            print(f"[DemoController] Stackelberg decide error: {exc}")
            stackelberg_fallback_used = True

        # PPO – load if model exists, else fall back to rule-based
        ppo_decision = None
        ppo_fallback_used = False
        try:
            from iot_defense.defense.ppo_policy import PPODefensePolicy
            ppo = PPODefensePolicy(
                model_path="models/ppo_defense",
                fallback=RuleBasedDefensePolicy(),
            )
            ppo_decision = ppo.decide(context, stackelberg_info=stackelberg_reasoning)
            ppo_fallback_used = ppo.model is None
        except Exception as exc:  # noqa: BLE001
            print(f"[DemoController] PPO load error: {exc}")

        comparison: dict[str, Any] = {
            "rule_based": rule_decision.to_dict(),
            "stackelberg": stack_decision.to_dict() if stack_decision else None,
            "stackelberg_reasoning": stackelberg_reasoning,
            "stackelberg_fallback_used": stackelberg_fallback_used,
            "ppo": ppo_decision.to_dict() if ppo_decision else None,
            "ppo_fallback_used": ppo_fallback_used,
        }
        return comparison, rule_decision, stack_decision, ppo_decision

    # ─── Packet observation ───────────────────────────────────────────────────

    def _observe_packets(self, raw_packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalize and annotate every captured packet before it's stored.

        MonitoringAgent normalizes each raw packet dict into a fixed schema
        (real, defensive use on every packet). DetectionAgent then runs its
        original packet-level heuristic over the normalized packet as a
        secondary, visible signal alongside the flow-based detector that
        actually drives the ALLOW/ALERT/DECOY/ISOLATE decision -- it is
        never the authoritative detector, just an additional annotation.
        """
        observed: list[dict[str, Any]] = []
        for packet in raw_packets:
            normalized = self.monitoring_agent.observe(packet)
            analysis = self.detection_agent.analyze(normalized)
            normalized["packet_suspicious"] = bool(analysis.get("suspicious"))
            normalized["packet_suspicion_score"] = analysis.get("score")
            self.metrics_collector.record(
                {"suspicious": analysis.get("suspicious"), "source": "packet_level_heuristic"}
            )
            observed.append(normalized)
        return observed

    # ─── Detection ────────────────────────────────────────────────────────────

    def _classify_attack_traffic(self, flows: list[Any]) -> ThreatEvent:
        """Classify captured attack traffic without knowing which attack (if
        any) was actually triggered.

        Runs the attack-type-agnostic UnifiedRuleBasedDetector against the
        real captured flow -- it checks every registered attack's
        signature every time, regardless of what attack_mode requested,
        and is therefore not "told the answer" in advance. Only if it
        independently concludes reconnaissance is the trained Random
        Forest model consulted, as a richer ML-based confirmation of that
        specific, validated class. RF is now genuinely trained across all
        five classes (Phase 4), not just recon-vs-normal -- but it's still
        deliberately consulted only for recon: that's the one signature
        with the fuzziest rule-based boundary (a moderate rate spread
        across several ports, not a clean threshold), where the other
        four attacks' rule-based detectors have each been proven reliable
        across many live Mininet runs this project already has behind it.
        """
        from iot_defense.detection.detector import UnifiedRuleBasedDetector

        if not flows:
            # No reliable signal was captured -- report no evidence of an
            # attack rather than guessing, so the system fails safe.
            features = {
                "source_ip": "unknown",
                "destination_ip": NODE_IPS["sensor"],
                "unique_destination_ports": 0,
                "packet_count": 0,
                "packets_per_second": 0.0,
            }
            threat_event = UnifiedRuleBasedDetector().detect(features)
        else:
            # detect_flows(), not flows[0]: a capture window can contain
            # incidental background noise (ARP, IPv6 neighbour discovery)
            # ahead of the real attack traffic in capture order, especially
            # after a response has already isolated/restored the network
            # once this run -- scanning every flow instead of trusting
            # position avoids missing the real signal behind it.
            threat_event = UnifiedRuleBasedDetector().detect_flows(flows)
            features = threat_event.features

        if threat_event.attack_type == "reconnaissance_port_scan":
            try:
                from iot_defense.ml.random_forest import RandomForestDetector
                rf = RandomForestDetector("models/random_forest_detector.joblib")
                rf_event = rf.detect(features)
                # RF is a *confirmation* step, not a veto: only let it
                # override the rule-based recon classification -- downgrade
                # to "normal" or relabel to a different attack -- when it
                # disagrees with real confidence, not a near coin-flip.
                # Found via a live run where RF reclassified a genuine,
                # rule-verified port scan as "normal" at 50% confidence in
                # this 6-class model (only marginally better than the ~17%
                # an uninformed guess would get) -- silently downgrading a
                # real, already-detected attack to no response is the one
                # mistake this confirmation step must never make, however
                # small this project's controlled training set stays.
                if rf_event.attack_type == threat_event.attack_type or rf_event.confidence >= 0.7:
                    threat_event = rf_event
            except (FileNotFoundError, Exception):  # noqa: BLE001
                pass  # keep the rule-based recon classification

        return threat_event

    # ─── Main pipeline ────────────────────────────────────────────────────────

    async def _run_evaluate_and_respond(self, threat_event: ThreatEvent) -> None:
        """Decision → Response pipeline for a single threat event."""
        detect_start = time.perf_counter()

        # Build BDI-style security context. DecisionAgent tracks real event
        # history across the whole run -- previous_relevant_events on this
        # context genuinely reflects prior events (e.g. the baseline normal
        # traffic) rather than always being empty.
        context = self.decision_agent.build_context(threat_event, device_criticality="high")
        self.decision_agent.record(threat_event)
        self.metrics_collector.record({"suspicious": threat_event.attack_type != "normal", "source": "flow_detection"})

        # Evaluate all policies
        comparison, rule_decision, stack_decision, ppo_decision = self._build_policy_comparison(
            threat_event, context
        )
        detection_latency_ms = (time.perf_counter() - detect_start) * 1000

        # Selected decision: prefer Stackelberg (strategic), fall back to
        # rule-based if it failed to decide at all -- a real conditional
        # now, not just a comment (see _build_policy_comparison above).
        selected = stack_decision if stack_decision is not None else rule_decision

        await self.update_state(
            {
                "phase": "DECIDING",
                "threat_event": threat_event.to_dict(),
                "security_context": context.to_dict(),
                "policy_comparison": comparison,
                "selected_decision": selected.to_dict(),
                "threat_status": "THREAT_DETECTED",
                "metrics": {
                    **self.state["metrics"],
                    "detection_latency_ms": round(detection_latency_ms, 2),
                },
                "nodes": self._set_node_status({
                    "attacker": "ATTACKED",
                    "sensor": "ATTACKED",
                }),
            },
            timeline_message=(
                f"All policies evaluated. Rule-Based→{rule_decision.action.value}, "
                + (f"Stackelberg→{stack_decision.action.value}" if stack_decision else "Stackelberg→FAILED (fell back to rule-based)")
                + (f", PPO→{ppo_decision.action.value}" if ppo_decision else "")
                + f". Selected: {selected.action.value}"
            ),
        )

        # Execute the selected response
        resp_start = time.perf_counter()
        await self.update_state(
            {"phase": "RESPONDING"},
            timeline_message=f"Executing response: {selected.action.value} on {selected.target_ip}",
        )

        result = self.executor.execute(selected)
        response_latency_ms = (time.perf_counter() - resp_start) * 1000

        # Determine post-response phase and node statuses
        action = selected.action
        result_dict = result.to_dict()
        if action == DefenseAction.DECOY:
            post_phase = "DECOY_ACTIVE"
            node_updates = {
                "attacker": "DECOY ACTIVE",
                "decoy": "DECOY ACTIVE",
            }
            # Prove the redirect actually works: have the attacker connect to
            # the (redirected) target port and show the connection actually
            # lands on the decoy service, not the real target.
            interaction_summary = None
            if result.status == "success":
                try:
                    attacker_host = self.net.get("attacker")
                    decoy_ports = result.details.get("decoy_ports") or [22]
                    probe_port = decoy_ports[0]
                    interaction_output = attacker_host.cmd(
                        "python3 - <<'PY'\n"
                        "import socket\n"
                        "try:\n"
                        f"    sock = socket.create_connection(('{selected.target_ip}', {probe_port}), timeout=2)\n"
                        "    sock.sendall(b'GET /status')\n"
                        "    banner = sock.recv(128).decode(errors='replace').strip()\n"
                        "    sock.close()\n"
                        "    print(f'INTERACTION_OK:{banner}')\n"
                        "except Exception as exc:\n"
                        "    print(f'INTERACTION_FAILED:{exc}')\n"
                        "PY"
                    ).strip()
                    interaction_summary = interaction_output or None
                except Exception as exc:  # noqa: BLE001
                    interaction_summary = f"INTERACTION_ERROR:{exc}"
            decoy_interactions = self.state["metrics"].get("decoy_interactions", 0) + (
                1 if interaction_summary and "INTERACTION_OK" in interaction_summary else 0
            )
            result_dict["details"] = {
                **result_dict.get("details", {}),
                "interaction": interaction_summary,
                "interaction_count": decoy_interactions,
            }
            tl_msg = "Decoy active at 10.0.0.200 — attacker traffic redirected"
            if interaction_summary:
                tl_msg += f"; decoy interaction: {interaction_summary}"
        elif action == DefenseAction.ISOLATE:
            post_phase = "ISOLATED"
            node_updates = {"sensor": "ISOLATED"}
            decoy_interactions = self.state["metrics"].get("decoy_interactions", 0)
            tl_msg = f"Isolation applied to {selected.target_ip}"
        elif action == DefenseAction.THROTTLE:
            post_phase = "THROTTLED"
            node_updates = {"sensor": "THROTTLED"}
            decoy_interactions = self.state["metrics"].get("decoy_interactions", 0)
            throttle_details = result_dict.get("details", {})
            tl_msg = (
                f"Connection attempts to {selected.target_ip} rate-limited "
                f"({throttle_details.get('rate', '?')}, real iptables hashlimit)"
            )
        elif action == DefenseAction.BLOCK_SOURCE:
            post_phase = "BLOCKED_SOURCE"
            node_updates = {"sensor": "SOURCE BLOCKED"}
            decoy_interactions = self.state["metrics"].get("decoy_interactions", 0)
            block_details = result_dict.get("details", {})
            tl_msg = f"Attacker source {block_details.get('source_ip', selected.source_ip)} blocked at {selected.target_ip}"
        elif action == DefenseAction.QUARANTINE:
            post_phase = "QUARANTINED"
            node_updates = {"sensor": "QUARANTINED"}
            decoy_interactions = self.state["metrics"].get("decoy_interactions", 0)
            tl_msg = f"{selected.target_ip} quarantined to a default-deny allowlist of known-legitimate peers"
        elif action == DefenseAction.RESET_SESSIONS:
            post_phase = "SESSIONS_RESET"
            node_updates = {"sensor": "SESSIONS RESET"}
            decoy_interactions = self.state["metrics"].get("decoy_interactions", 0)
            tl_msg = f"Live connections between {selected.target_ip} and {selected.source_ip} were terminated"
        elif action == DefenseAction.FORENSIC_CAPTURE:
            post_phase = "FORENSICS_CAPTURED"
            node_updates = {"sensor": "MONITORED"}
            decoy_interactions = self.state["metrics"].get("decoy_interactions", 0)
            forensic_details = result_dict.get("details", {})
            tl_msg = f"Evidence captured to {forensic_details.get('pcap_path', '?')} — no network change"
        elif action == DefenseAction.BANDWIDTH_CAP:
            post_phase = "BANDWIDTH_CAPPED"
            node_updates = {"attacker": "BANDWIDTH CAPPED"}
            decoy_interactions = self.state["metrics"].get("decoy_interactions", 0)
            bandwidth_details = result_dict.get("details", {})
            tl_msg = f"Attacker egress bandwidth capped ({bandwidth_details.get('rate', '?')}, real tc tbf)"
        elif action in (DefenseAction.ALLOW, DefenseAction.ALERT):
            # The only two actions this chain deliberately never gives
            # their own phase -- neither has a real network effect to
            # report (see DefenseAction's own docstring for the two
            # named exceptions to "every dependent module derives from
            # the enum"). Every other action is handled explicitly
            # above; test_demo_controller.py's own completeness test
            # enforces that this stays true as the enum grows.
            post_phase = "OBSERVING"
            node_updates = {}
            decoy_interactions = self.state["metrics"].get("decoy_interactions", 0)
            tl_msg = f"Response executed: {action.value} — no network change"
        else:
            # Found by a system review: this branch used to be a silent
            # catch-all for ANY unhandled action, so a new DefenseAction
            # with a real network effect would fall through to "no
            # network change" instead of failing loudly. A genuinely
            # new action needs its own branch above -- this is a real
            # safety net, not routine behavior, and should never fire
            # for any of this project's own 10 currently-registered
            # actions.
            raise NotImplementedError(
                f"DefenseAction.{action.name} has no post-response phase branch in "
                "_run_evaluate_and_respond -- add one (or add it to the ALLOW/ALERT "
                "no-op case above if it genuinely has no network effect)."
            )

        new_metrics = {
            **self.state["metrics"],
            "response_latency_ms": round(response_latency_ms, 2),
            "threats_detected": self.state["metrics"]["threats_detected"] + 1,
            "isolations": self.state["metrics"]["isolations"] + (1 if action == DefenseAction.ISOLATE else 0),
            "throttles": self.state["metrics"].get("throttles", 0) + (1 if action == DefenseAction.THROTTLE else 0),
            "blocks": self.state["metrics"].get("blocks", 0) + (1 if action == DefenseAction.BLOCK_SOURCE else 0),
            "quarantines": self.state["metrics"].get("quarantines", 0) + (1 if action == DefenseAction.QUARANTINE else 0),
            "session_resets": self.state["metrics"].get("session_resets", 0) + (1 if action == DefenseAction.RESET_SESSIONS else 0),
            "forensic_captures": self.state["metrics"].get("forensic_captures", 0) + (1 if action == DefenseAction.FORENSIC_CAPTURE else 0),
            "bandwidth_caps": self.state["metrics"].get("bandwidth_caps", 0) + (1 if action == DefenseAction.BANDWIDTH_CAP else 0),
            "decoy_interactions": decoy_interactions,
        }

        self.metrics_collector.record({"action": action.value.lower(), "suspicious": True})
        await self.update_state(
            {
                "phase": post_phase,
                "response_result": result_dict,
                "metrics": new_metrics,
                "nodes": self._set_node_status(node_updates),
                "observability": self.metrics_collector.summary(),
            },
            timeline_message=tl_msg,
        )
        self.event_logger.log(
            {
                "event": "response_executed",
                "action": action.value,
                "target_ip": selected.target_ip,
                "status": result.status,
                "latency_ms": round(response_latency_ms, 2),
            }
        )

    async def run_demo(self, attack_mode: str = "reconnaissance") -> None:
        """Execute the full three-scenario IoT defense demonstration.

        attack_mode selects which registered attack Scenario B generates
        and detects -- any key in iot_defense.attacks.registry.ATTACK_SCENARIOS.
        Everything downstream of detection -- SecurityContext, the three
        policies, response execution, isolation validation, and
        restoration -- is already generic over attack type and needs no
        branching here.
        """
        if attack_mode not in ATTACK_SCENARIOS:
            raise ValueError(
                f"Unsupported attack_mode: {attack_mode!r} (expected one of {tuple(ATTACK_SCENARIOS)})"
            )
        try:
            # ── Phase 0: Start network ─────────────────────────────────────────
            await self.update_state(
                {"phase": "STARTING_NETWORK", "attack_mode": attack_mode},
                timeline_message=f"Initializing Mininet IoT network (attack mode: {attack_mode})",
            )

            from iot_defense.network.topology import create_mininet_network
            from iot_defense.monitoring.monitor import PacketMonitor
            from iot_defense.simulation.traffic import TrafficGenerator
            from iot_defense.defense.executor import MininetResponseExecutor

            self.net = create_mininet_network()
            self.net.start()
            self.executor = MininetResponseExecutor(self.net)
            traffic_gen = TrafficGenerator()
            monitor = PacketMonitor()
            aggregator = FeatureAggregator()

            online_nodes = {n: "ONLINE" for n in ["sensor", "camera", "smart_plug", "attacker", "decoy"]}
            await self.update_state(
                {
                    "nodes": self._set_node_status(online_nodes),
                },
                timeline_message="Mininet network started — all nodes online",
            )
            self.event_logger.log({"event": "network_started", "hosts": list(NODE_IPS.keys())})

            # ── Scenario A: Normal baseline traffic ────────────────────────────
            await self.update_state(
                {"phase": "BASELINE", "threat_status": "NORMAL"},
                timeline_message="Generating baseline IoT traffic",
            )
            # Start packet capture before generating traffic so tcpdump is
            # actively listening while traffic is on the wire, and that the
            # pcap file is fully flushed before it's read. start_capture()
            # blocks only until tcpdump confirms "listening on" (not a fixed
            # guess), and stop_capture() blocks until tcpdump confirms it has
            # exited and flushed (forcing a clean exit via SIGTERM if it
            # hasn't hit its packet limit yet) -- both ends of the earlier
            # race are now driven by tcpdump's own signals, not fixed sleeps.
            # watchdog_seconds: a real, previously-missing wall-clock
            # safety net (see start_capture's own docstring) -- generous
            # above this capture's own 4.0s completion_timeout so it never
            # fires in normal operation, only against a genuinely hung
            # capture or traffic generator.
            capture_session = await asyncio.to_thread(
                monitor.start_capture, self.net, "sensor", 20, watchdog_seconds=64.0
            )
            traffic_gen.generate_normal_mininet_traffic(self.net)
            cap_path = await asyncio.to_thread(monitor.stop_capture, self.net, capture_session, 4.0)
            raw_packets = self._observe_packets(monitor.read_capture(self.net, "sensor", cap_path))

            traffic_events = raw_packets[:20]
            flows = aggregator.aggregate(raw_packets)

            await self.update_state(
                {
                    "phase": "OBSERVING",
                    "traffic": traffic_events,
                    "metrics": {
                        **self.state["metrics"],
                        "packets_observed": len(raw_packets),
                        "flows_analyzed": len(flows),
                    },
                },
                timeline_message=f"Baseline capture complete — {len(raw_packets)} packets, {len(flows)} flows",
            )

            # Build a normal ThreatEvent from captured features
            if flows:
                f = flows[0]
                normal_event = ThreatEvent.from_result(
                    source_ip=f.source_ip,
                    destination_ip=f.destination_ip,
                    attack_type="normal",
                    threat_score=0.05,
                    confidence=0.92,
                    detection_reason="Baseline traffic classified as normal by flow feature analysis",
                    features=f.to_dict(),
                    detector_name="RuleBasedDetector:baseline",
                )
            else:
                normal_event = ThreatEvent.from_result(
                    source_ip=NODE_IPS["sensor"],
                    destination_ip=NODE_IPS["camera"],
                    attack_type="normal",
                    threat_score=0.05,
                    confidence=0.92,
                    detection_reason="Baseline traffic — no anomalies detected",
                    features={},
                    detector_name="RuleBasedDetector:baseline",
                )

            normal_context = self.decision_agent.build_context(normal_event)
            rule_p = RuleBasedDefensePolicy()
            normal_decision = rule_p.decide(normal_context)
            self.decision_agent.record(normal_event)
            self.metrics_collector.record({"suspicious": False, "source": "flow_detection"})

            await self.update_state(
                {
                    "threat_event": normal_event.to_dict(),
                    "security_context": normal_context.to_dict(),
                    "selected_decision": normal_decision.to_dict(),
                    "threat_status": "NORMAL",
                },
                timeline_message="Normal traffic confirmed — ALLOW policy applied",
            )

            # ── Scenario B: Attack (per attack_mode, from the attack registry) ──
            scenario = ATTACK_SCENARIOS[attack_mode]
            attack_label = scenario.label
            await self.update_state(
                {"phase": "THREAT_DETECTED", "threat_status": "SUSPICIOUS"},
                timeline_message=f"Generating {attack_label} attack",
            )

            # Attack traffic runs on the "attacker" host while capture runs on
            # "sensor" -- different host shells, so these can run concurrently
            # with no risk of overlapping .cmd() calls on the same host.
            # See the baseline capture above for why start/stop_capture are
            # used instead of a fixed-duration sleep on either end. Each
            # registered scenario carries its own packet_limit and capture
            # timeout, sized for how much traffic that attack actually
            # produces (e.g. a flood needs a higher limit and a tighter
            # window than a scan).
            atk_capture_session = await asyncio.to_thread(
                monitor.start_capture,
                self.net,
                "sensor",
                scenario.capture_packet_limit,
                watchdog_seconds=scenario.capture_completion_timeout + 60.0,
            )
            attack_result = scenario.generate_traffic(self.net)
            atk_cap_path = await asyncio.to_thread(
                monitor.stop_capture, self.net, atk_capture_session, scenario.capture_completion_timeout
            )
            atk_packets = self._observe_packets(monitor.read_capture(self.net, "sensor", atk_cap_path))
            atk_flows = aggregator.aggregate(atk_packets)

            # Detection is attack-type-agnostic from here: it classifies
            # whatever was actually captured, not what attack_mode was
            # requested. attack_mode only chose which traffic to generate
            # above; the detector is never told which attack (if any) it
            # should find.
            threat_event: ThreatEvent = self._classify_attack_traffic(atk_flows)

            all_traffic = (traffic_events + atk_packets)[:20]
            await self.update_state(
                {
                    "threat_status": "THREAT_DETECTED",
                    "traffic": all_traffic,
                    "metrics": {
                        **self.state["metrics"],
                        "packets_observed": self.state["metrics"]["packets_observed"] + len(atk_packets),
                        "flows_analyzed": self.state["metrics"]["flows_analyzed"] + len(atk_flows),
                    },
                },
                timeline_message=(
                    f"{attack_label} detected — {len(atk_packets)} attack packets captured, "
                    f"threat_score={threat_event.threat_score:.2f}"
                ),
            )
            self.event_logger.log(
                {
                    "event": "threat_detected",
                    "attack_type": threat_event.attack_type,
                    "threat_score": threat_event.threat_score,
                    "confidence": threat_event.confidence,
                    "source_ip": threat_event.source_ip,
                    "destination_ip": threat_event.destination_ip,
                    "detector_name": threat_event.detector_name,
                }
            )

            await self._run_evaluate_and_respond(threat_event)

            # ── Isolation capability validation ────────────────────────────────
            # Independent of which action the policies selected above for this
            # particular threat, prove the isolation/restore mechanism itself
            # works live: isolate an uninvolved device, verify connectivity is
            # actually lost, restore it, verify connectivity actually returns.
            # Ping *from* "camera", not "sensor" -- when the real response
            # above isolates sensor itself (e.g. the DoS scenario), sensor's
            # own interface is already down and it cannot send a ping at
            # all, which previously made this check silently read as
            # "failed" even though the real isolation had genuinely worked.
            # Camera is never a target of either attack scenario.
            await self.update_state(
                {"phase": "RESPONDING"},
                timeline_message="Validating isolation capability on smart_plug (10.0.0.30)",
            )
            try:
                pinger_host = self.net.get("camera")
                isolate_decision = DefenseDecision.create(
                    action=DefenseAction.ISOLATE,
                    target_ip=NODE_IPS["smart_plug"],
                    source_ip=NODE_IPS["attacker"],
                    reason=(
                        "Isolation capability validation — demonstrates containment "
                        "independently of the action selected for the current threat."
                    ),
                    confidence=1.0,
                    threat_score=1.0,
                    policy_name="IsolationCapabilityValidation",
                    context={"validation": "isolation_capability"},
                )
                isolate_result = self.executor.execute(isolate_decision)
                await self.update_state(
                    {
                        "phase": "ISOLATED",
                        "nodes": self._set_node_status({"smart_plug": "ISOLATED"}),
                        "metrics": {
                            **self.state["metrics"],
                            "isolations": self.state["metrics"]["isolations"] + 1,
                        },
                    },
                    timeline_message=f"Isolation applied to smart_plug — {isolate_result.status}",
                )
                after_ping = pinger_host.cmd(f"ping -c 1 -W 1 {NODE_IPS['smart_plug']}")
                self.executor.restore(NODE_IPS["smart_plug"])
                after_restore_ping = pinger_host.cmd(f"ping -c 1 -W 1 {NODE_IPS['smart_plug']}")
                connectivity_lost = "100% packet loss" in after_ping
                connectivity_recovered = "0% packet loss" in after_restore_ping
                await self.update_state(
                    {
                        "nodes": self._set_node_status({"smart_plug": "RESTORED"}),
                        "metrics": {
                            **self.state["metrics"],
                            "restorations": self.state["metrics"]["restorations"] + 1,
                        },
                    },
                    timeline_message=(
                        "Isolation validation complete — connectivity lost then restored "
                        f"(loss confirmed: {connectivity_lost}, recovery confirmed: {connectivity_recovered})"
                    ),
                )
                self.event_logger.log(
                    {
                        "event": "isolation_validation",
                        "target_ip": NODE_IPS["smart_plug"],
                        "connectivity_lost": connectivity_lost,
                        "connectivity_recovered": connectivity_recovered,
                    }
                )
            except Exception as exc:  # noqa: BLE001
                print(f"[DemoController] isolation validation error: {exc}", flush=True)

            # ── Scenario C: Restoration ────────────────────────────────────────
            await self.update_state(
                {"phase": "RESTORING"},
                timeline_message="Initiating restoration — reversing isolation/decoy",
            )

            # Only try restore if something was isolated or throttled --
            # executor.restore() itself checks both and undoes whichever
            # (if either) actually applies to this target.
            try:
                restore_details = self.executor.restore(threat_event.destination_ip)
            except Exception:  # noqa: BLE001
                restore_details = {"operation": "restore", "status": "nothing_isolated"}

            restore_nodes = {n: "RESTORED" for n in ["sensor", "attacker", "decoy", "camera", "smart_plug"]}
            await self.update_state(
                {
                    "phase": "RESTORED",
                    "nodes": self._set_node_status(restore_nodes),
                    "threat_status": "NORMAL",
                    "metrics": {
                        **self.state["metrics"],
                        "restorations": self.state["metrics"]["restorations"] + 1,
                    },
                },
                timeline_message="Restoration complete — network connectivity verified",
            )
            self.event_logger.log({"event": "restoration_complete", "target_ip": threat_event.destination_ip})

            await self.update_state(
                {"phase": "COMPLETE"},
                timeline_message="Demo complete — all scenarios executed successfully",
            )

        except Exception as exc:  # noqa: BLE001
            await self.update_state(
                {"phase": "ERROR", "error": str(exc)},
                timeline_message=f"ERROR: {exc}",
            )
        finally:
            await self.update_state(
                {"phase": "CLEANUP"},
                timeline_message="Cleaning up Mininet resources",
            )
            self.cleanup()


def _select_attack_mode() -> str:
    """Resolve the attack mode from --attack, or prompt interactively if omitted."""
    import argparse

    attack_keys = list(ATTACK_SCENARIOS)

    parser = argparse.ArgumentParser(description="Run the IoT defense live demo.")
    parser.add_argument(
        "--attack",
        choices=attack_keys,
        default=None,
        help=(
            "Attack scenario to run: "
            + ", ".join(f"{key!r} ({ATTACK_SCENARIOS[key].label})" for key in attack_keys)
            + ". Prompted interactively if omitted."
        ),
    )
    args = parser.parse_args()
    if args.attack is not None:
        return args.attack

    print("Select attack scenario:")
    for index, key in enumerate(attack_keys, start=1):
        scenario = ATTACK_SCENARIOS[key]
        print(f"  [{index}] {scenario.label} -> expected response: {scenario.preferred_action.value}")
    choice = input(f"Enter choice [1-{len(attack_keys)}] (default 1): ").strip()
    try:
        selected_index = int(choice) - 1
        if 0 <= selected_index < len(attack_keys):
            return attack_keys[selected_index]
    except ValueError:
        pass
    return attack_keys[0]


def main() -> None:
    attack_mode = _select_attack_mode()
    print(f"[DemoController] attack_mode={attack_mode}", flush=True)
    controller = DemoController()
    asyncio.run(controller.run_demo(attack_mode=attack_mode))


if __name__ == "__main__":
    main()
