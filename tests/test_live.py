"""The live (real-network) defender: detection window, firewall backend, policy
filtering, the legitimate-client service, and the loop that ties them together.

No test here needs root, a network or iptables: the firewall is driven through
a recording fake runner and traffic comes from synthetic packet events.
"""

from __future__ import annotations

import json
import urllib.request

import pytest

from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.pipeline import PolicyPipeline
from iot_defense.live import defender as live_defender
from iot_defense.live.backend import CHAIN, SUPPORTED_ACTIONS, IptablesBackend, UnsafeTargetError
from iot_defense.live.defender import LiveDefender, LiveState, replay_events
from iot_defense.live.service import LegitService
from iot_defense.live.window import WindowedDetector, is_routable_peer, sustained_alarms

BOX = "192.168.43.10"
PHONE = "192.168.43.20"
ATTACKER = "192.168.43.50"
GATEWAY = "192.168.43.1"


# ── synthetic traffic ─────────────────────────────────────────────────────────
def packet(src, dst, t, dport, sport=40000, proto="TCP", flags=0x02, length=60):
    return {
        "timestamp": t, "src_ip": src, "dst_ip": dst, "protocol": proto, "src_port": sport, "dst_port": dport,
        "packet_length": length, "ttl": 64, "direction": "inbound", "tcp_flags": flags,
        "display_src": src, "display_dst": dst, "display_protocol": proto, "background": False,
    }


def scan(src=ATTACKER, start=100.0, ports=300, rate=100.0):
    return [packet(src, BOX, start + i / rate, 1 + i, sport=50000 + i) for i in range(ports)]


def browsing(src=PHONE, start=100.0, seconds=60, port=8080, poll=2.0):
    """What the protected page's own polling puts on the wire toward the box: over one
    keep-alive connection, a request (~350 bytes) and the client's ACK of each reply."""
    events = []
    for i in range(int(seconds / poll)):
        t = start + i * poll
        events.append(packet(src, BOX, t, port, sport=45000, flags=0x18, length=350))
        events.append(packet(src, BOX, t + 0.05, port, sport=45000, flags=0x10, length=52))
    return events


def reconnecting(src=PHONE, start=100.0, seconds=60, port=8080):
    """A client that opens a brand-new connection every second (what the page would do
    without keep-alive): handshake, request, close. By shape this is a brute-force pattern."""
    events = []
    for s in range(seconds):
        t = start + s
        for k, (flags, length) in enumerate(((0x02, 60), (0x10, 52), (0x18, 350), (0x11, 52), (0x10, 52))):
            events.append(packet(src, BOX, t + 0.01 * k, port, sport=45000 + s, flags=flags, length=length))
    return events


class FakeRunner:
    def __init__(self, kernel_expiry=True):
        self.commands: list[list[str]] = []
        self.kernel_expiry = kernel_expiry
        self.listing = ""

    def __call__(self, args):
        self.commands.append(args)
        if "-m" in args and "time" in args and "192.0.2.1" in args:
            return (0 if self.kernel_expiry else 1), ""
        if "-L" in args:
            return 0, self.listing
        return 0, ""

    def joined(self):
        return [" ".join(c) for c in self.commands]


def make_backend(runner=None, clock=None, **kwargs):
    runner = runner or FakeRunner()
    clock = clock or (lambda: 1000.0)
    backend = IptablesBackend("enp0s8", [BOX], allowlist=[PHONE, GATEWAY], runner=runner, clock=clock, ttl_seconds=60, **kwargs)
    return backend, runner


# ── window / detection ────────────────────────────────────────────────────────
class TrustedService:
    """Stands in for the web service once it has seen the phone complete real requests."""

    def __init__(self, *trusted):
        self._trusted = set(trusted)

    def trusted_clients(self):
        return set(self._trusted)

    def served_since(self, *_a, **_k):
        return 0


class TestWindowedDetector:
    def test_a_port_scan_is_flagged_with_its_source(self):
        window = WindowedDetector([BOX])
        for event in scan():
            window.ingest(event)
        threat = window.evaluate(101.5)
        assert threat is not None
        assert threat.attack_type == "reconnaissance_port_scan"
        assert threat.source_ip == ATTACKER and threat.destination_ip == BOX

    def test_a_phone_polling_the_protected_page_is_never_flagged_for_more_than_a_moment(self):
        """Calibration finding: the first two or three packets of any new client are few and
        large, which the exploit detector reads as 'a small number of oversized requests'. That
        lasts one check; the defender requires consecutive checks, so it never acts on it."""
        window = WindowedDetector([BOX])
        alarms = window.scan_for_false_alarms(browsing())
        assert len(alarms) <= 1
        assert all(b["at"] - a["at"] > 1.0 for a, b in zip(alarms, alarms[1:]))

    def test_a_client_that_reconnects_every_second_looks_like_brute_force_which_is_why_trust_exists(self):
        window = WindowedDetector([BOX])
        alarms = window.scan_for_false_alarms(reconnecting())
        assert alarms and {a["attack_type"] for a in alarms} == {"brute_force"}

    def test_normal_traffic_with_a_scan_mixed_in_flags_only_the_scanner(self):
        window = WindowedDetector([BOX])
        for event in sorted(browsing() + scan(start=130.0), key=lambda e: e["timestamp"]):
            window.ingest(event)
        threat = window.evaluate(131.5)
        assert threat is not None and threat.source_ip == ATTACKER

    def test_sources_in_the_ignore_set_are_not_reconsidered(self):
        window = WindowedDetector([BOX])
        for event in scan():
            window.ingest(event)
        assert window.evaluate(101.5, ignore_sources={ATTACKER}) is None

    def test_only_ipv4_traffic_to_a_protected_address_from_a_real_peer_is_kept(self):
        window = WindowedDetector([BOX])
        assert window.ingest(packet(ATTACKER, "192.168.43.99", 1.0, 80)) is False  # someone else's traffic
        assert window.ingest(packet("unknown", BOX, 1.0, 80)) is False  # IPv6 / non-IP
        assert window.ingest(packet("0.0.0.0", BOX, 1.0, 80)) is False
        assert window.ingest(packet("224.0.0.251", BOX, 1.0, 80)) is False
        assert window.ingest(packet(BOX, BOX, 1.0, 80)) is False  # our own address
        assert window.ingest(packet(ATTACKER, BOX, 1.0, 80)) is True

    def test_old_packets_leave_the_window(self):
        window = WindowedDetector([BOX], window_seconds=5.0)
        for event in scan(start=100.0):
            window.ingest(event)
        assert window.evaluate(200.0) is None

    def test_is_routable_peer(self):
        assert is_routable_peer("192.168.1.5") and not is_routable_peer("127.0.0.1") and not is_routable_peer("fe80::1")


class TestSustainedAlarms:
    """Calibration must judge alarms the way the defender acts on them (two checks in a row)."""

    @staticmethod
    def alarm(at, source=PHONE, kind="exploit_payload_injection"):
        return {"at": at, "source_ip": source, "attack_type": kind, "reason": "x"}

    def test_a_one_off_alarm_is_not_sustained(self):
        assert sustained_alarms([self.alarm(102.0)]) == []

    def test_consecutive_alarms_from_one_source_are_one_sustained_run(self):
        runs = sustained_alarms([self.alarm(102.0), self.alarm(103.0), self.alarm(104.0)])
        assert len(runs) == 1 and runs[0]["checks"] == 3 and runs[0]["source_ip"] == PHONE and runs[0]["start"] == 102.0

    def test_a_gap_ends_the_run(self):
        assert sustained_alarms([self.alarm(102.0), self.alarm(110.0)]) == []
        assert len(sustained_alarms([self.alarm(102.0), self.alarm(103.0), self.alarm(120.0), self.alarm(121.0)])) == 2

    def test_sources_are_tracked_separately(self):
        runs = sustained_alarms([self.alarm(102.0), self.alarm(102.0, ATTACKER), self.alarm(103.0), self.alarm(103.0, ATTACKER, "brute_force")])
        assert {r["source_ip"] for r in runs} == {PHONE, ATTACKER}

    def test_the_required_run_length_is_configurable(self):
        assert len(sustained_alarms([self.alarm(102.0)], confirm_ticks=1)) == 1
        assert sustained_alarms([self.alarm(102.0), self.alarm(103.0)], confirm_ticks=3) == []

    def test_the_phones_normal_polling_has_no_sustained_alarm(self):
        alarms = WindowedDetector([BOX]).scan_for_false_alarms(browsing())
        assert sustained_alarms(alarms) == []


# ── firewall backend ──────────────────────────────────────────────────────────
class TestIptablesBackend:
    def test_setup_builds_a_dedicated_chain_hooked_to_one_interface_and_shields_the_allowlist(self):
        backend, runner = make_backend()
        backend.setup()
        cmds = runner.joined()
        assert any(f"-N {CHAIN}" in c for c in cmds)
        assert any(f"-I INPUT 1 -i enp0s8 -j {CHAIN}" in c for c in cmds)
        for address in (PHONE, GATEWAY, BOX):
            assert any(f"-A {CHAIN} -s {address}" in c and c.endswith("-j RETURN") for c in cmds)
        assert backend.kernel_expiry is True

    def test_kernel_expiry_is_optional(self):
        backend, runner = make_backend(FakeRunner(kernel_expiry=False))
        backend.setup()
        backend.block_source(ATTACKER)
        rule = next(c for c in runner.joined() if "iotdef:block" in c)
        assert backend.kernel_expiry is False and "--datestop" not in rule

    def test_block_source_installs_a_drop_rule_with_a_comment_and_a_deadline(self):
        backend, runner = make_backend()
        backend.setup()
        details = backend.block_source(ATTACKER)
        rule = next(c for c in runner.joined() if "iotdef:block" in c)
        assert f"-s {ATTACKER}" in rule and rule.endswith("-j DROP") and "--datestop" in rule
        assert details["source_ip"] == ATTACKER and details["expires_in_s"] == 60.0
        assert backend.active_sources() == {ATTACKER}

    def test_it_never_acts_on_protected_trusted_or_nonsense_addresses(self):
        backend, runner = make_backend()
        backend.setup()
        before = len(runner.commands)
        for bad in (BOX, PHONE, GATEWAY, "127.0.0.1", "224.0.0.1", "0.0.0.0", "not-an-ip", "fe80::1", "10.0.0.1; reboot"):
            with pytest.raises(UnsafeTargetError):
                backend.block_source(bad)
        assert len(runner.commands) == before and backend.active_sources() == set()

    def test_a_block_expires_and_its_rule_is_removed(self):
        now = [1000.0]
        backend, runner = make_backend(clock=lambda: now[0])
        backend.setup()
        backend.block_source(ATTACKER)
        now[0] = 1030.0
        assert backend.expire_due() == []
        now[0] = 1060.1
        assert backend.expire_due() == [ATTACKER]
        assert any(c.startswith("iptables -w 5 -D " + CHAIN) and "iotdef:block" in c for c in runner.joined())
        assert backend.active_sources() == set()

    def test_repeat_blocks_refresh_instead_of_stacking_rules(self):
        backend, runner = make_backend()
        backend.setup()
        backend.block_source(ATTACKER)
        again = backend.block_source(ATTACKER)
        assert again["already_active"] is True
        assert sum("iotdef:block" in c for c in runner.joined() if " -A " in c) == 1

    def test_throttle_uses_a_hashlimit_name_within_the_kernel_limit(self):
        backend, runner = make_backend()
        backend.setup()
        details = backend.throttle(ATTACKER)
        rule = next(c for c in runner.joined() if "iotdef:throttle" in c)
        name = rule.split("--hashlimit-name ")[1].split()[0]
        assert len(name) <= 15 and "--hashlimit-above 10/second" in rule and details["rate"] == "10/second"

    def test_counters_report_what_each_rule_dropped(self):
        backend, runner = make_backend()
        backend.setup()
        backend.block_source(ATTACKER)
        runner.listing = (
            f"Chain {CHAIN} (1 references)\n    pkts      bytes target     prot opt in     out     source               destination\n"
            f"       0        0 RETURN     all  --  *      *       {PHONE}            0.0.0.0/0            /* iotdef:allow:{PHONE} */\n"
            f"     812    48720 DROP       all  --  *      *       {ATTACKER}          0.0.0.0/0            /* iotdef:block:{ATTACKER} */\n"
        )
        assert backend.counters() == {ATTACKER: {"packets": 812, "bytes": 48720}}
        assert backend.snapshot()[0]["packets_dropped"] == 812

    def test_trusting_a_device_shields_it_and_releases_any_block_on_it(self):
        backend, runner = make_backend()
        backend.setup()
        backend.block_source(ATTACKER)
        backend.trust(ATTACKER)
        assert backend.active_sources() == set() and ATTACKER in backend.allowlist
        assert any(f"-I {CHAIN} 1 -s {ATTACKER}" in c and c.endswith("-j RETURN") for c in runner.joined())
        with pytest.raises(UnsafeTargetError):
            backend.block_source(ATTACKER)

    def test_teardown_removes_the_hook_and_the_chain(self):
        backend, runner = make_backend()
        backend.setup()
        backend.teardown()
        cmds = runner.joined()
        assert any(f"-D INPUT -i enp0s8 -j {CHAIN}" in c for c in cmds)
        assert cmds[-2].endswith(f"-F {CHAIN}") and cmds[-1].endswith(f"-X {CHAIN}")

    def test_forensic_capture_saves_evidence_without_touching_the_firewall(self, tmp_path):
        backend, runner = make_backend(evidence_dir=tmp_path)
        backend.setup()
        before = len(runner.commands)
        details = backend.save_evidence(ATTACKER, scan(ports=5))
        assert len(runner.commands) == before and details["packets"] == 5
        assert len((tmp_path / next(p.name for p in tmp_path.iterdir())).read_text().splitlines()) == 5


# ── policy pipeline ───────────────────────────────────────────────────────────
def decision(action, policy, source=ATTACKER):
    return DefenseDecision.create(
        action=action, target_ip=BOX, source_ip=source, reason="t", confidence=0.9, threat_score=0.9, policy_name=policy, context={}
    )


class TestPolicyPipeline:
    def context(self):
        from iot_defense.agents.decision_agent import DecisionAgent
        from iot_defense.detection.threat_event import ThreatEvent

        event = ThreatEvent.from_result(
            source_ip=ATTACKER, destination_ip=BOX, attack_type="reconnaissance_port_scan", threat_score=0.9, confidence=0.88,
            detection_reason="t", features={"packets_per_second": 90.0, "unique_destination_ports": 300}, detector_name="t",
        )
        return DecisionAgent().build_context(event, device_criticality="high")

    def patch_proposals(self, monkeypatch, rule, stack, ppo):
        comparison = {"rule_based": rule.to_dict(), "stackelberg": stack.to_dict(), "stackelberg_reasoning": {},
                      "stackelberg_fallback_used": False, "ppo": ppo.to_dict(), "ppo_fallback_used": False}
        monkeypatch.setattr("iot_defense.defense.pipeline.compute_proposals", lambda *_a, **_k: (comparison, rule, stack, ppo))

    def test_a_proposal_the_device_cannot_perform_is_set_aside_and_reported(self, monkeypatch, synthetic_table):
        from iot_defense.defense.arbiter import ArbiterPolicy

        self.patch_proposals(monkeypatch, decision(DefenseAction.DECOY, "r"), decision(DefenseAction.BLOCK_SOURCE, "s"), decision(DefenseAction.BLOCK_SOURCE, "p"))
        pipeline = PolicyPipeline("arbiter", supported_actions=SUPPORTED_ACTIONS, arbiter=ArbiterPolicy(synthetic_table))
        evaluation = pipeline.decide(self.context())
        assert evaluation.excluded == {"rule_based": "DECOY"}
        assert evaluation.selected.action == DefenseAction.BLOCK_SOURCE
        reasoning = evaluation.selected.context["arbiter_reasoning"]
        assert set(reasoning["proposals"]) == {"stackelberg", "ppo"}
        assert reasoning["excluded_unavailable"] == {"rule_based": "DECOY"}
        assert evaluation.comparison["excluded_unavailable"] == {"rule_based": "DECOY"}

    def test_a_forced_policy_whose_proposal_is_unavailable_falls_back_to_the_next(self, monkeypatch):
        self.patch_proposals(monkeypatch, decision(DefenseAction.DECOY, "r"), decision(DefenseAction.THROTTLE, "s"), decision(DefenseAction.QUARANTINE, "p"))
        evaluation = PolicyPipeline("rule_based", supported_actions=SUPPORTED_ACTIONS).decide(self.context())
        assert evaluation.selected.action == DefenseAction.THROTTLE and evaluation.excluded == {"rule_based": "DECOY", "ppo": "QUARANTINE"}

    def test_when_nothing_proposed_is_available_it_alerts_and_changes_nothing(self, monkeypatch):
        self.patch_proposals(monkeypatch, decision(DefenseAction.DECOY, "r"), decision(DefenseAction.ISOLATE, "s"), decision(DefenseAction.QUARANTINE, "p"))
        evaluation = PolicyPipeline("arbiter", supported_actions=SUPPORTED_ACTIONS).decide(self.context())
        assert evaluation.selected.action == DefenseAction.ALERT and evaluation.selected.policy_name == "LiveSafeFallback"

    def test_without_a_constraint_nothing_is_excluded(self, monkeypatch):
        self.patch_proposals(monkeypatch, decision(DefenseAction.DECOY, "r"), decision(DefenseAction.ISOLATE, "s"), decision(DefenseAction.QUARANTINE, "p"))
        evaluation = PolicyPipeline("stackelberg").decide(self.context())
        assert evaluation.excluded == {} and evaluation.selected.action == DefenseAction.ISOLATE

    def test_bad_policy_mode_is_rejected(self):
        with pytest.raises(ValueError):
            PolicyPipeline("vote")


# ── the always-legit service ──────────────────────────────────────────────────
class TestLegitService:
    def test_serves_the_page_and_learns_who_is_legitimate(self):
        service = LegitService(host="127.0.0.1", port=0)
        port = service.start()
        try:
            page = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3).read().decode()
            assert "Protected device" in page
            assert service.trusted_clients() == set()  # loading the page alone does not make a device trusted
            for _ in range(3):
                reply = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/ping", timeout=3).read())
                assert reply["ok"] is True
            assert service.trusted_clients() == {"127.0.0.1"}
            assert service.served_since(10) == 3 and service.served_since(10, exclude={"127.0.0.1"}) == 0
        finally:
            service.stop()

    def test_a_scanner_that_never_completes_a_request_is_never_trusted(self):
        service = LegitService(host="127.0.0.1", port=0)
        assert service.trusted_clients() == set()


# ── the loop ──────────────────────────────────────────────────────────────────
@pytest.fixture
def stack(tmp_path):
    runner = FakeRunner()
    now = [0.0]
    backend = IptablesBackend("enp0s8", [BOX], allowlist=[GATEWAY], runner=runner, clock=lambda: now[0], ttl_seconds=30,
                              evidence_dir=tmp_path / "evidence")
    backend.setup()
    live = {"mode": "live", "iface": "enp0s8", "box_ip": BOX, "static_allow": [GATEWAY], "supported_actions": [], "blocks": [],
            "trusted": [], "served_recent": 0, "dry_run": False, "kernel_expiry": True, "policy_mode": "stackelberg"}
    state = LiveState(tmp_path / "state.json", live)
    pipeline = PolicyPipeline("stackelberg", supported_actions=SUPPORTED_ACTIONS, ppo_model_path=str(tmp_path / "missing_ppo"))
    defender = LiveDefender(box_ip=BOX, backend=backend, pipeline=pipeline, state=state, window=WindowedDetector([BOX]),
                            service=TrustedService(PHONE))
    return defender, runner, state, tmp_path / "state.json"


class TestLiveDefender:
    def test_a_scan_is_detected_decided_and_blocked_while_the_phone_keeps_being_served(self, stack):
        defender, runner, state, state_path = stack
        events = sorted(browsing(start=100.0, seconds=40) + scan(start=110.0), key=lambda e: e["timestamp"])
        threats = replay_events(defender, events)

        assert [t.source_ip for t in threats] == [ATTACKER]  # exactly one response, and to the scanner
        blocks = [c for c in runner.joined() if "iotdef:block" in c]
        assert len(blocks) == 1 and f"-s {ATTACKER}" in blocks[0]
        assert not any(PHONE in c and c.endswith("-j DROP") for c in runner.joined())

        saved = json.loads(state_path.read_text())
        assert saved["attack_mode"] == "reconnaissance"
        assert saved["selected_decision"]["action"] == "BLOCK_SOURCE"
        assert saved["response_result"]["status"] == "success" and saved["response_result"]["action"] == "BLOCK_SOURCE"
        assert saved["policy_comparison"]["excluded_unavailable"] is not None
        assert saved["live"]["mode"] == "live" and saved["metrics"]["blocks"] == 1
        assert saved["nodes"]["attacker"]["ip"] == ATTACKER and saved["nodes"]["sensor"]["ip"] == BOX
        assert saved["metrics"]["detection_latency_ms"] is not None

    def test_the_block_expires_on_its_own_and_the_dashboard_says_so(self, stack):
        defender, runner, state, state_path = stack
        replay_events(defender, scan(start=100.0, ports=200))
        # ttl is 30s: run quiet time past it
        replay_events(defender, [packet(PHONE, BOX, 100.0 + s, 8080) for s in range(0, 60)])
        assert defender.backend.active_sources() == set()
        saved = json.loads(state_path.read_text())
        assert saved["threat_status"] == "NORMAL"
        assert any("expired" in entry["message"] for entry in saved["timeline"])

    def test_a_scanner_that_keeps_going_while_blocked_is_not_re_decided_every_second(self, stack):
        defender, runner, state, _ = stack
        events = scan(start=100.0, ports=200) + scan(start=102.0, ports=200) + scan(start=104.0, ports=200)
        threats = replay_events(defender, sorted(events, key=lambda e: e["timestamp"]))
        assert len(threats) == 1
        assert len([c for c in runner.joined() if "iotdef:block" in c]) == 1

    def test_an_unknown_phone_polling_normally_is_not_blocked_even_before_it_is_trusted(self, stack):
        defender, runner, _, _ = stack
        defender.service = TrustedService()  # nobody trusted yet
        assert replay_events(defender, browsing(seconds=60)) == []
        assert not [c for c in runner.joined() if "iotdef:block" in c]

    def test_a_trusted_client_that_looks_like_an_attack_is_left_alone_and_a_stranger_doing_the_same_is_not(self, stack):
        defender, runner, _, _ = stack
        assert replay_events(defender, reconnecting(src=PHONE, seconds=20)) == []
        stranger = replay_events(defender, reconnecting(src=ATTACKER, start=300.0, seconds=20))
        assert [t.source_ip for t in stranger] == [ATTACKER]
        blocked = [c for c in runner.joined() if "iotdef:block" in c]
        assert len(blocked) == 1 and ATTACKER in blocked[0] and PHONE not in blocked[0]

    def test_a_check_flagged_only_once_does_not_change_the_firewall_but_two_in_a_row_do(self, stack, monkeypatch):
        from iot_defense.detection.threat_event import ThreatEvent

        defender, runner, _, _ = stack
        threat = ThreatEvent.from_result(
            source_ip=ATTACKER, destination_ip=BOX, attack_type="reconnaissance_port_scan", threat_score=0.9, confidence=0.88,
            detection_reason="t", features={"packets_per_second": 90.0, "unique_destination_ports": 300}, detector_name="t",
        )
        sequence = iter([threat, None, threat, threat])
        monkeypatch.setattr(defender.window, "evaluate", lambda *_a, **_k: next(sequence))
        outcomes = [defender.step([], 100.0 + i) for i in range(4)]
        assert [o is not None for o in outcomes] == [False, False, False, True]
        assert len([c for c in runner.joined() if "iotdef:block" in c]) == 1

    def test_warm_up_runs_the_pipeline_once_without_touching_history_state_or_firewall(self, stack, monkeypatch):
        """The first evaluation took ~13 s on the demo VM (RL library import, PPO model load) and
        stalled the protected page; the defender now does it once at start-up."""
        defender, runner, _, _ = stack
        calls, real = [], defender.pipeline.decide
        monkeypatch.setattr(defender.pipeline, "decide", lambda ctx: (calls.append(ctx), real(ctx))[1])
        before = dict(defender.state.state)
        seconds = defender.warm_up()
        assert len(calls) == 1 and seconds >= 0.0
        assert defender.decision_agent.event_history == []
        assert defender.state.state == before
        assert not [c for c in runner.joined() if "iotdef:block" in c]

    def test_a_trusted_gateway_is_never_blocked_even_if_it_scans(self, stack):
        defender, runner, _, _ = stack
        threats = replay_events(defender, scan(src=GATEWAY))
        assert threats == [] and not [c for c in runner.joined() if "iotdef:block" in c]

    def test_an_attack_after_the_block_expired_is_blocked_again(self, stack):
        defender, runner, _, _ = stack
        replay_events(defender, scan(start=100.0, ports=200))
        replay_events(defender, [packet(PHONE, BOX, 101.0 + s, 8080) for s in range(1, 70)])
        replay_events(defender, scan(start=200.0, ports=200))
        assert len([c for c in runner.joined() if "iotdef:block" in c and " -A " in c]) == 2

    def test_a_refused_response_is_reported_as_failed_not_hidden(self, stack, monkeypatch):
        defender, runner, state, state_path = stack
        monkeypatch.setattr(defender.backend, "block_source", lambda *_: (_ for _ in ()).throw(UnsafeTargetError("never-block list")))
        replay_events(defender, scan(start=100.0, ports=200))
        saved = json.loads(state_path.read_text())
        assert saved["response_result"]["status"] == "failed" and "never-block" in saved["response_result"]["message"]
        assert saved["phase"] == "ERROR"


def test_interface_and_gateway_helpers_parse_iproute_output():
    runner = lambda cmd: (0, "3: enp0s8    inet 192.168.43.10/24 brd 192.168.43.255 scope global dynamic enp0s8\n") if "addr" in cmd else (
        0, "default via 192.168.43.1 proto dhcp src 192.168.43.10 metric 600\n")
    assert live_defender.interface_ip("enp0s8", runner) == "192.168.43.10"
    assert live_defender.default_gateway("enp0s8", runner) == "192.168.43.1"
    with pytest.raises(SystemExit):
        live_defender.interface_ip("enp0s8", lambda cmd: (1, ""))


def test_packet_to_event_labels_direction_and_flags():
    scapy = pytest.importorskip("scapy.all")
    from iot_defense.monitoring.monitor import packet_to_event

    pkt = scapy.Ether() / scapy.IP(src=ATTACKER, dst=BOX) / scapy.TCP(sport=51000, dport=22, flags="S")
    event = packet_to_event(pkt, BOX)
    assert (event["src_ip"], event["dst_ip"], event["protocol"], event["dst_port"], event["tcp_flags"]) == (ATTACKER, BOX, "TCP", 22, 0x02)
    assert event["direction"] == "inbound" and event["background"] is False
