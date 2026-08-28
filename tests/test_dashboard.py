"""Dashboard integration tests — no Mininet required."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient


# ── Ensure state file exists before importing app ──────────────────────────────
_STATE_DIR = Path("/home/abdullah/iot-defense/data/dashboard")
_STATE_DIR.mkdir(parents=True, exist_ok=True)
_STATE_FILE = _STATE_DIR / "state.json"
if not _STATE_FILE.exists():
    _STATE_FILE.write_text(json.dumps({"phase": "IDLE"}), encoding="utf-8")

from iot_defense.dashboard.server import app  # noqa: E402
from iot_defense.demo.controller import _initial_state  # noqa: E402


@pytest.fixture(scope="module")
def client():
    """Single TestClient per module to avoid repeated app startup."""
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def reset_state_file():
    """Restore a minimal valid state.json before each test."""
    _STATE_FILE.write_text(json.dumps({"phase": "IDLE", "nodes": {}}), encoding="utf-8")
    yield
    _STATE_FILE.write_text(json.dumps({"phase": "IDLE"}), encoding="utf-8")


def _fresh_controller(tmp_path=None):
    """Create a fresh, isolated DemoController with its own tmp state file."""
    from iot_defense.demo.controller import DemoController
    ctrl = DemoController()
    if tmp_path:
        ctrl.data_dir = str(tmp_path)
        ctrl.state_file = str(Path(tmp_path) / "state.json")
    else:
        import tempfile
        d = tempfile.mkdtemp()
        ctrl.data_dir = d
        ctrl.state_file = str(Path(d) / "state.json")
    ctrl._persist()
    return ctrl


def _run(coro):
    """Run a coroutine in a fresh event loop."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()
        asyncio.set_event_loop(None)


# ── HTTP endpoint tests ────────────────────────────────────────────────────────

class TestRootEndpoint:
    def test_root_returns_200(self, client):
        resp = client.get("/")
        assert resp.status_code == 200

    def test_root_is_html(self, client):
        resp = client.get("/")
        assert "text/html" in resp.headers.get("content-type", "")

    def test_root_contains_dashboard_content(self, client):
        resp = client.get("/")
        text = resp.text.lower()
        assert "iot" in text or "defense" in text or "residential" in text


class TestStaticFiles:
    def test_dashboard_js_200(self, client):
        resp = client.get("/static/dashboard.js")
        assert resp.status_code == 200

    def test_style_css_200(self, client):
        resp = client.get("/static/style.css")
        assert resp.status_code == 200

    def test_index_html_via_static_200(self, client):
        resp = client.get("/static/index.html")
        assert resp.status_code == 200

    def test_js_content_type(self, client):
        resp = client.get("/static/dashboard.js")
        ct = resp.headers.get("content-type", "")
        assert "javascript" in ct or "text" in ct

    def test_css_content_type(self, client):
        resp = client.get("/static/style.css")
        ct = resp.headers.get("content-type", "")
        assert "css" in ct or "text" in ct


class TestStateEndpoint:
    def test_state_returns_200(self, client):
        resp = client.get("/state")
        assert resp.status_code == 200

    def test_state_returns_valid_json(self, client):
        resp = client.get("/state")
        data = resp.json()
        assert isinstance(data, dict)

    def test_state_has_phase(self, client):
        resp = client.get("/state")
        data = resp.json()
        assert "phase" in data

    def test_state_reflects_file_contents(self, client):
        _STATE_FILE.write_text(json.dumps({"phase": "BASELINE", "extra": 1}))
        resp = client.get("/state")
        data = resp.json()
        assert data["phase"] == "BASELINE"

    def test_state_handles_missing_file(self, client):
        """Server should return fallback IDLE state if state.json is missing."""
        backup = _STATE_FILE.read_text()
        _STATE_FILE.unlink()
        try:
            resp = client.get("/state")
            assert resp.status_code == 200
            data = resp.json()
            assert "phase" in data
        finally:
            _STATE_FILE.write_text(backup)


class _UvicornThread(threading.Thread):
    """Run the real ASGI app over a real socket for streaming-response tests.

    httpx's in-process ASGITransport (used by FastAPI's TestClient) fully
    drains an app's response before returning control, so it cannot test an
    endpoint whose generator is intentionally infinite (a correct SSE
    stream). A real socket streams incrementally like production uvicorn
    does, so /stream must be exercised against a live server instead.
    """

    def __init__(self, port: int) -> None:
        super().__init__(daemon=True)
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        self.server = uvicorn.Server(config)

    def run(self) -> None:
        self.server.run()

    def stop(self) -> None:
        self.server.should_exit = True


@pytest.fixture(scope="module")
def live_server_url():
    """Start the real dashboard app on a real socket for one test module."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    thread = _UvicornThread(port)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        try:
            httpx.get(f"{base_url}/state", timeout=0.5)
            break
        except httpx.HTTPError:
            time.sleep(0.1)
    else:
        raise RuntimeError("Live dashboard server did not become ready in time")

    yield base_url

    thread.stop()
    thread.join(timeout=5)


class TestStreamEndpoint:
    def test_stream_exists(self, live_server_url):
        with httpx.stream("GET", f"{live_server_url}/stream", timeout=5.0) as resp:
            assert resp.status_code == 200

    def test_stream_content_type_sse(self, live_server_url):
        with httpx.stream("GET", f"{live_server_url}/stream", timeout=5.0) as resp:
            ct = resp.headers.get("content-type", "")
            assert "text/event-stream" in ct

    def test_stream_delivers_initial_state_as_valid_json(self, live_server_url):
        """Verify the very first SSE frame is real, parseable state — not just headers."""
        with httpx.stream("GET", f"{live_server_url}/stream", timeout=5.0) as resp:
            assert resp.status_code == 200
            for line in resp.iter_lines():
                if line.startswith("data: "):
                    payload = json.loads(line[len("data: "):])
                    assert "phase" in payload
                    break
            else:
                pytest.fail("No data frame received from /stream")


# ── DemoController unit tests ──────────────────────────────────────────────────

class TestDemoControllerState:
    """Each test method gets a fresh isolated controller."""

    def test_initial_phase_is_idle(self):
        ctrl = _fresh_controller()
        assert ctrl.state["phase"] == "IDLE"

    def test_initial_nodes_present(self):
        ctrl = _fresh_controller()
        nodes = ctrl.state["nodes"]
        assert "sensor" in nodes
        assert "camera" in nodes
        assert "smart_plug" in nodes
        assert "attacker" in nodes
        assert "decoy" in nodes

    def test_initial_metrics_present(self):
        ctrl = _fresh_controller()
        m = ctrl.state["metrics"]
        assert "packets_observed" in m
        assert "flows_analyzed" in m
        assert "threats_detected" in m

    def test_update_state_changes_phase(self):
        ctrl = _fresh_controller()
        _run(ctrl.update_state({"phase": "BASELINE"}))
        assert ctrl.state["phase"] == "BASELINE"

    def test_update_state_persists_to_file(self):
        ctrl = _fresh_controller()
        _run(ctrl.update_state({"phase": "OBSERVING"}))
        with open(ctrl.state_file) as f:
            data = json.load(f)
        assert data["phase"] == "OBSERVING"

    def test_update_state_adds_timestamp(self):
        ctrl = _fresh_controller()
        _run(ctrl.update_state({"phase": "BASELINE"}))
        assert "timestamp" in ctrl.state

    def test_update_state_publishes_to_queue(self):
        ctrl = _fresh_controller()
        _run(ctrl.update_state({"phase": "THREAT_DETECTED"}))
        assert not ctrl.event_queue.empty()

    def test_timeline_message_appended(self):
        ctrl = _fresh_controller()
        _run(ctrl.update_state({"phase": "BASELINE"}, timeline_message="Test message"))
        tl = ctrl.state["timeline"]
        assert len(tl) == 1
        assert tl[0]["message"] == "Test message"
        assert tl[0]["phase"] == "BASELINE"
        assert "timestamp" in tl[0]

    def test_set_node_status_updates(self):
        ctrl = _fresh_controller()
        nodes = ctrl._set_node_status({"sensor": "ONLINE", "attacker": "ATTACKED"})
        assert nodes["sensor"]["status"] == "ONLINE"
        assert nodes["attacker"]["status"] == "ATTACKED"

    def test_node_ips_correct(self):
        ctrl = _fresh_controller()
        nodes = ctrl.state["nodes"]
        assert nodes["sensor"]["ip"] == "10.0.0.10"
        assert nodes["camera"]["ip"] == "10.0.0.20"
        assert nodes["smart_plug"]["ip"] == "10.0.0.30"
        assert nodes["attacker"]["ip"] == "10.0.0.100"
        assert nodes["decoy"]["ip"] == "10.0.0.200"


# ── State serialization tests ──────────────────────────────────────────────────

class TestStateSerializationCompatibility:
    """Verify that all backend objects serialize to JSON cleanly."""

    def test_threat_event_to_dict_is_json_serializable(self):
        from iot_defense.detection.threat_event import ThreatEvent
        evt = ThreatEvent.from_result(
            source_ip="10.0.0.100", destination_ip="10.0.0.10",
            attack_type="reconnaissance_port_scan", threat_score=0.88,
            confidence=0.86, detection_reason="test",
            features={"packet_count": 10, "unique_destination_ports": 4},
            detector_name="test-detector",
        )
        d = evt.to_dict()
        s = json.dumps(d)
        assert "reconnaissance_port_scan" in s
        assert "10.0.0.100" in s

    def test_security_context_to_dict_is_json_serializable(self):
        from iot_defense.defense.context import build_security_context
        from iot_defense.detection.threat_event import ThreatEvent
        evt = ThreatEvent.from_result(
            source_ip="10.0.0.100", destination_ip="10.0.0.10",
            attack_type="reconnaissance_port_scan", threat_score=0.88,
            confidence=0.86, detection_reason="test", features={}, detector_name="t",
        )
        ctx = build_security_context(evt)
        d = ctx.to_dict()
        s = json.dumps(d)
        assert "beliefs" in s
        assert "desires" in s
        assert "intention" in s

    def test_defense_decision_to_dict_is_json_serializable(self):
        from iot_defense.defense.decision import DefenseAction, DefenseDecision
        dec = DefenseDecision.create(
            action=DefenseAction.DECOY, target_ip="10.0.0.10", source_ip="10.0.0.100",
            reason="test", confidence=0.88, threat_score=0.85,
            policy_name="TestPolicy", context={},
        )
        d = dec.to_dict()
        s = json.dumps(d)
        assert "DECOY" in s

    def test_response_result_to_dict_is_json_serializable(self):
        from iot_defense.defense.decision import DefenseAction
        from iot_defense.defense.result import ResponseResult
        r = ResponseResult.from_timing(
            action=DefenseAction.ALERT, target_ip="10.0.0.10", source_ip="10.0.0.100",
            status="success", started_at="2026-01-01T00:00:00Z", latency_ms=5.2,
            message="test", details={"operation": "log_only"},
        )
        s = json.dumps(r.to_dict())
        assert "ALERT" in s

    def test_stackelberg_solution_to_dict_is_json_serializable(self):
        from iot_defense.defense.stackelberg import StackelbergGame
        game = StackelbergGame()
        sol = game.solve("RECONNAISSANCE_PORT_SCAN")
        d = sol.to_dict()
        s = json.dumps(d)
        assert "selected_action" in s
        assert "candidates" in s

    def test_full_state_snapshot_is_json_serializable(self):
        state = _initial_state()
        s = json.dumps(state, default=str)
        data = json.loads(s)
        assert data["phase"] == "IDLE"
        assert "nodes" in data
        assert "metrics" in data
        assert "timeline" in data


# ── Demo state transition tests ────────────────────────────────────────────────

class TestDemoStateTransitions:
    VALID_PHASES = [
        "IDLE", "STARTING_NETWORK", "BASELINE", "OBSERVING",
        "THREAT_DETECTED", "DECIDING", "RESPONDING", "DECOY_ACTIVE",
        "ISOLATED", "RESTORING", "RESTORED", "COMPLETE", "ERROR", "CLEANUP",
    ]

    def test_all_phase_names_valid(self):
        ctrl = _fresh_controller()
        for phase in self.VALID_PHASES:
            _run(ctrl.update_state({"phase": phase}))
            assert ctrl.state["phase"] == phase

    def test_idle_to_starting_network(self):
        ctrl = _fresh_controller()
        _run(ctrl.update_state({"phase": "STARTING_NETWORK"}))
        assert ctrl.state["phase"] == "STARTING_NETWORK"

    def test_threat_detected_sets_status(self):
        ctrl = _fresh_controller()
        _run(ctrl.update_state({"phase": "THREAT_DETECTED", "threat_status": "THREAT_DETECTED"}))
        assert ctrl.state["threat_status"] == "THREAT_DETECTED"

    def test_cleanup_after_demo(self):
        ctrl = _fresh_controller()
        _run(ctrl.update_state({"phase": "CLEANUP"}))
        assert ctrl.state["phase"] == "CLEANUP"


# ── Frontend/state compatibility ───────────────────────────────────────────────

class TestFrontendStateCompatibility:
    """Verify that state fields match what dashboard.js expects to read."""

    def test_nodes_have_ip_and_status(self):
        state = _initial_state()
        for name, node in state["nodes"].items():
            assert "ip" in node, f"node {name} missing ip"
            assert "status" in node, f"node {name} missing status"
            assert "role" in node, f"node {name} missing role"

    def test_metrics_keys_match_frontend(self):
        state = _initial_state()
        m = state["metrics"]
        expected = [
            "packets_observed", "flows_analyzed", "threats_detected",
            "decoy_interactions", "isolations", "restorations",
            "detection_latency_ms", "response_latency_ms",
        ]
        for key in expected:
            assert key in m, f"metrics missing key: {key}"

    def test_threat_event_has_frontend_fields(self):
        from iot_defense.detection.threat_event import ThreatEvent
        evt = ThreatEvent.from_result(
            source_ip="10.0.0.100", destination_ip="10.0.0.10",
            attack_type="reconnaissance_port_scan", threat_score=0.88,
            confidence=0.86, detection_reason="test", features={}, detector_name="t",
        )
        d = evt.to_dict()
        for key in ["source_ip", "destination_ip", "attack_type", "threat_score",
                    "confidence", "detection_reason", "features", "detector_name"]:
            assert key in d, f"threat_event missing frontend field: {key}"

    def test_security_context_has_beliefs_desires_intention(self):
        from iot_defense.defense.context import build_security_context
        from iot_defense.detection.threat_event import ThreatEvent
        evt = ThreatEvent.from_result(
            source_ip="10.0.0.100", destination_ip="10.0.0.10",
            attack_type="reconnaissance_port_scan", threat_score=0.88,
            confidence=0.86, detection_reason="test", features={}, detector_name="t",
        )
        ctx = build_security_context(evt)
        d = ctx.to_dict()
        assert "beliefs" in d
        assert "desires" in d
        assert "intention" in d
        b = d["beliefs"]
        for key in ["threat_type", "threat_score", "confidence",
                    "source_device", "destination_device", "device_criticality"]:
            assert key in b, f"beliefs missing: {key}"

    def test_policy_comparison_has_three_policies(self):
        from iot_defense.defense.context import build_security_context
        from iot_defense.defense.policy import RuleBasedDefensePolicy, StackelbergDefensePolicy
        from iot_defense.detection.threat_event import ThreatEvent
        evt = ThreatEvent.from_result(
            source_ip="10.0.0.100", destination_ip="10.0.0.10",
            attack_type="reconnaissance_port_scan", threat_score=0.88,
            confidence=0.86, detection_reason="test", features={}, detector_name="t",
        )
        ctx = build_security_context(evt)
        rb_d = RuleBasedDefensePolicy().decide(ctx).to_dict()
        sk   = StackelbergDefensePolicy()
        sk_d = sk.decide(ctx).to_dict()
        assert "action" in rb_d
        assert "action" in sk_d
        sk_r = sk_d["context"]["stackelberg_reasoning"]
        assert "selected_action" in sk_r
        assert "candidates" in sk_r

    def test_response_result_has_frontend_fields(self):
        from iot_defense.defense.decision import DefenseAction
        from iot_defense.defense.result import ResponseResult
        r = ResponseResult.from_timing(
            action=DefenseAction.DECOY, target_ip="10.0.0.10", source_ip="10.0.0.100",
            status="success", started_at="2026-01-01T00:00:00Z", latency_ms=12.5,
            message="Decoy started", details={"operation": "decoy"},
        )
        d = r.to_dict()
        for key in ["action", "target_ip", "source_ip", "status",
                    "started_at", "completed_at", "latency_ms", "message", "details"]:
            assert key in d, f"response_result missing: {key}"
        assert d["action"] == "DECOY"

    def test_full_state_snapshot_is_json_serializable(self):
        state = _initial_state()
        s = json.dumps(state, default=str)
        data = json.loads(s)
        assert data["phase"] == "IDLE"
