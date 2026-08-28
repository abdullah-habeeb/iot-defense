"""DemoController unit tests — no Mininet required."""

from __future__ import annotations

import asyncio
import json
import os

import pytest

from iot_defense.demo.controller import DemoController, _initial_state


@pytest.fixture()
def ctrl(tmp_path):
    c = DemoController()
    c.data_dir = str(tmp_path)
    c.state_file = str(tmp_path / "state.json")
    c._persist()
    return c


def run(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestInitialState:
    def test_initial_phase_is_idle(self, ctrl):
        assert ctrl.state["phase"] == "IDLE"

    def test_initial_nodes_have_correct_ips(self, ctrl):
        n = ctrl.state["nodes"]
        assert n["sensor"]["ip"] == "10.0.0.10"
        assert n["camera"]["ip"] == "10.0.0.20"
        assert n["smart_plug"]["ip"] == "10.0.0.30"
        assert n["attacker"]["ip"] == "10.0.0.100"
        assert n["decoy"]["ip"] == "10.0.0.200"

    def test_initial_metrics_zeros(self, ctrl):
        m = ctrl.state["metrics"]
        assert m["packets_observed"] == 0
        assert m["threats_detected"] == 0

    def test_initial_timeline_empty(self, ctrl):
        assert ctrl.state["timeline"] == []

    def test_initial_traffic_empty(self, ctrl):
        assert ctrl.state["traffic"] == []


class TestUpdateState:
    def test_phase_updated(self, ctrl):
        run(ctrl.update_state({"phase": "BASELINE"}))
        assert ctrl.state["phase"] == "BASELINE"

    def test_timestamp_added(self, ctrl):
        run(ctrl.update_state({"phase": "BASELINE"}))
        assert "timestamp" in ctrl.state

    def test_persists_to_file(self, ctrl):
        run(ctrl.update_state({"phase": "OBSERVING"}))
        with open(ctrl.state_file) as f:
            data = json.load(f)
        assert data["phase"] == "OBSERVING"

    def test_publishes_to_event_queue(self, ctrl):
        run(ctrl.update_state({"phase": "THREAT_DETECTED"}))
        assert not ctrl.event_queue.empty()

    def test_timeline_message_appended(self, ctrl):
        run(ctrl.update_state({"phase": "BASELINE"}, timeline_message="Network started"))
        tl = ctrl.state["timeline"]
        assert len(tl) == 1
        assert tl[0]["message"] == "Network started"
        assert tl[0]["phase"] == "BASELINE"
        assert "timestamp" in tl[0]

    def test_multiple_updates_accumulate_timeline(self, ctrl):
        run(ctrl.update_state({"phase": "BASELINE"}, timeline_message="A"))
        run(ctrl.update_state({"phase": "OBSERVING"}, timeline_message="B"))
        assert len(ctrl.state["timeline"]) == 2


class TestNodeStatus:
    def test_set_node_status_updates_correctly(self, ctrl):
        nodes = ctrl._set_node_status({"sensor": "ONLINE", "attacker": "ATTACKED"})
        assert nodes["sensor"]["status"] == "ONLINE"
        assert nodes["attacker"]["status"] == "ATTACKED"

    def test_set_node_status_preserves_ip(self, ctrl):
        nodes = ctrl._set_node_status({"sensor": "ONLINE"})
        assert nodes["sensor"]["ip"] == "10.0.0.10"

    def test_set_node_status_ignores_unknown(self, ctrl):
        # Unknown node names should be silently skipped
        nodes = ctrl._set_node_status({"nonexistent": "ONLINE"})
        assert "nonexistent" not in nodes


class TestInitialStateFactory:
    def test_initial_state_has_required_keys(self):
        state = _initial_state()
        required = ["phase", "nodes", "threat_status", "timeline", "traffic",
                    "threat_event", "security_context", "policy_comparison",
                    "selected_decision", "response_result", "metrics", "timestamp"]
        for key in required:
            assert key in state, f"missing key: {key}"

    def test_initial_state_is_json_serializable(self):
        state = _initial_state()
        s = json.dumps(state, default=str)
        data = json.loads(s)
        assert data["phase"] == "IDLE"
