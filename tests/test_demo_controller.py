"""DemoController unit tests — no Mininet required."""

from __future__ import annotations

import asyncio
import json
import os
from unittest.mock import patch

import pytest

from iot_defense.demo.controller import DemoController, _initial_state
from iot_defense.detection.flow_features import FlowFeatures
from iot_defense.detection.threat_event import ThreatEvent


def _flow(**overrides):
    base = dict(
        source_ip="10.0.0.100", destination_ip="10.0.0.10", protocol="TCP",
        duration=1.0, packet_count=1, packets_per_second=1.0, bytes_total=64,
        average_packet_size=64.0, unique_destination_ports=0, unique_source_ports=0,
        tcp_syn_count=0, tcp_ack_count=0, udp_packet_count=0, icmp_packet_count=0,
    )
    base.update(overrides)
    return FlowFeatures(**base)


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


class TestAttackClassificationIsAttackTypeAgnostic:
    """_classify_attack_traffic must classify from traffic shape alone --
    it is never told which attack scenario (if any) was requested."""

    def test_flood_shaped_traffic_is_classified_as_dos(self, ctrl):
        flow = _flow(protocol="UDP", packet_count=300, packets_per_second=80.0,
                      unique_destination_ports=1, udp_packet_count=300)
        event = ctrl._classify_attack_traffic([flow])
        assert event.attack_type == "dos_flood"

    def test_scan_shaped_traffic_is_classified_as_reconnaissance(self, ctrl):
        flow = _flow(protocol="TCP", packet_count=13, packets_per_second=42.6,
                      unique_destination_ports=4, tcp_syn_count=13, tcp_ack_count=13)
        event = ctrl._classify_attack_traffic([flow])
        assert event.attack_type == "reconnaissance_port_scan"

    def test_benign_shaped_traffic_is_classified_as_normal(self, ctrl):
        flow = _flow(protocol="ICMP", packet_count=2, packets_per_second=1.0,
                      unique_destination_ports=0, icmp_packet_count=2)
        event = ctrl._classify_attack_traffic([flow])
        assert event.attack_type == "normal"

    def test_empty_capture_fails_safe_to_normal_rather_than_guessing(self, ctrl):
        event = ctrl._classify_attack_traffic([])
        assert event.attack_type == "normal"

    def test_classification_does_not_depend_on_flow_order_or_labeling(self, ctrl):
        """Two independently-shaped captures must classify independently --
        proves there is no hidden attack-mode state influencing the result."""
        dos_flow = _flow(protocol="UDP", packet_count=300, packets_per_second=80.0,
                          unique_destination_ports=1, udp_packet_count=300)
        recon_flow = _flow(protocol="TCP", packet_count=13, packets_per_second=42.6,
                            unique_destination_ports=4, tcp_syn_count=13, tcp_ack_count=13)
        first = ctrl._classify_attack_traffic([dos_flow])
        second = ctrl._classify_attack_traffic([recon_flow])
        assert first.attack_type == "dos_flood"
        assert second.attack_type == "reconnaissance_port_scan"


def _rf_event(attack_type: str, confidence: float) -> ThreatEvent:
    return ThreatEvent.from_result(
        source_ip="10.0.0.100", destination_ip="10.0.0.10", attack_type=attack_type,
        threat_score=confidence, confidence=confidence, detection_reason="test",
        features={}, detector_name="random-forest-flow-v1:RandomForestClassifier",
    )


class TestRandomForestConfirmationCannotVetoARealDetectionAtLowConfidence:
    """Regression coverage for a real live bug: RF, consulted only to
    confirm a rule-based reconnaissance detection, once reclassified a
    genuine, rule-verified port scan as "normal" at 50% confidence in a
    6-class model -- silently downgrading an already-detected real attack
    to no response, the one mistake a *confirmation* step must never
    make. RF may only override the rule-based verdict when it agrees, or
    disagrees with real confidence -- not a near coin-flip."""

    RECON_FLOW = _flow(protocol="TCP", packet_count=13, packets_per_second=42.6,
                        unique_destination_ports=4, tcp_syn_count=13, tcp_ack_count=13)

    def test_low_confidence_disagreement_keeps_the_rule_based_verdict(self, ctrl):
        with patch("iot_defense.ml.random_forest.RandomForestDetector") as MockRF:
            MockRF.return_value.detect.return_value = _rf_event("normal", 0.5)
            event = ctrl._classify_attack_traffic([self.RECON_FLOW])
        assert event.attack_type == "reconnaissance_port_scan"
        assert event.detector_name == "RuleBasedReconDetector"

    def test_high_confidence_disagreement_is_trusted(self, ctrl):
        with patch("iot_defense.ml.random_forest.RandomForestDetector") as MockRF:
            MockRF.return_value.detect.return_value = _rf_event("brute_force", 0.85)
            event = ctrl._classify_attack_traffic([self.RECON_FLOW])
        assert event.attack_type == "brute_force"

    def test_agreement_uses_the_rf_event_regardless_of_confidence(self, ctrl):
        with patch("iot_defense.ml.random_forest.RandomForestDetector") as MockRF:
            MockRF.return_value.detect.return_value = _rf_event("reconnaissance_port_scan", 0.4)
            event = ctrl._classify_attack_traffic([self.RECON_FLOW])
        assert event.attack_type == "reconnaissance_port_scan"
        assert event.detector_name == "random-forest-flow-v1:RandomForestClassifier"


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
