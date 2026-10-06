"""Tests for the distributed attack variants: the spoofed-packet generator,
destination-aggregate detection, registry wiring and model coverage. No Mininet."""

from __future__ import annotations

import itertools
import socket
import struct
from unittest.mock import MagicMock, patch

import pytest

from iot_defense.attacks.registry import ATTACK_SCENARIOS
from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.objective import load_policy_section
from iot_defense.defense.policy import StackelbergDefensePolicy
from iot_defense.defense.ppo_env import TRAINING_SCENARIOS, context_for_scenario
from iot_defense.detection.detector import (
    UnifiedRuleBasedDetector,
    build_distributed_dos_detector,
    build_distributed_icmp_flood_detector,
    build_distributed_replay_detector,
    build_distributed_syn_flood_detector,
    destination_aggregates,
)
from iot_defense.detection.flow_features import FlowFeatures
from iot_defense.simulation.traffic import DISTRIBUTED_SOURCE_IPS, TrafficGenerator

DISTRIBUTED = {k: s for k, s in ATTACK_SCENARIOS.items() if not s.per_flow_detectable}


def flow(src, dst="10.0.0.10", protocol="UDP", packets=50, duration=1.0, size=100.0, **kw):
    return FlowFeatures(
        source_ip=src, destination_ip=dst, protocol=protocol, duration=duration, packet_count=packets,
        packets_per_second=packets / duration, bytes_total=int(size * packets), average_packet_size=size,
        unique_destination_ports=1, unique_source_ports=1, window_start=0.0, window_end=duration, **kw,
    )


def six_source_flows(**kw):
    return [flow(ip, **kw) for ip in DISTRIBUTED_SOURCE_IPS]


# ───────────────────────── the generator's packets ─────────────────────────


def ones_complement_ok(data: bytes) -> bool:
    if len(data) % 2:
        data += b"\x00"
    total = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return total == 0xFFFF


def run_flood(protocol, *, sources=DISTRIBUTED_SOURCE_IPS, duration=1, pps=40, payload=16, dst_port=9999):
    """Execute the exact script the Mininet host would run, against a fake raw
    socket, and return the packets it would have sent."""
    command = TrafficGenerator._spoofed_raw_flood_command(
        protocol=protocol, sources=sources, target_ip="10.0.0.10", dst_port=dst_port,
        duration_seconds=duration, total_pps=pps, payload_size=payload, marker="done_marker",
    )
    script = command.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    sent: list[bytes] = []
    fake_socket = MagicMock()
    fake_socket.sendto.side_effect = lambda packet, address: sent.append(packet)
    with patch("socket.socket", return_value=fake_socket), patch("time.sleep"), patch(
        "time.time", side_effect=itertools.count(0.0, 0.0005)
    ):
        namespace: dict = {}
        exec(compile(script, "<spoofed-flood>", "exec"), namespace)
    return sent


@pytest.mark.parametrize("protocol,ip_proto", [("UDP", socket.IPPROTO_UDP), ("ICMP", socket.IPPROTO_ICMP), ("TCP", socket.IPPROTO_TCP)])
class TestSpoofedPackets:
    def test_sends_the_requested_count_cycling_every_source(self, protocol, ip_proto):
        packets = run_flood(protocol, duration=1, pps=36)
        assert len(packets) == 36
        sources = [socket.inet_ntoa(p[12:16]) for p in packets]
        assert sources[: len(DISTRIBUTED_SOURCE_IPS)] == list(DISTRIBUTED_SOURCE_IPS)
        assert set(sources) == set(DISTRIBUTED_SOURCE_IPS)

    def test_ip_headers_are_valid_and_target_the_sensor(self, protocol, ip_proto):
        for packet in run_flood(protocol, duration=1, pps=12):
            assert packet[0] == 0x45 and packet[9] == ip_proto
            assert struct.unpack("!H", packet[2:4])[0] == len(packet)
            assert ones_complement_ok(packet[:20])
            assert socket.inet_ntoa(packet[16:20]) == "10.0.0.10"


class TestProtocolSpecifics:
    def test_udp_ports_and_length(self):
        packet = run_flood("UDP", dst_port=9999, payload=64, pps=6)[0]
        sport, dport, length, _ = struct.unpack("!HHHH", packet[20:28])
        assert dport == 9999 and length == 8 + 64 and len(packet) == 20 + length

    def test_icmp_is_an_echo_request_with_a_valid_checksum(self):
        for packet in run_flood("ICMP", payload=56, pps=12):
            assert packet[20] == 8 and packet[21] == 0
            assert ones_complement_ok(packet[20:])

    def test_tcp_is_syn_only_with_a_valid_pseudo_header_checksum(self):
        for packet in run_flood("TCP", dst_port=8080, payload=0, pps=12):
            tcp = packet[20:]
            assert struct.unpack("!H", tcp[2:4])[0] == 8080
            assert tcp[13] == 0x02, "SYN only"
            pseudo = packet[12:16] + packet[16:20] + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp))
            assert ones_complement_ok(pseudo + tcp)

    def test_generators_report_their_sources_and_use_the_attacker_host(self):
        net = MagicMock()
        for method, expected_protocol in (
            ("generate_dos_distributed_mininet_traffic", "UDP"),
            ("generate_syn_flood_distributed_mininet_traffic", "TCP"),
            ("generate_icmp_flood_distributed_mininet_traffic", "ICMP"),
        ):
            result = getattr(TrafficGenerator(), method)(net)
            assert result["spoofed_sources"] == list(DISTRIBUTED_SOURCE_IPS)
            net.get.assert_called_with("attacker")
            assert f"PROTOCOL = '{expected_protocol}'" in net.get.return_value.cmd.call_args[0][0]


# ───────────────────────────── aggregation ─────────────────────────────


class TestDestinationAggregates:
    def test_sums_flows_and_counts_distinct_sources(self):
        aggregates = destination_aggregates(six_source_flows(packets=50))
        assert len(aggregates) == 1
        agg = aggregates[0]
        assert agg["unique_source_ips"] == 6 and agg["packet_count"] == 300
        assert agg["packets_per_second"] == pytest.approx(300.0)
        assert agg["destination_ip"] == "10.0.0.10" and agg["protocol"] == "UDP"

    def test_a_single_source_is_left_to_the_per_flow_detectors(self):
        assert destination_aggregates([flow("10.0.0.100", packets=500)]) == []

    def test_groups_by_destination_and_protocol(self):
        flows = six_source_flows(protocol="UDP") + [flow(ip, protocol="TCP") for ip in ("10.0.0.20", "10.0.0.30")]
        aggregates = destination_aggregates(flows)
        assert {(a["protocol"], a["unique_source_ips"]) for a in aggregates} == {("UDP", 6), ("TCP", 2)}

    def test_representative_source_is_the_heaviest_one(self):
        flows = [flow("10.0.0.121", packets=5), flow("10.0.0.100", packets=90), flow("10.0.0.122", packets=5)]
        assert destination_aggregates(flows)[0]["source_ip"] == "10.0.0.100"

    def test_falls_back_to_flow_durations_without_a_window(self):
        flows = six_source_flows()
        for f in flows:
            f.window_start = f.window_end = None
        assert destination_aggregates(flows)[0]["packets_per_second"] == pytest.approx(300.0)


# ───────────────────────────── detection ─────────────────────────────


SIGNATURES = {
    "dos_flood_distributed": (build_distributed_dos_detector, dict(protocol="UDP", packets=60, duration=0.2, size=106.0)),
    "tcp_syn_flood_distributed": (build_distributed_syn_flood_detector, dict(protocol="TCP", packets=20, duration=0.5, size=54.0, tcp_syn_count=20)),
    "icmp_ping_flood_distributed": (build_distributed_icmp_flood_detector, dict(protocol="ICMP", packets=20, duration=0.5, size=98.0, icmp_packet_count=20)),
    "credential_replay_distributed": (build_distributed_replay_detector, dict(protocol="UDP", packets=3, duration=21.0, size=68.0)),
}


def aggregate_for(signature):
    return destination_aggregates(six_source_flows(**signature))[0]


class TestDistributedDetectors:
    @pytest.mark.parametrize("attack_type", SIGNATURES)
    def test_each_detector_flags_its_own_signature(self, attack_type):
        build, signature = SIGNATURES[attack_type]
        assert build().detect(aggregate_for(signature)).attack_type == attack_type

    def test_each_signature_is_claimed_by_exactly_one_detector(self):
        for attack_type, (_, signature) in SIGNATURES.items():
            aggregate = aggregate_for(signature)
            claimers = [t for t, (build, _) in SIGNATURES.items() if build().detect(aggregate).attack_type != "normal"]
            assert claimers == [attack_type]

    @pytest.mark.parametrize("attack_type", SIGNATURES)
    def test_too_few_sources_is_normal(self, attack_type):
        build, signature = SIGNATURES[attack_type]
        flows = [flow(ip, **signature) for ip in DISTRIBUTED_SOURCE_IPS[:3]]
        assert build().detect(destination_aggregates(flows)[0]).attack_type == "normal"

    @pytest.mark.parametrize("attack_type", SIGNATURES)
    def test_a_single_flow_is_never_distributed(self, attack_type):
        build, signature = SIGNATURES[attack_type]
        assert build().detect(flow("10.0.0.100", **signature).to_dict()).attack_type == "normal"

    def test_ordinary_two_peer_traffic_is_never_flagged(self):
        flows = [flow("10.0.0.20", packets=400, duration=2.0), flow("10.0.0.30", packets=400, duration=2.0)]
        event = UnifiedRuleBasedDetector().detect_flows(flows)
        assert not event.attack_type.endswith("_distributed")

    def test_event_carries_the_aggregate_features_the_policies_and_executor_use(self):
        build, signature = SIGNATURES["icmp_ping_flood_distributed"]
        event = build().detect(aggregate_for(signature))
        assert event.features["unique_source_ips"] == 6 and event.features["protocol"] == "ICMP"
        assert event.source_ip in DISTRIBUTED_SOURCE_IPS and event.destination_ip == "10.0.0.10"


class TestUnifiedSweep:
    def test_a_distributed_flood_is_labelled_distributed_not_as_the_plain_flood_its_slices_resemble(self):
        # each source alone is 300 packets in 1 s -- a textbook per-flow DoS
        flows = six_source_flows(packets=300, duration=1.0, size=106.0)
        assert UnifiedRuleBasedDetector().detect(flows[0].to_dict()).attack_type == "dos_flood"
        assert UnifiedRuleBasedDetector().detect_flows(flows).attack_type == "dos_flood_distributed"

    def test_a_single_source_flood_is_still_a_plain_flood(self):
        assert UnifiedRuleBasedDetector().detect_flows([flow("10.0.0.100", packets=300, duration=1.0, size=106.0)]).attack_type == "dos_flood"

    @pytest.mark.parametrize("attack_type", SIGNATURES)
    def test_every_signature_is_recognized_through_detect_flows(self, attack_type):
        _, signature = SIGNATURES[attack_type]
        assert UnifiedRuleBasedDetector().detect_flows(six_source_flows(**signature)).attack_type == attack_type


# ───────────────────────────── registry & models ─────────────────────────────


class TestRegistryWiring:
    def test_four_distributed_variants_are_registered(self):
        assert {s.attack_type for s in DISTRIBUTED.values()} == set(SIGNATURES)

    def test_they_are_inbound_multi_source_and_start_with_the_real_attacker(self):
        for scenario in DISTRIBUTED.values():
            assert scenario.traffic_direction == "inbound"
            assert scenario.sender_ips == DISTRIBUTED_SOURCE_IPS and len(set(scenario.sender_ips)) >= 4
            assert scenario.sender_ips[0] == "10.0.0.100"

    def test_everything_else_stays_per_flow_detectable_single_sender(self):
        for key, scenario in ATTACK_SCENARIOS.items():
            if key not in DISTRIBUTED:
                assert scenario.per_flow_detectable and scenario.sender_ips == ()

    def test_distributed_variants_are_registered_after_every_other_attack(self):
        keys = list(ATTACK_SCENARIOS)
        assert keys[-len(DISTRIBUTED):] == list(DISTRIBUTED)

    def test_they_are_excluded_from_the_per_flow_ml_pipeline_but_present_for_policies(self):
        from iot_defense.ml.generate_dataset import _ATTACK_KEYS
        from iot_defense.ml.schema import LABEL_NAMES

        assert not set(DISTRIBUTED) & set(_ATTACK_KEYS)
        assert not {s.attack_type for s in DISTRIBUTED.values()} & set(LABEL_NAMES.values())
        assert {s.attack_type for s in DISTRIBUTED.values()} <= set(TRAINING_SCENARIOS())

    def test_example_features_carry_the_source_count_so_the_detector_sweep_applies(self):
        for scenario in DISTRIBUTED.values():
            assert scenario.ppo_example_features["unique_source_ips"] >= 4


class TestModelsKnowTheNewClasses:
    def test_game_model_classifies_every_variant(self):
        classes = load_policy_section("game_model")["attack_class"]
        assert {classes[s.attack_type] for s in DISTRIBUTED.values()} == {"distributed_flood", "distributed_trickle"}

    def test_a_per_source_block_is_not_expected_to_contain_a_distributed_flood(self):
        priors = load_policy_section("game_model")["containment_prior"]
        assert priors["BLOCK_SOURCE"]["distributed_flood"] < priors["BLOCK_SOURCE"]["flood"]
        assert priors["BLOCK_SOURCE"]["distributed_flood"] < priors["QUARANTINE"]["distributed_flood"]
        assert priors["THROTTLE"]["distributed_trickle"] == 0.0 < priors["THROTTLE"]["distributed_flood"]

    def test_stackelberg_does_not_reach_for_the_source_block_on_a_distributed_flood(self):
        policy = StackelbergDefensePolicy()
        for attack_type in ("dos_flood_distributed", "tcp_syn_flood_distributed", "icmp_ping_flood_distributed"):
            assert policy.decide(context_for_scenario(attack_type)).action != DefenseAction.BLOCK_SOURCE
