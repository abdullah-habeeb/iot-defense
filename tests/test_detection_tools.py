"""Detector evaluation tools (evaluation/detection_report.py, evaluation/pcap_replay.py).

Synthetic traffic only: no Mininet, no root, no network. Real captures are exercised by running the tools themselves.
"""

from __future__ import annotations

import json

import pytest
from scapy.all import IP, TCP, Ether, wrpcap

from iot_defense.evaluation import detection_report as dr
from iot_defense.evaluation import pcap_replay as pr

BOX = "192.168.43.10"
PHONE = "192.168.43.20"
ATTACKER = "192.168.43.50"


def packet(src, dst, t, dport, sport=40000, flags=0x02, length=60):
    return {
        "timestamp": t, "src_ip": src, "dst_ip": dst, "protocol": "TCP", "src_port": sport, "dst_port": dport,
        "packet_length": length, "ttl": 64, "direction": "inbound", "tcp_flags": flags,
        "display_src": src, "display_dst": dst, "display_protocol": "TCP", "background": False,
    }


def scan(start=100.0, ports=300, rate=100.0):
    return [packet(ATTACKER, BOX, start + i / rate, 1 + i, sport=50000 + i) for i in range(ports)]


def browsing(start=100.0, seconds=60, poll=2.0):
    events = []
    for i in range(int(seconds / poll)):
        t = start + i * poll
        events.append(packet(PHONE, BOX, t, 8080, sport=45000, flags=0x18, length=350))
        events.append(packet(PHONE, BOX, t + 0.05, 8080, sport=45000, flags=0x10, length=52))
    return events


# ── statistics ────────────────────────────────────────────────────────────────
def test_wilson_interval_brackets_the_proportion_and_widens_with_few_samples():
    low, high = dr.wilson(8, 10)
    assert low < 0.8 < high
    narrow = dr.wilson(800, 1000)
    assert (high - low) > (narrow[1] - narrow[0])


def test_wilson_with_no_failures_still_leaves_room_for_a_real_rate():
    low, high = dr.wilson(0, 20)
    assert low == 0.0 and 0.1 < high < 0.2  # zero false alarms in 20 does not prove a rate of zero


def test_wilson_with_nothing_to_measure_says_so():
    assert dr.wilson(0, 0) == (0.0, 1.0)


def test_per_class_precision_and_recall_come_from_the_confusions():
    pairs = [("scan", "scan")] * 3 + [("scan", "normal")] + [("normal", "scan")] + [("normal", "normal")] * 5
    stats = dr.per_class(pairs, ["scan", "normal"])
    assert stats["scan"]["tp"] == 3 and stats["scan"]["fn"] == 1 and stats["scan"]["fp"] == 1
    assert stats["scan"]["recall"] == pytest.approx(0.75)
    assert stats["scan"]["precision"] == pytest.approx(0.75)
    assert stats["normal"]["recall"] == pytest.approx(5 / 6)


def test_a_class_with_no_samples_has_no_metrics_rather_than_a_fake_zero():
    stats = dr.per_class([("a", "a")], ["a", "b"])
    assert stats["b"]["support"] == 0 and stats["b"]["recall"] is None and stats["b"]["precision"] is None


def test_false_alarm_summary_counts_only_benign_samples():
    summary = dr.false_alarm_summary([("normal", "normal")] * 9 + [("normal", "dos_flood"), ("dos_flood", "dos_flood")])
    assert summary["benign_samples"] == 10 and summary["flagged"] == 1
    assert summary["rate"] == pytest.approx(0.1)
    assert summary["ci"][0] < 0.1 < summary["ci"][1]


# ── replay ────────────────────────────────────────────────────────────────────
def test_a_scan_is_acted_on_and_the_delay_is_measured_from_its_first_packet():
    result = pr.replay(scan(), [BOX])
    assert result["acted_on"], "a 300-port sweep should be acted on"
    assert 0.0 <= result["first_action_delay_seconds"] <= 10.0
    assert result["acted_on"][0]["source_ip"] == ATTACKER


def test_a_short_burst_is_still_acted_on_because_the_defender_keeps_checking_while_it_is_in_the_window():
    burst = scan(ports=300, rate=1000.0)  # the whole attack lasts 0.3 s, then the recording ends
    result = pr.replay(burst, [BOX])
    assert result["acted_on"], "the defender checks every second for as long as the burst is in its window"
    assert result["first_action_delay_seconds"] <= 3.0


def test_ordinary_browsing_is_never_acted_on():
    result = pr.replay(browsing(), [BOX])
    assert result["acted_on"] == [] and result["acted_on_per_hour"] == 0.0
    assert result["first_action_delay_seconds"] is None


def test_an_empty_recording_has_nothing_to_report():
    result = pr.replay([], [BOX])
    assert result["packets"] == 0 and result["acted_on"] == []


def test_the_confirmation_requirement_changes_what_is_acted_on():
    strict = pr.replay(scan(), [BOX], confirm_ticks=2)
    lenient = pr.replay(scan(), [BOX], confirm_ticks=1)
    assert len(lenient["acted_on"]) >= len(strict["acted_on"])


def test_protected_addresses_can_be_found_from_a_subnet():
    events = scan(ports=5) + [packet(PHONE, "8.8.8.8", 100.0, 53)]
    assert pr.protected_from_subnet(events, "192.168.43.0/24") == {BOX}


# ── pcap round trip ───────────────────────────────────────────────────────────
def write_pcap(path, events):
    packets = []
    for e in events:
        p = Ether() / IP(src=e["src_ip"], dst=e["dst_ip"]) / TCP(sport=e["src_port"], dport=e["dst_port"], flags=e["tcp_flags"])
        p.time = e["timestamp"]
        packets.append(p)
    wrpcap(str(path), packets)


def test_a_pcap_round_trips_into_the_same_events(tmp_path):
    path = tmp_path / "scan.pcap"
    write_pcap(path, scan(ports=20))
    events = pr.read_events(path, BOX)
    assert len(events) == 20
    assert {e["dst_ip"] for e in events} == {BOX} and {e["src_ip"] for e in events} == {ATTACKER}
    assert pr.read_events(path, BOX, limit=5) and len(pr.read_events(path, BOX, limit=5)) == 5


def test_captures_are_scored_against_the_scenario_in_their_file_name(tmp_path):
    lab_scan = [packet("10.0.0.100", "10.0.0.10", 100.0 + i * 0.1, 20 + i, sport=50000 + i) for i in range(12)]
    quiet = [packet("10.0.0.20", "10.0.0.10", 100.0 + i, 8080, sport=45000, flags=0x18, length=300) for i in range(4)]
    write_pcap(tmp_path / "trial000_reconnaissance_port_scan.pcap", lab_scan)
    write_pcap(tmp_path / "trial000_normal.pcap", quiet)
    (tmp_path / "notes.txt").write_text("not a capture")
    result = dr.evaluate_captures(tmp_path)
    assert result["captures"] == 2
    by_truth = {c: v for c, v in result["per_class"].items()}
    assert by_truth["normal"]["support"] == 1 and by_truth["reconnaissance_port_scan"]["support"] == 1
    assert result["false_alarms"]["benign_samples"] == 1
    json.dumps(result)  # the report must serialise


def test_an_empty_capture_is_skipped_and_reported_not_a_crash(tmp_path):
    write_pcap(tmp_path / "trial000_normal.pcap", [packet("10.0.0.20", "10.0.0.10", 100.0, 8080, sport=45000, flags=0x18, length=300)])
    (tmp_path / "trial001_normal.pcap").write_bytes(b"")
    result = dr.evaluate_captures(tmp_path)
    assert result["captures"] == 1
    assert result["unreadable_captures"] == ["trial001_normal.pcap"]


def test_the_label_timeline_reports_each_class_under_each_configuration(tmp_path):
    lab_scan = [packet("10.0.0.100", "10.0.0.10", 100.0 + i * 0.1, 20 + i, sport=50000 + i) for i in range(12)]
    quiet = [packet("10.0.0.20", "10.0.0.10", 100.0 + i, 8080, sport=45000, flags=0x18, length=300) for i in range(4)]
    write_pcap(tmp_path / "trial000_reconnaissance_port_scan.pcap", lab_scan)
    write_pcap(tmp_path / "trial000_normal.pcap", quiet)
    timeline = dr.label_timeline(tmp_path)
    assert [c["name"] for c in timeline["configs"]] == ["before", "after"]
    assert set(timeline["classes"]) == {"reconnaissance_port_scan", "normal"}
    for config in ("before", "after"):
        assert timeline["classes"]["normal"]["by_config"][config]["acted_on"] == 0
        row = timeline["classes"]["reconnaissance_port_scan"]["by_config"][config]
        assert 0 <= row["right_at_action"] <= row["acted_on"] <= 1
    json.dumps(timeline)
    assert "Is the attack named correctly" in dr.render_markdown({
        "captures": dr.evaluate_captures(tmp_path),
        "flow_table": {"rule_based": {"accuracy": 1.0, "accuracy_ci": (0, 1), "per_class": {}}, "random_forest_cv": {"accuracy": 1.0, "accuracy_ci": (0, 1), "per_class": {}}, "folds": 5},
        "live_harness": {"trials": 1, "accuracy": 1.0, "accuracy_ci": (0, 1), "per_class": {}, "false_alarms": {"flagged": 0, "benign_samples": 0}, "confusions": {}, "whole_observation_ms": {"median": 1.0}},
        "label_timeline": timeline,
    })


def test_the_harness_log_is_read_once_per_trial_not_once_per_arm(tmp_path):
    rows = []
    for trial, (truth, seen) in enumerate([("dos_flood", "dos_flood"), ("normal", "normal"), ("dos_flood", "normal")]):
        for arm in ("rule_based", "stackelberg", "ppo"):
            rows.append({"arm": arm, "trial": trial, "ground_truth_attack_type": truth, "detected_attack_type": seen, "detection_latency_ms": 3000.0 + trial})
    path = tmp_path / "harness.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows))
    result = dr.evaluate_harness(path)
    assert result["trials"] == 3
    assert result["accuracy"] == pytest.approx(2 / 3)
    assert result["per_class"]["dos_flood"]["fn"] == 1
    assert "not a time-to-detect" in result["whole_observation_ms"]["note"]
