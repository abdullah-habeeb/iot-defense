"""Replaying recorded attacks through the whole live defender (evaluation/defender_replay.py).

Small generated captures in the lab's address range, the cheap Stackelberg policy and the synthetic outcome table:
no Mininet, no root, no model download.
"""

from __future__ import annotations

from scapy.all import IP, TCP, Ether, wrpcap

from iot_defense.defense.decision import DefenseAction
from iot_defense.evaluation import defender_replay as dr
from iot_defense.evaluation.outcome import OutcomeTable
from iot_defense.live.backend import SUPPORTED_ACTIONS

SENSOR = "10.0.0.10"
ATTACKER = "10.0.0.100"


def write_pcap(path, rows):
    packets = []
    for t, src, dst, dport, sport, flags, length in rows:
        p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
        p.time = t
        packets.append(p)
    wrpcap(str(path), packets)


def scan_rows(start=1000.0, ports=300, rate=100.0):
    return [(start + i / rate, ATTACKER, SENSOR, 1 + i, 50000 + i, 0x02, 60) for i in range(ports)]


def quiet_rows(start=1000.0):
    return [(start + i * 3.7, "10.0.0.20", SENSOR, 8080, 45000, 0x18, 300) for i in range(5)]


def test_a_scan_capture_is_decided_on_and_scored_against_the_live_best(tmp_path, synthetic_table_path):
    path = tmp_path / "trial000_reconnaissance_port_scan.pcap"
    write_pcap(path, scan_rows())
    outcome = dr.run_capture(path, "stackelberg", dr.CONFIGS[0][1], tmp_path)
    assert outcome is not None and outcome["decisions"]
    assert outcome["decisions"][0]["label"] == "reconnaissance_port_scan"
    table = OutcomeTable.from_jsonl(synthetic_table_path)
    scored = dr.score(table, "reconnaissance_port_scan", outcome["decisions"])
    assert scored["decided"] and scored["first_label_right"]
    assert DefenseAction(scored["best_live_action"]) in SUPPORTED_ACTIONS
    assert scored["final_regret"] >= 0.0


def test_a_capture_with_no_decision_is_reported_as_silent():
    assert dr.score(None, "dos_flood", []) == {"decided": False}


def test_ordinary_traffic_makes_no_decision(tmp_path):
    path = tmp_path / "trial000_normal.pcap"
    write_pcap(path, quiet_rows())
    outcome = dr.run_capture(path, "stackelberg", dr.CONFIGS[1][1], tmp_path)
    assert outcome is not None and outcome["decisions"] == []


def test_both_configurations_are_run_over_every_class_and_rendered(tmp_path, synthetic_table_path):
    write_pcap(tmp_path / "trial000_reconnaissance_port_scan.pcap", scan_rows())
    write_pcap(tmp_path / "trial000_normal.pcap", quiet_rows())
    result = dr.evaluate(tmp_path, synthetic_table_path, "stackelberg", per_class=2)
    assert list(result["configs"]) == ["before", "after"]
    for name in ("before", "after"):
        classes = result["configs"][name]["classes"]
        assert classes["normal"]["false_alarms"] == 0
        assert classes["reconnaissance_port_scan"]["decided"] == 1
    text = dr.render_markdown(result)
    assert "reconnaissance_port_scan" in text and "false alarms 0/1" in text
