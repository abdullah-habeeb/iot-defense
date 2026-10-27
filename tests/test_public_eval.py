"""Both-direction detection, streaming replay and the public-dataset evaluation (evaluation/public_eval.py).

Synthetic traffic and tiny generated pcaps only: no download, no Mininet, no root.
"""

from __future__ import annotations

import json

import pytest
from scapy.all import IP, TCP, Ether, wrpcap

from iot_defense.evaluation import pcap_replay as pr
from iot_defense.evaluation import public_eval as pe
from iot_defense.live.window import WindowedDetector

DEVICE = "192.168.1.50"
REMOTE = "93.184.216.34"
SCANNER = "45.33.32.156"


def packet(src, dst, t, dport, sport=40000, flags=0x02, length=60):
    return {
        "timestamp": t, "src_ip": src, "dst_ip": dst, "protocol": "TCP", "src_port": sport, "dst_port": dport,
        "packet_length": length, "ttl": 64, "direction": "unknown", "tcp_flags": flags,
        "display_src": src, "display_dst": dst, "display_protocol": "TCP", "background": False,
    }


def write_pcap(path, events):
    packets = []
    for e in events:
        p = Ether() / IP(src=e["src_ip"], dst=e["dst_ip"]) / TCP(sport=e["src_port"], dport=e["dst_port"], flags=e["tcp_flags"])
        p.time = e["timestamp"]
        packets.append(p)
    wrpcap(str(path), packets)


def scan_in(start=1000.0, ports=300, rate=100.0):
    return [packet(SCANNER, DEVICE, start + i / rate, 1 + i, sport=50000 + i) for i in range(ports)]


def quiet(start=1000.0, seconds=120, regular=False):
    """Ordinary traffic: a request now and then at irregular gaps (or, with `regular`, on a fixed schedule)."""
    import random

    rng = random.Random(5)
    events, t = [], start
    while t < start + seconds:
        events.append(packet("10.0.0.1", DEVICE, t, 443, sport=45000, flags=0x18, length=200))
        events.append(packet(DEVICE, "10.0.0.1", t + 0.02, 45000, sport=443, flags=0x10, length=66))
        t += 4.0 if regular else rng.uniform(1.5, 9.0)
    return events


# ── the window's two views ────────────────────────────────────────────────────
def test_inbound_mode_ignores_what_the_protected_host_sends():
    window = WindowedDetector([DEVICE])
    assert window.ingest(packet(REMOTE, DEVICE, 1.0, 80))
    assert not window.ingest(packet(DEVICE, REMOTE, 1.1, 80))


def test_both_mode_keeps_traffic_in_either_direction_and_names_the_far_side():
    window = WindowedDetector([DEVICE], directions="both")
    inbound, outbound = packet(REMOTE, DEVICE, 1.0, 80), packet(DEVICE, REMOTE, 1.1, 80)
    assert window.ingest(inbound) and window.ingest(outbound)
    assert window.peer(inbound) == REMOTE and window.peer(outbound) == REMOTE
    assert not window.ingest(packet("10.9.9.9", "10.9.9.8", 1.2, 80)), "traffic that does not touch a protected host is not ours"
    assert not window.ingest(packet(DEVICE, "255.255.255.255", 1.3, 67)), "a broadcast is not a peer"


def test_an_unknown_direction_mode_is_refused():
    with pytest.raises(ValueError):
        WindowedDetector([DEVICE], directions="sideways")


def test_ignoring_a_source_means_ignoring_its_traffic_in_both_directions():
    window = WindowedDetector([DEVICE], window_seconds=60.0, directions="both")
    for e in scan_in(ports=300):
        window.ingest(e)
    assert window.evaluate(1003.0) is not None
    assert window.evaluate(1003.0, ignore_sources={SCANNER}) is None
    assert window.window_events(1003.0, {SCANNER})


def test_a_device_sending_a_lot_out_is_seen_only_in_both_mode():
    out = [packet(DEVICE, REMOTE, 1000.0 + i * 0.3, 8443, sport=50000, flags=0x18, length=1200) for i in range(12)]
    inbound_only = WindowedDetector([DEVICE], window_seconds=60.0)
    both = WindowedDetector([DEVICE], window_seconds=60.0, directions="both")
    for e in out:
        inbound_only.ingest(e)
        both.ingest(e)
    assert inbound_only.evaluate(1004.0) is None
    seen = both.evaluate(1004.0)
    assert seen is not None and seen.attack_type == "data_exfiltration"


def test_an_outbound_threat_is_attributed_to_the_remote_party_not_the_protected_host():
    out = [packet(DEVICE, REMOTE, 1000.0 + i * 0.3, 8443, sport=50000, flags=0x18, length=1200) for i in range(12)]
    window = WindowedDetector([DEVICE], window_seconds=60.0, directions="both")
    for e in out:
        window.ingest(e)
    threat = window.evaluate(1004.0)
    assert threat is not None
    assert threat.source_ip == REMOTE and threat.destination_ip == DEVICE
    assert window.evaluate(1004.0, ignore_sources={REMOTE}) is None, "a cooldown on the remote party silences it"


# ── streaming replay ──────────────────────────────────────────────────────────
def test_streaming_a_scan_pcap_acts_on_it(tmp_path):
    path = tmp_path / "scan.pcap"
    write_pcap(path, scan_in())
    result = pr.stream_replay(path, {DEVICE}, window_seconds=10.0)
    assert result["acted_on"] and result["acted_on_by_attack"].get("reconnaissance_port_scan")
    assert result["first_action_delay_seconds"] is not None and result["first_action_delay_seconds"] < 5


def test_streaming_ordinary_traffic_raises_no_alarm_and_skips_quiet_gaps(tmp_path):
    path = tmp_path / "quiet.pcap"
    events = quiet(seconds=60) + quiet(start=5000.0, seconds=60)  # an hour of silence between them
    write_pcap(path, events)
    result = pr.stream_replay(path, {DEVICE}, window_seconds=60.0)
    assert result["flagged_checks"] == 0 and result["acted_on"] == []
    assert result["duration_seconds"] > 4000  # the gap is part of the recording, but is not walked second by second


def test_traffic_on_a_perfectly_fixed_schedule_is_flagged_in_a_long_window(tmp_path):
    """Recorded on purpose: near-uniform spacing is what the rules look for in an attack, so a device that really
    does poll on a fixed timer (a heartbeat, a keep-alive) is the false alarm to watch for on real traffic. (The
    rules call this synthetic pattern an MQTT flood; the name matters less than that it is flagged at all.)"""
    path = tmp_path / "timer.pcap"
    write_pcap(path, quiet(seconds=120, regular=True))
    assert pr.stream_replay(path, {DEVICE}, window_seconds=60.0)["acted_on"]


def test_streaming_and_in_memory_replay_agree_on_the_same_capture(tmp_path):
    path = tmp_path / "scan.pcap"
    write_pcap(path, scan_in())
    streamed = pr.stream_replay(path, {DEVICE}, window_seconds=10.0, directions="inbound")
    loaded = pr.replay(pr.read_events(path), {DEVICE}, window_seconds=10.0, directions="inbound")
    assert streamed["acted_on_by_attack"] == loaded["acted_on_by_attack"]


def test_the_cheap_event_carries_what_the_detectors_read(tmp_path):
    path = tmp_path / "one.pcap"
    write_pcap(path, [packet(SCANNER, DEVICE, 1000.0, 22, sport=51000)])
    light = next(pr.iter_light_events(path))
    full = pr.read_events(path)[0]
    for key in ("timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "packet_length", "tcp_flags"):
        assert light[key] == full[key], key


def test_the_busiest_private_address_is_the_device(tmp_path):
    path = tmp_path / "quiet.pcap"
    write_pcap(path, quiet(seconds=40))
    assert pr.busiest_private_address(path) in {DEVICE, "10.0.0.1"}


# ── IoT-23 labelled logs ──────────────────────────────────────────────────────
CONN_HEADER = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\tlabel\tdet_label"


def conn_row(ts, orig, resp, duration, label, detail):
    return "\t".join([str(ts), "Cabc", orig, "40000", resp, "23", "tcp", "-", str(duration), "0", "0", "S0", "-", "-", "0", "S", "3", "180", "0", "0", "-", label, detail])


def write_log(path, rows):
    path.write_text("#separator \\x09\n" + CONN_HEADER + "\n" + "\n".join(rows) + "\n")


def test_a_labelled_log_is_read_with_its_times_and_labels(tmp_path):
    log = tmp_path / "conn.log.labeled"
    write_log(log, [conn_row(1000.0, SCANNER, DEVICE, 2.5, "Malicious", "PartOfAHorizontalPortScan"), conn_row(1010.0, DEVICE, REMOTE, "-", "Benign", "-")])
    rows = pe.read_conn_labels(log)
    assert len(rows) == 2
    assert rows[0]["end"] == pytest.approx(1002.5) and rows[0]["label"] == "Malicious" and rows[0]["detail"] == "PartOfAHorizontalPortScan"
    assert rows[1]["end"] == rows[1]["start"]
    assert pe.busiest_in_conns(rows) == DEVICE


def test_a_log_whose_last_cell_joins_the_labels_with_spaces_is_read_too(tmp_path):
    log = tmp_path / "conn.log.labeled"
    header = CONN_HEADER.replace("tunnel_parents\tlabel\tdet_label", "tunnel_parents   label   detailed-label")
    base = "\t".join(["1000.0", "Cabc", SCANNER, "40000", DEVICE, "23", "tcp", "-", "3.0", "0", "0", "S0", "-", "-", "0", "S", "3", "180", "0", "0"])
    lines = [header, base + "\t(empty)   Benign   -", base + "\t-   Malicious   C&C-HeartBeat"]
    log.write_text("\n".join(lines) + "\n")
    rows = pe.read_conn_labels(log)
    assert [r["label"] for r in rows] == ["Benign", "Malicious"]
    assert [r["detail"] for r in rows] == ["-", "C&C-HeartBeat"]


def test_a_scan_labelled_as_a_scan_is_noticed_and_named_right(tmp_path):
    pcap, log = tmp_path / "m.pcap", tmp_path / "m.conn.log.labeled"
    events = scan_in(ports=300)
    write_pcap(pcap, events)
    write_log(log, [conn_row(1000.0, SCANNER, DEVICE, 3.0, "Malicious", "PartOfAHorizontalPortScan")])
    result = pe.evaluate_malicious(pcap, log, window_seconds=10.0)
    assert result["protected"] == DEVICE
    assert result["recall_by_second"] == 1.0 and result["justified_alarms"] > 0
    assert result["recall_by_connection"] == 1.0 and result["malicious_connections_in_capture"] == 1
    assert result["connections_by_label"]["PartOfAHorizontalPortScan"]["noticed"] == 1
    assert result["name_agrees"] > 0 and result["name_disagrees"] == 0
    assert result["recall_by_label"]["PartOfAHorizontalPortScan"]["recall"] == 1.0
    json.dumps(result, default=str)


def test_an_alarm_with_nothing_malicious_labelled_is_a_false_alarm(tmp_path):
    pcap, log = tmp_path / "m.pcap", tmp_path / "m.conn.log.labeled"
    write_pcap(pcap, scan_in(ports=300))
    write_log(log, [conn_row(1000.0, DEVICE, REMOTE, 3.0, "Benign", "-")])
    result = pe.evaluate_malicious(pcap, log, window_seconds=10.0)
    assert result["malicious_connections"] == 0 and result["malicious_seconds"] == 0
    assert result["justified_alarms"] == 0 and result["false_alarm_checks"] == result["flagged_checks"] > 0


def test_a_run_inside_a_block_is_not_a_new_firewall_action():
    runs = [{"source_ip": "a", "attack_type": "x", "start": 100.0, "checks": 3},
            {"source_ip": "a", "attack_type": "x", "start": 130.0, "checks": 2},   # inside the 60 s block
            {"source_ip": "a", "attack_type": "x", "start": 200.0, "checks": 2},   # block expired
            {"source_ip": "b", "attack_type": "x", "start": 110.0, "checks": 2}]   # another source
    kept = pr.dedupe_actions(runs, confirm_ticks=2, step=1.0)
    assert [(r["source_ip"], r["start"]) for r in kept] == [("a", 100.0), ("b", 110.0), ("a", 200.0)]


def test_the_scoring_window_is_independent_of_the_detectors_window(tmp_path):
    pcap, log = tmp_path / "m.pcap", tmp_path / "m.conn.log.labeled"
    write_pcap(pcap, scan_in(ports=300))
    write_log(log, [conn_row(1000.0, SCANNER, DEVICE, 3.0, "Malicious", "PartOfAHorizontalPortScan")])
    short = pe.evaluate_malicious(pcap, log, window_seconds=5.0, match_window=60.0)
    long_ = pe.evaluate_malicious(pcap, log, window_seconds=60.0, match_window=60.0)
    assert short["match_window"] == long_["match_window"] == 60.0
    assert short["recall_by_connection"] == 1.0 and long_["recall_by_connection"] == 1.0
    # the connection's label is a port scan and the alarm is called one, so it is also noticed under its own name
    assert long_["named_connections"] == 1 and long_["recall_named_by_connection"] == 1.0
    assert long_["actions"] >= 1 and long_["alarm_list"]
    json.dumps(long_, default=str)


def test_a_connection_whose_label_has_no_equivalent_is_not_counted_as_named(tmp_path):
    pcap, log = tmp_path / "m.pcap", tmp_path / "m.conn.log.labeled"
    write_pcap(pcap, scan_in(ports=300))
    write_log(log, [conn_row(1000.0, SCANNER, DEVICE, 3.0, "Malicious", "Okiru")])
    result = pe.evaluate_malicious(pcap, log, window_seconds=10.0)
    assert result["named_connections"] == 0 and result["recall_named_by_connection"] is None
    assert result["recall_by_connection"] == 1.0


def test_benign_traffic_is_scored_per_hour(tmp_path):
    pcap = tmp_path / "benign.pcap"
    write_pcap(pcap, quiet(seconds=120))
    result = pe.evaluate_benign(pcap, window_seconds=60.0)
    assert result["acted_on"] == 0 and result["flagged_checks"] == 0
    assert result["acted_on_per_hour"] == 0.0 and result["duration_hours"] >= 0.0


def test_the_report_renders_every_section():
    report = {
        "window_seconds": 60.0, "directions": "both",
        "benign": [{"capture": "b.pcap", "protected": DEVICE, "packets": 10, "duration_hours": 1.0, "flagged_checks": 0, "flagged_checks_per_hour": 0.0,
                    "acted_on": 0, "acted_on_per_hour": 0.0, "alarm_names": {}}],
        "malicious": [{"capture": "m.pcap", "protected": DEVICE, "packets": 10, "malicious_seconds": 5, "recall_by_second": 0.8, "recall_ci": (0.4, 0.97),
                       "flagged_checks": 3, "justified_alarms": 3, "false_alarm_checks": 0, "false_alarm_checks_per_hour": 0.0,
                       "recall_by_label": {"DDoS": {"seconds": 5, "noticed": 4, "recall": 0.8}}, "name_agrees": 1,
                       "malicious_connections_in_capture": 4, "recall_by_connection": 0.75, "recall_by_connection_ci": (0.3, 0.95),
                       "connections_by_label": {"DDoS": {"connections": 4, "noticed": 3, "recall": 0.75}}, "name_disagrees": 1, "name_unmapped": 1,
                       "alarm_names": {"dos_flood": 3}}],
    }
    text = pe.render_markdown(report)
    for fragment in ("Benign traffic", "Malware traffic", "DDoS", "Label mapping used", "Named a plausible equivalent"):
        assert fragment in text
