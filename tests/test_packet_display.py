"""Packet labelling for the dashboard feed.

Regression coverage for a real bug: the dashboard's "Live Packet Feed" showed
rows of unknown / unknown / UNKNOWN for a data-exfiltration run. Two causes:

* PacketMonitor.read_capture() only understood IPv4 and ARP, so the IPv6
  neighbour-discovery / multicast chatter Linux emits whenever a virtual
  interface comes up was labelled "unknown" instead of described;
* the controller built the feed as (baseline + attack)[:20], and the baseline
  alone already filled all 20 slots, so the attack's own packets were never
  shown.

The labelling is display-only: src_ip / dst_ip / protocol keep the values
FeatureAggregator keys flows on, so detection is unchanged.
"""

from __future__ import annotations

import pytest

scapy = pytest.importorskip("scapy.all")
from scapy.all import ARP, ICMPv6ND_NS, IP, IPv6, TCP, Ether, wrpcap  # noqa: E402

from iot_defense.agents.monitoring_agent import MonitoringAgent  # noqa: E402
from iot_defense.demo.controller import DemoController  # noqa: E402
from iot_defense.detection.flow_features import FeatureAggregator  # noqa: E402
from iot_defense.monitoring.monitor import PacketMonitor  # noqa: E402


class _NoHostNet:
    def get(self, name):
        raise KeyError(name)


def _read(tmp_path, packets):
    path = tmp_path / "capture.pcap"
    wrpcap(str(path), packets)
    return PacketMonitor(base_dir=str(tmp_path)).read_capture(_NoHostNet(), "sensor", str(path))


def _packets():
    return [
        Ether() / IP(src="10.0.0.10", dst="10.0.0.100", ttl=64) / TCP(sport=40000, dport=443, flags="S"),
        Ether() / ARP(psrc="10.0.0.10", pdst="10.0.0.20"),
        Ether() / IPv6(src="fe80::1", dst="ff02::2") / ICMPv6ND_NS(tgt="fe80::2"),
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02"),
    ]


def test_ipv6_housekeeping_is_described_not_unknown(tmp_path):
    events = _read(tmp_path, _packets())
    nd = next(e for e in events if e["display_protocol"] == "ICMPv6")
    assert nd["display_src"] == "fe80::1"
    assert nd["display_dst"] == "ff02::2"
    assert nd["background"] is True


def test_real_traffic_keeps_its_labels_and_is_not_background(tmp_path):
    events = _read(tmp_path, _packets())
    tcp = next(e for e in events if e["protocol"] == "TCP")
    assert (tcp["display_src"], tcp["display_dst"], tcp["display_protocol"]) == ("10.0.0.10", "10.0.0.100", "TCP")
    assert tcp["background"] is False
    arp = next(e for e in events if e["protocol"] == "ARP")
    assert arp["display_src"] == "10.0.0.10"
    assert arp["background"] is False


def test_link_layer_only_frame_falls_back_to_mac_addresses(tmp_path):
    events = _read(tmp_path, _packets())
    bare = next(e for e in events if e["display_src"] == "02:00:00:00:00:01")
    assert bare["display_dst"] == "02:00:00:00:00:02"
    assert bare["background"] is True


def test_pipeline_fields_are_unchanged_so_detection_is_unaffected(tmp_path):
    events = _read(tmp_path, _packets())
    nd = next(e for e in events if e["display_protocol"] == "ICMPv6")
    # Still what FeatureAggregator has always seen for a non-IPv4 packet.
    assert nd["src_ip"] == "unknown" and nd["dst_ip"] == "unknown" and nd["protocol"] == "UNKNOWN"
    observed = [MonitoringAgent().observe(e) for e in events]
    flows = FeatureAggregator().aggregate(observed)
    assert {(f.source_ip, f.destination_ip) for f in flows} == {("10.0.0.10", "10.0.0.100"), ("10.0.0.10", "10.0.0.20")}


def test_monitoring_agent_carries_display_fields_and_defaults_them():
    agent = MonitoringAgent()
    carried = agent.observe(
        {"src_ip": "unknown", "dst_ip": "unknown", "protocol": "UNKNOWN",
         "display_src": "fe80::1", "display_dst": "ff02::2", "display_protocol": "ICMPv6", "background": True}
    )
    assert carried["display_src"] == "fe80::1" and carried["background"] is True
    legacy = agent.observe({"src_ip": "10.0.0.10", "dst_ip": "10.0.0.20", "protocol": "TCP"})
    assert (legacy["display_src"], legacy["display_protocol"], legacy["background"]) == ("10.0.0.10", "TCP", False)


def _pkt(i, background=False):
    return {"timestamp": float(i), "background": background}


def test_feed_shows_latest_real_traffic_and_counts_hidden_background():
    packets = [_pkt(i, background=(i % 2 == 0)) for i in range(60)]
    shown, hidden = DemoController._feed_sample(packets, limit=20)
    assert len(shown) == 20 and not any(p["background"] for p in shown)
    assert shown[-1]["timestamp"] == 59.0  # the most recent real packet
    assert hidden == 30


def test_feed_with_only_background_falls_back_instead_of_going_empty():
    packets = [_pkt(i, background=True) for i in range(5)]
    shown, hidden = DemoController._feed_sample(packets)
    assert len(shown) == 5 and hidden == 0


def test_feed_of_an_empty_capture_is_empty():
    assert DemoController._feed_sample([]) == ([], 0)


def test_attack_packets_are_not_crowded_out_by_the_baseline():
    # The old (baseline + attack)[:20] returned only baseline packets.
    baseline = [dict(_pkt(i), phase="baseline") for i in range(20)]
    attack = [dict(_pkt(100 + i), phase="attack") for i in range(8)]
    shown, _ = DemoController._feed_sample(attack)
    assert all(p["phase"] == "attack" for p in shown)
    assert all(p["phase"] == "baseline" for p in (baseline + attack)[:20])  # what the bug did
