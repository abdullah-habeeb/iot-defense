from iot_defense.detection.detector import RuleBasedReconDetector
from iot_defense.detection.flow_features import FeatureAggregator


def test_normal_udp_flow_preserves_source_and_destination_ips():
    events = [
        {
            "timestamp": 1.0,
            "src_ip": "10.0.0.20",
            "dst_ip": "10.0.0.10",
            "protocol": "UDP",
            "src_port": 12345,
            "dst_port": 53,
            "packet_length": 100,
        },
        {
            "timestamp": 1.1,
            "src_ip": "10.0.0.20",
            "dst_ip": "10.0.0.10",
            "protocol": "UDP",
            "src_port": 12346,
            "dst_port": 53,
            "packet_length": 120,
        },
        {
            "timestamp": 1.2,
            "src_ip": "unknown",
            "dst_ip": "unknown",
            "protocol": "ARP",
            "packet_length": 28,
        },
    ]

    aggregator = FeatureAggregator(window_seconds=3.0)
    features = aggregator.aggregate(events)

    assert len(features) == 1
    assert features[0].source_ip == "10.0.0.20"
    assert features[0].destination_ip == "10.0.0.10"

    detector = RuleBasedReconDetector(min_unique_ports=4, min_packet_count=5, min_packets_per_second=0.5)
    result = detector.detect(features[0].to_dict())

    assert result.source_ip == "10.0.0.20"
    assert result.destination_ip == "10.0.0.10"
    assert result.attack_type == "normal"


def test_feature_aggregation_counts_packets_and_ports():
    events = [
        {
            "timestamp": 1.0,
            "src_ip": "10.0.0.100",
            "dst_ip": "10.0.0.10",
            "protocol": "TCP",
            "src_port": 40000,
            "dst_port": 22,
            "packet_length": 74,
        },
        {
            "timestamp": 1.2,
            "src_ip": "10.0.0.100",
            "dst_ip": "10.0.0.10",
            "protocol": "TCP",
            "src_port": 40001,
            "dst_port": 80,
            "packet_length": 74,
        },
        {
            "timestamp": 1.5,
            "src_ip": "10.0.0.100",
            "dst_ip": "10.0.0.10",
            "protocol": "TCP",
            "src_port": 40002,
            "dst_port": 443,
            "packet_length": 74,
        },
    ]

    aggregator = FeatureAggregator(window_seconds=3.0)
    features = aggregator.aggregate(events)

    assert len(features) == 1
    assert features[0].packet_count == 3
    assert features[0].bytes_total == 222
    assert features[0].unique_destination_ports == 3
    assert features[0].unique_source_ports == 3


def test_packet_rate_and_unique_port_helpers():
    events = [
        {"timestamp": 1.0, "protocol": "TCP", "src_port": 1000, "dst_port": 22, "tcp_flags": 0x02},  # SYN
        {"timestamp": 1.5, "protocol": "TCP", "src_port": 1001, "dst_port": 80, "tcp_flags": 0x12},  # SYN+ACK
        {"timestamp": 2.0, "protocol": "UDP", "src_port": 1002, "dst_port": 53},
    ]

    aggregator = FeatureAggregator(window_seconds=3.0)
    assert aggregator.calculate_packets_per_second(events) == 3.0
    assert aggregator.calculate_unique_ports(events, "dst_port") == 3
    assert aggregator.count_tcp_flags(events, "syn") == 2
    assert aggregator.count_tcp_flags(events, "ack") == 1


def test_tcp_syn_ack_counts_reflect_real_flags_not_port_presence():
    """Every real TCP packet -- refused, SYN-only, or a full handshake --
    carries both a source and destination port, so counting SYN/ACK by port
    presence silently makes tcp_syn_count == tcp_ack_count == packet_count
    for every TCP flow. These counts must come from the real tcp_flags bits
    captured off the wire."""
    events = [
        {"timestamp": 1.0, "src_ip": "10.0.0.100", "dst_ip": "10.0.0.10", "protocol": "TCP",
         "src_port": 40000, "dst_port": 22, "tcp_flags": 0x02},  # SYN
        {"timestamp": 1.1, "src_ip": "10.0.0.100", "dst_ip": "10.0.0.10", "protocol": "TCP",
         "src_port": 40000, "dst_port": 22, "tcp_flags": 0x12},  # SYN+ACK
        {"timestamp": 1.2, "src_ip": "10.0.0.100", "dst_ip": "10.0.0.10", "protocol": "TCP",
         "src_port": 40000, "dst_port": 22, "tcp_flags": 0x18},  # PSH+ACK (data)
        {"timestamp": 1.3, "src_ip": "10.0.0.100", "dst_ip": "10.0.0.10", "protocol": "TCP",
         "src_port": 40000, "dst_port": 22, "tcp_flags": 0x04},  # RST, no ACK
        {"timestamp": 1.4, "src_ip": "10.0.0.100", "dst_ip": "10.0.0.10", "protocol": "UDP",
         "src_port": 40001, "dst_port": 53},  # not TCP at all
    ]

    aggregator = FeatureAggregator(window_seconds=3.0)
    features = aggregator.aggregate(events)
    tcp_flow = next(f for f in features if f.protocol == "TCP")

    assert tcp_flow.packet_count == 4
    assert tcp_flow.tcp_syn_count == 2  # SYN and SYN+ACK
    assert tcp_flow.tcp_ack_count == 2  # SYN+ACK and PSH+ACK
