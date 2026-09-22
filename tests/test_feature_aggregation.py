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


def test_packet_rate_helper_agrees_with_aggregate_on_zero_duration():
    """Regression test for a real bug found by a system review:
    calculate_packets_per_second()'s zero-duration fallback used to
    return float(len(events)) (the raw packet count), silently
    disagreeing with aggregate()'s own real path (0.0) for the exact
    same input -- an ordinary single-packet or simultaneous-timestamp
    flow would misreport as an extreme rate through this helper."""
    aggregator = FeatureAggregator(window_seconds=3.0)
    simultaneous = [
        {"timestamp": 5.0, "protocol": "UDP", "src_port": 1, "dst_port": 1},
        {"timestamp": 5.0, "protocol": "UDP", "src_port": 2, "dst_port": 1},
    ]
    assert aggregator.calculate_packets_per_second(simultaneous) == 0.0


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


def test_inter_arrival_cv_is_near_zero_for_perfectly_regular_timing():
    """A near-0 coefficient of variation is the whole point of this
    feature -- it's the one real signal C2 beaconing needs and no
    rate/size/count-based detector provides."""
    events = [
        {"timestamp": t, "src_ip": "10.0.0.10", "dst_ip": "10.0.0.200", "protocol": "UDP", "packet_length": 60}
        for t in (0.0, 3.0, 6.0, 9.0, 12.0, 15.0)
    ]
    features = FeatureAggregator().aggregate(events)
    assert features[0].inter_arrival_cv < 0.01


def test_inter_arrival_cv_is_high_for_bursty_irregular_timing():
    events = [
        {"timestamp": t, "src_ip": "10.0.0.100", "dst_ip": "10.0.0.10", "protocol": "UDP", "packet_length": 60}
        for t in (0.0, 0.1, 3.5, 3.6, 3.7, 9.2)
    ]
    features = FeatureAggregator().aggregate(events)
    assert features[0].inter_arrival_cv > 0.5


def test_inter_arrival_cv_defaults_to_the_insufficient_data_sentinel():
    """Fewer than 3 packets can't produce a real variance -- must not be
    silently reported as 0.0 ("perfectly regular"), the opposite of what
    too little data actually tells you."""
    events = [
        {"timestamp": t, "src_ip": "10.0.0.100", "dst_ip": "10.0.0.10", "protocol": "UDP", "packet_length": 60}
        for t in (0.0, 1.0)
    ]
    features = FeatureAggregator().aggregate(events)
    assert features[0].inter_arrival_cv == 999.0
