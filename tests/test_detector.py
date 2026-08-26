from iot_defense.detection.detector import RuleBasedReconDetector


def test_normal_traffic_is_not_flagged():
    features = {
        "source_ip": "10.0.0.20",
        "destination_ip": "10.0.0.10",
        "protocol": "TCP",
        "packet_count": 2,
        "packets_per_second": 0.3,
        "unique_destination_ports": 1,
    }

    detector = RuleBasedReconDetector(min_unique_ports=4, min_packet_count=5, min_packets_per_second=0.5)
    result = detector.detect(features)

    assert result.attack_type == "normal"
    assert result.threat_score < 0.5


def test_scan_traffic_is_detected():
    features = {
        "source_ip": "10.0.0.100",
        "destination_ip": "10.0.0.10",
        "protocol": "TCP",
        "packet_count": 10,
        "packets_per_second": 8.0,
        "unique_destination_ports": 6,
    }

    detector = RuleBasedReconDetector(min_unique_ports=4, min_packet_count=5, min_packets_per_second=0.5)
    result = detector.detect(features)

    assert result.attack_type == "reconnaissance_port_scan"
    assert result.threat_score >= 0.8
    assert result.confidence > 0.8
