from iot_defense.detection.rule_based import RuleBasedDetector


def test_rule_based_detector_marks_icmp_attack_as_suspicious():
    detector = RuleBasedDetector(suspicious_threshold=0.75)
    features = {
        "protocol": "ICMP",
        "dst_port": 22,
        "direction": "inbound",
        "packet_length": 2500,
    }

    result = detector.predict(features)

    assert result["suspicious"] is True
    assert result["label"] == "malicious"
    assert result["score"] >= 0.75


def test_rule_based_detector_keeps_benign_traffic_clean():
    detector = RuleBasedDetector(suspicious_threshold=0.75)
    features = {
        "protocol": "TCP",
        "dst_port": 80,
        "direction": "outbound",
        "packet_length": 140,
    }

    result = detector.predict(features)

    assert result["suspicious"] is False
    assert result["label"] == "benign"
