from iot_defense.detection.detector import RuleBasedDosDetector, RuleBasedReconDetector, UnifiedRuleBasedDetector


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


def test_dos_detector_ignores_benign_traffic():
    features = {
        "source_ip": "10.0.0.20",
        "destination_ip": "10.0.0.10",
        "protocol": "UDP",
        "packet_count": 3,
        "packets_per_second": 1.0,
        "unique_destination_ports": 1,
    }

    detector = RuleBasedDosDetector(min_packets_per_second=20.0, max_unique_ports=2, min_packet_count=20)
    result = detector.detect(features)

    assert result.attack_type == "normal"
    assert result.threat_score < 0.5


def test_dos_detector_flags_high_rate_single_port_flood():
    features = {
        "source_ip": "10.0.0.100",
        "destination_ip": "10.0.0.10",
        "protocol": "UDP",
        "packet_count": 400,
        "packets_per_second": 90.0,
        "unique_destination_ports": 1,
    }

    detector = RuleBasedDosDetector(min_packets_per_second=20.0, max_unique_ports=2, min_packet_count=20)
    result = detector.detect(features)

    assert result.attack_type == "dos_flood"
    assert result.threat_score >= 0.8
    assert result.confidence > 0.8


def test_dos_detector_does_not_confuse_port_scan_for_flood():
    """A port scan has high port diversity -- the opposite of a flood's
    signature -- so the DoS detector must not also flag it."""
    features = {
        "source_ip": "10.0.0.100",
        "destination_ip": "10.0.0.10",
        "protocol": "TCP",
        "packet_count": 40,
        "packets_per_second": 25.0,
        "unique_destination_ports": 6,
    }

    detector = RuleBasedDosDetector(min_packets_per_second=20.0, max_unique_ports=2, min_packet_count=20)
    result = detector.detect(features)

    assert result.attack_type == "normal"


class TestUnifiedDetectorIsAttackTypeAgnostic:
    """The unified detector must decide the attack type purely from the
    observed traffic shape, not from any hint about what was requested."""

    def _detector(self) -> UnifiedRuleBasedDetector:
        return UnifiedRuleBasedDetector(
            detectors={
                "reconnaissance": RuleBasedReconDetector(min_unique_ports=4, min_packet_count=5, min_packets_per_second=0.5),
                "dos": RuleBasedDosDetector(min_packets_per_second=20.0, max_unique_ports=2, min_packet_count=20),
            }
        )

    def test_classifies_flood_signature_as_dos(self):
        features = {
            "source_ip": "10.0.0.100", "destination_ip": "10.0.0.10",
            "packet_count": 300, "packets_per_second": 80.0, "unique_destination_ports": 1,
        }
        result = self._detector().detect(features)
        assert result.attack_type == "dos_flood"

    def test_classifies_scan_signature_as_reconnaissance(self):
        features = {
            "source_ip": "10.0.0.100", "destination_ip": "10.0.0.10",
            "packet_count": 10, "packets_per_second": 8.0, "unique_destination_ports": 6,
        }
        result = self._detector().detect(features)
        assert result.attack_type == "reconnaissance_port_scan"

    def test_classifies_benign_signature_as_normal(self):
        features = {
            "source_ip": "10.0.0.20", "destination_ip": "10.0.0.10",
            "packet_count": 2, "packets_per_second": 0.3, "unique_destination_ports": 1,
        }
        result = self._detector().detect(features)
        assert result.attack_type == "normal"

    def test_flood_check_runs_before_recon_check_and_does_not_misfire(self):
        """A flood's packet rate could coincidentally look high like a fast
        scan -- confirm the two signatures stay properly distinguished by
        port diversity, not conflated."""
        flood = {
            "source_ip": "10.0.0.100", "destination_ip": "10.0.0.10",
            "packet_count": 300, "packets_per_second": 80.0, "unique_destination_ports": 1,
        }
        scan = {
            "source_ip": "10.0.0.100", "destination_ip": "10.0.0.10",
            "packet_count": 10, "packets_per_second": 8.0, "unique_destination_ports": 6,
        }
        detector = self._detector()
        assert detector.detect(flood).attack_type == "dos_flood"
        assert detector.detect(scan).attack_type == "reconnaissance_port_scan"
