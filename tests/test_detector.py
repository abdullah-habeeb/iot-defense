from iot_defense.detection.detector import (
    RuleBasedBruteForceDetector,
    RuleBasedDosDetector,
    RuleBasedExfiltrationDetector,
    RuleBasedReconDetector,
    UnifiedRuleBasedDetector,
)


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


def test_brute_force_detector_ignores_benign_traffic():
    features = {
        "source_ip": "10.0.0.20",
        "destination_ip": "10.0.0.10",
        "protocol": "TCP",
        "packet_count": 3,
        "packets_per_second": 0.5,
        "unique_destination_ports": 1,
        "average_packet_size": 64.0,
    }

    detector = RuleBasedBruteForceDetector(
        max_unique_ports=2, min_packet_count=12, min_packets_per_second=1.0,
        max_packets_per_second=15.0, max_average_packet_size=200.0,
    )
    result = detector.detect(features)

    assert result.attack_type == "normal"
    assert result.threat_score < 0.5


def test_brute_force_detector_flags_repeated_login_attempts():
    features = {
        "source_ip": "10.0.0.100",
        "destination_ip": "10.0.0.10",
        "protocol": "TCP",
        "packet_count": 36,
        "packets_per_second": 6.0,
        "unique_destination_ports": 1,
        "average_packet_size": 74.0,
    }

    detector = RuleBasedBruteForceDetector(
        max_unique_ports=2, min_packet_count=12, min_packets_per_second=1.0,
        max_packets_per_second=15.0, max_average_packet_size=200.0,
    )
    result = detector.detect(features)

    assert result.attack_type == "brute_force"
    assert result.threat_score >= 0.7
    assert result.confidence > 0.7


def test_brute_force_detector_does_not_confuse_dos_flood_for_login_attempts():
    """A flood's packet rate sits above brute-force's rate ceiling -- confirm
    the two signatures stay distinguished by rate, not conflated."""
    features = {
        "source_ip": "10.0.0.100",
        "destination_ip": "10.0.0.10",
        "protocol": "UDP",
        "packet_count": 400,
        "packets_per_second": 90.0,
        "unique_destination_ports": 1,
        "average_packet_size": 92.0,
    }

    detector = RuleBasedBruteForceDetector(
        max_unique_ports=2, min_packet_count=12, min_packets_per_second=1.0,
        max_packets_per_second=15.0, max_average_packet_size=200.0,
    )
    result = detector.detect(features)

    assert result.attack_type == "normal"


def test_brute_force_detector_does_not_confuse_exfiltration_for_login_attempts():
    """Regression test for a real bug: brute-force's packet_count window
    ([12, inf)) overlaps exfiltration's ([3, 25]), and both restrict
    unique_destination_ports to a single port -- without the
    max_average_packet_size bound, a large-payload exfiltration flow whose
    packet_count happened to land in that overlap was silently
    misclassified as brute-force."""
    features = {
        "source_ip": "10.0.0.10",
        "destination_ip": "10.0.0.100",
        "protocol": "UDP",
        "packet_count": 15,
        "packets_per_second": 2.0,
        "unique_destination_ports": 1,
        "average_packet_size": 1242.0,
    }

    detector = RuleBasedBruteForceDetector(
        max_unique_ports=2, min_packet_count=12, min_packets_per_second=1.0,
        max_packets_per_second=15.0, max_average_packet_size=200.0,
    )
    result = detector.detect(features)

    assert result.attack_type == "normal"


def test_exfiltration_detector_ignores_benign_traffic():
    features = {
        "source_ip": "10.0.0.10",
        "destination_ip": "10.0.0.20",
        "protocol": "UDP",
        "packet_count": 5,
        "packets_per_second": 1.0,
        "unique_destination_ports": 1,
        "average_packet_size": 64.0,
    }

    detector = RuleBasedExfiltrationDetector(
        max_unique_ports=2, min_packet_count=3, max_packet_count=25, min_average_packet_size=600.0,
    )
    result = detector.detect(features)

    assert result.attack_type == "normal"
    assert result.threat_score < 0.5


def test_exfiltration_detector_flags_large_outbound_transfers():
    features = {
        "source_ip": "10.0.0.10",
        "destination_ip": "10.0.0.100",
        "protocol": "UDP",
        "packet_count": 5,
        "packets_per_second": 1.245,
        "unique_destination_ports": 1,
        "average_packet_size": 1242.0,
    }

    detector = RuleBasedExfiltrationDetector(
        max_unique_ports=2, min_packet_count=3, max_packet_count=25, min_average_packet_size=600.0,
    )
    result = detector.detect(features)

    assert result.attack_type == "data_exfiltration"
    assert result.threat_score >= 0.7
    assert result.confidence > 0.7
    # Direction is swapped: destination_ip must be the compromised device
    # (the flow's own source_ip), not the attacker's sink, so downstream
    # isolation targets the device, not the attacker.
    assert result.source_ip == "10.0.0.100"
    assert result.destination_ip == "10.0.0.10"


def test_exfiltration_detector_does_not_swap_direction_on_normal_traffic():
    """The swap only applies when a threat is actually flagged -- normal
    traffic keeps its real captured source/destination, matching every
    other detector's convention."""
    features = {
        "source_ip": "10.0.0.10",
        "destination_ip": "10.0.0.20",
        "protocol": "UDP",
        "packet_count": 5,
        "packets_per_second": 1.0,
        "unique_destination_ports": 1,
        "average_packet_size": 64.0,
    }

    detector = RuleBasedExfiltrationDetector(
        max_unique_ports=2, min_packet_count=3, max_packet_count=25, min_average_packet_size=600.0,
    )
    result = detector.detect(features)

    assert result.source_ip == "10.0.0.10"
    assert result.destination_ip == "10.0.0.20"


class TestUnifiedDetectorIsAttackTypeAgnostic:
    """The unified detector must decide the attack type purely from the
    observed traffic shape, not from any hint about what was requested."""

    def _detector(self) -> UnifiedRuleBasedDetector:
        return UnifiedRuleBasedDetector(
            detectors={
                "reconnaissance": RuleBasedReconDetector(min_unique_ports=4, min_packet_count=5, min_packets_per_second=0.5),
                "dos": RuleBasedDosDetector(min_packets_per_second=20.0, max_unique_ports=2, min_packet_count=20),
                "brute_force": RuleBasedBruteForceDetector(
                    max_unique_ports=2, min_packet_count=12, min_packets_per_second=1.0,
                    max_packets_per_second=15.0, max_average_packet_size=200.0,
                ),
                "exfiltration": RuleBasedExfiltrationDetector(
                    max_unique_ports=2, min_packet_count=3, max_packet_count=25, min_average_packet_size=600.0,
                ),
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

    def test_brute_force_check_runs_before_exfiltration_check_and_does_not_misfire(self):
        """Regression test at the unified-pipeline level, mirroring
        test_flood_check_runs_before_recon_check_and_does_not_misfire above:
        brute-force is checked before exfiltration in registry order, and
        their packet_count windows overlap, so a real large-payload
        exfiltration flow whose packet_count lands in that overlap must
        still resolve to exfiltration, not get shadowed by brute-force
        just because it was checked first."""
        login_attempts = {
            "source_ip": "10.0.0.100", "destination_ip": "10.0.0.10",
            "packet_count": 36, "packets_per_second": 6.0,
            "unique_destination_ports": 1, "average_packet_size": 74.0,
        }
        exfiltration = {
            "source_ip": "10.0.0.10", "destination_ip": "10.0.0.100",
            "packet_count": 15, "packets_per_second": 2.0,
            "unique_destination_ports": 1, "average_packet_size": 1242.0,
        }
        detector = self._detector()
        assert detector.detect(login_attempts).attack_type == "brute_force"
        assert detector.detect(exfiltration).attack_type == "data_exfiltration"
