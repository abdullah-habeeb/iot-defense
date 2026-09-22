import pytest

from iot_defense.detection.detector import (
    RuleBasedBruteForceDetector,
    RuleBasedDnsAmplificationDetector,
    RuleBasedDosDetector,
    RuleBasedExfiltrationDetector,
    RuleBasedFirmwareTamperingDetector,
    RuleBasedReconDetector,
    UnifiedRuleBasedDetector,
    _load_detection_policy,
)
from iot_defense.detection.flow_features import FlowFeatures


def test_load_detection_policy_actually_finds_the_yaml_file():
    """Regression test for a real bug: the config path was resolved one
    directory too shallow (parents[2], landing in src/ instead of the repo
    root), so config_path.exists() was always False and this always
    silently returned {} -- editing config/policies.yaml's policy.detection
    section had no effect at all. Invisible in practice only because every
    detector's hardcoded fallback default happened to be kept in sync with
    the YAML by hand; this asserts the file is genuinely found."""
    config = _load_detection_policy()
    assert config, "config/policies.yaml's policy.detection section must actually load, not silently return {}"
    assert config["dos_min_packets_per_second"] == 20.0
    assert config["exploit_min_average_packet_size"] == 250.0


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


def _flow(**overrides):
    defaults = dict(
        source_ip="unknown", destination_ip="unknown", protocol="UNKNOWN",
        duration=0.0, packet_count=1, packets_per_second=0.0, bytes_total=42,
        average_packet_size=42.0, unique_destination_ports=0, unique_source_ports=0,
    )
    defaults.update(overrides)
    return FlowFeatures(**defaults)


class TestDetectFlowsScansEveryFlow:
    """Regression coverage for a real bug found running the evaluation
    harness: a capture window can contain incidental background noise
    (ARP, IPv6 neighbour discovery triggered by an interface flap) ahead
    of the real attack traffic in capture order. detect() alone (called
    on a single pre-selected flow, e.g. flows[0]) would pick up that noise
    instead of the real signal -- detect_flows() must scan every flow."""

    def test_skips_leading_noise_flow_and_finds_the_real_attack(self):
        noise = _flow()  # unknown/unknown, exactly what a stray ND/ARP packet decodes to
        real_flood = _flow(
            source_ip="10.0.0.100", destination_ip="10.0.0.10", protocol="UDP",
            duration=1.0, packet_count=200, packets_per_second=200.0,
            unique_destination_ports=1, average_packet_size=64.0,
        )
        event = UnifiedRuleBasedDetector().detect_flows([noise, real_flood])
        assert event.attack_type == "dos_flood"

    def test_returns_normal_when_every_flow_is_benign(self):
        benign = [_flow(source_ip="10.0.0.30", destination_ip="10.0.0.10", packet_count=3, average_packet_size=90.0) for _ in range(3)]
        event = UnifiedRuleBasedDetector().detect_flows(benign)
        assert event.attack_type == "normal"

    def test_raises_on_an_empty_flow_list(self):
        with pytest.raises(ValueError):
            UnifiedRuleBasedDetector().detect_flows([])


class TestDnsAmplificationAndFirmwareTamperingShareOneBoundaryNotAGap:
    """Regression test for a real, confirmed bug found by a rigorous
    system review: RuleBasedDnsAmplificationDetector's floor
    (packets_per_second >= 4.0) and RuleBasedFirmwareTamperingDetector's
    ceiling (originally packets_per_second < 5.0) used mismatched
    values, leaving a real [4.0, 5.0) band where both windows were
    simultaneously true -- unlike every other boundary-sharing detector
    pair in this file (e.g. dns_tunneling/rogue_beacon, both exactly
    5.5), which use one shared value. Dormant in production only because
    no real traffic generator's pacing ever landed in that band -- a
    live logic defect, not a theoretical one. Fixed by tightening
    firmware_tampering's ceiling to the same 4.0 boundary."""

    BASE_FEATURES = {
        "source_ip": "10.0.0.10",
        "destination_ip": "10.0.0.100",
        "protocol": "UDP",
        "unique_destination_ports": 1,
        "packet_count": 30,
        "average_packet_size": 600.0,
    }

    def test_no_pps_value_fires_both_detectors(self):
        dns_amp = RuleBasedDnsAmplificationDetector()
        fw = RuleBasedFirmwareTamperingDetector()
        pps = 0.0
        overlaps = []
        while pps <= 10.0:
            features = dict(self.BASE_FEATURES, packets_per_second=round(pps, 2))
            both_fire = (
                dns_amp.detect(features).attack_type == "dns_amplification"
                and fw.detect(features).attack_type == "firmware_tampering"
            )
            if both_fire:
                overlaps.append(pps)
            pps += 0.05
        assert not overlaps, f"dns_amplification and firmware_tampering both fire at pps={overlaps}"

    def test_exactly_4_0_pps_is_dns_amplification_not_firmware_tampering(self):
        """The shared boundary itself: 4.0 must belong to exactly one
        detector, not both and not neither."""
        dns_amp = RuleBasedDnsAmplificationDetector()
        fw = RuleBasedFirmwareTamperingDetector()
        features = dict(self.BASE_FEATURES, packets_per_second=4.0)
        assert dns_amp.detect(features).attack_type == "dns_amplification"
        assert fw.detect(features).attack_type == "normal"

    def test_real_firmware_tampering_traffic_rate_stays_under_the_new_ceiling(self):
        """generate_firmware_tampering_mininet_traffic paces at ~3.33 pps
        (0.3s interval) -- confirm the tightened 4.0 ceiling still leaves
        real margin, not just a synthetic boundary value."""
        fw = RuleBasedFirmwareTamperingDetector()
        features = dict(self.BASE_FEATURES, packets_per_second=1 / 0.3)
        assert fw.detect(features).attack_type == "firmware_tampering"
