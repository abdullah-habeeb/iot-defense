from pathlib import Path

from iot_defense.detection.features import FeatureExtractor


def test_extract_feature_vector_uses_expected_fields():
    extractor = FeatureExtractor()

    sample = {
        "src_ip": "10.0.0.2",
        "dst_ip": "10.0.0.3",
        "protocol": "TCP",
        "packet_length": 120,
        "ttl": 64,
        "src_port": 5000,
        "dst_port": 80,
        "timestamp": 1710.0,
        "direction": "outbound",
    }

    vector = extractor.extract(sample)

    assert isinstance(vector, dict)
    assert vector["protocol"] == "TCP"
    assert vector["packet_length"] == 120
    assert vector["ttl"] == 64
    assert vector["dst_port"] == 80
    assert vector["direction"] == "outbound"


def test_feature_extractor_uses_pathlike_output_dir():
    extractor = FeatureExtractor(output_dir=Path("data/metrics"))
    assert extractor.output_dir == Path("data/metrics")
