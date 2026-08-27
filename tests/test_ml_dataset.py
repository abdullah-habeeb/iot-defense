from pathlib import Path

import pandas as pd

from iot_defense.detection.flow_features import FlowFeatures
from iot_defense.ml.evaluation import classification_metrics, split_by_run
from iot_defense.ml.random_forest import RandomForestDetector
from iot_defense.ml.generate_dataset import _reconnaissance_traffic
from iot_defense.ml.schema import DATASET_COLUMNS, FEATURE_COLUMNS, flow_to_dataset_row, validate_dataset
from iot_defense.ml.train_random_forest import train_and_evaluate


def flow(protocol: str, attack: bool) -> FlowFeatures:
    return FlowFeatures(
        source_ip="10.0.0.100" if attack else "10.0.0.30",
        destination_ip="10.0.0.10",
        protocol=protocol,
        duration=0.2 if attack else 2.0,
        packet_count=10 if attack else 3,
        packets_per_second=50.0 if attack else 1.5,
        bytes_total=740 if attack else 180,
        average_packet_size=74.0 if attack else 60.0,
        unique_destination_ports=4 if attack else 1,
        unique_source_ports=10 if attack else 1,
        tcp_syn_count=10 if attack else 0,
        tcp_ack_count=10 if attack else 0,
        udp_packet_count=0 if attack else 3,
        icmp_packet_count=0,
    )


def dataset(rows_per_class: int = 10) -> pd.DataFrame:
    rows = []
    for run in range(rows_per_class * 2):
        attack = run % 2 == 1
        rows.append(
            flow_to_dataset_row(
                flow("TCP" if attack else "UDP", attack),
                flow_id=f"flow-{run}",
                run_id=f"run-{run}",
                scenario_id="recon" if attack else "normal",
                label=int(attack),
            )
        )
    return pd.DataFrame(rows, columns=DATASET_COLUMNS)


def test_schema_and_label_assignment():
    row = flow_to_dataset_row(
        flow("TCP", True), flow_id="f1", run_id="r1", scenario_id="recon-1", label=1
    )
    assert list(row) == list(DATASET_COLUMNS)
    assert row["label"] == 1
    assert row["label_name"] == "reconnaissance_port_scan"
    assert list(FEATURE_COLUMNS) == [
        "protocol", "duration", "packet_count", "packets_per_second", "bytes_total",
        "average_packet_size", "unique_destination_ports", "unique_source_ports",
        "tcp_syn_count", "tcp_ack_count", "udp_packet_count", "icmp_packet_count",
    ]


def test_data_validation_and_metrics():
    data = dataset()
    assert validate_dataset(data) == ["duplicate_feature_label_rows"]
    data.loc[0, "packet_count"] = -1
    assert "negative_numeric_feature" in validate_dataset(data)
    metrics = classification_metrics([0, 0, 1, 1], [0, 1, 1, 1])
    assert metrics["tn"] == 1
    assert metrics["fp"] == 1
    assert metrics["fn"] == 0
    assert metrics["tp"] == 2
    assert metrics["false_positive_rate"] == 0.5


def test_group_split_keeps_runs_disjoint():
    data = dataset()
    train, validation, test = split_by_run(data, seed=7)
    assert set(train.run_id).isdisjoint(validation.run_id)
    assert set(train.run_id).isdisjoint(test.run_id)
    assert set(validation.run_id).isdisjoint(test.run_id)


def test_random_forest_training_save_load_and_threat_event(tmp_path: Path):
    data_path = tmp_path / "flows.csv"
    model_path = tmp_path / "rf.joblib"
    dataset().to_csv(data_path, index=False)
    metrics = train_and_evaluate(dataset_path=data_path, model_path=model_path, seed=7)
    assert model_path.exists()
    assert metrics["random_forest"]["tp"] >= 0
    detector = RandomForestDetector(model_path)
    result = detector.detect(dataset().iloc[-1].to_dict())
    assert result.attack_type in {"normal", "reconnaissance_port_scan"}
    assert result.source_ip == "10.0.0.100"
    assert result.destination_ip == "10.0.0.10"


def test_reconnaissance_traffic_no_bind():
    # Mock host object that just returns the command
    class MockHost:
        def cmd(self, command: str) -> str:
            return command

    command = _reconnaissance_traffic(MockHost(), "10.0.0.1", [80, 443], 0.01)
    assert "sock.bind" not in command
