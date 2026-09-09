from pathlib import Path

import pandas as pd

from iot_defense.detection.flow_features import FlowFeatures
from iot_defense.ml.evaluation import classification_metrics, split_by_run
from iot_defense.ml.random_forest import RandomForestDetector
from iot_defense.ml.generate_dataset import _reconnaissance_traffic, _start_tcp_listener
from iot_defense.ml.schema import DATASET_COLUMNS, FEATURE_COLUMNS, LABEL_NAMES, flow_to_dataset_row, validate_dataset
from iot_defense.ml.train_random_forest import train_and_evaluate

# Reverse of LABEL_NAMES, matching train_random_forest.py's own convention.
_LABEL_NAME_TO_INT = {name: label for label, name in LABEL_NAMES.items()}


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


def flow_for_label(label_name: str) -> FlowFeatures:
    """A canonical FlowFeatures fixture per registered class, whose
    rate/port/payload profile actually satisfies (or, for "normal",
    satisfies none of) the real thresholds each rule-based detector in
    detection/detector.py checks -- not an arbitrary placeholder. Values
    are chosen with real margin so they stay unambiguous even as an
    UnifiedRuleBasedDetector sweep, not just against their own detector.
    """
    if label_name == "normal":
        return FlowFeatures(
            source_ip="10.0.0.30", destination_ip="10.0.0.10", protocol="UDP",
            duration=2.0, packet_count=3, packets_per_second=1.5, bytes_total=180,
            average_packet_size=60.0, unique_destination_ports=1, unique_source_ports=1,
            tcp_syn_count=0, tcp_ack_count=0, udp_packet_count=3, icmp_packet_count=0,
        )
    if label_name == "reconnaissance_port_scan":
        return FlowFeatures(
            source_ip="10.0.0.100", destination_ip="10.0.0.10", protocol="TCP",
            duration=5.0, packet_count=15, packets_per_second=3.0, bytes_total=1050,
            average_packet_size=70.0, unique_destination_ports=6, unique_source_ports=1,
            tcp_syn_count=15, tcp_ack_count=0, udp_packet_count=0, icmp_packet_count=0,
        )
    if label_name == "dos_flood":
        return FlowFeatures(
            source_ip="10.0.0.100", destination_ip="10.0.0.10", protocol="TCP",
            duration=1.875, packet_count=150, packets_per_second=80.0, bytes_total=10500,
            average_packet_size=70.0, unique_destination_ports=1, unique_source_ports=1,
            tcp_syn_count=150, tcp_ack_count=0, udp_packet_count=0, icmp_packet_count=0,
        )
    if label_name == "brute_force":
        return FlowFeatures(
            source_ip="10.0.0.100", destination_ip="10.0.0.10", protocol="TCP",
            duration=4.0, packet_count=20, packets_per_second=5.0, bytes_total=1600,
            average_packet_size=80.0, unique_destination_ports=1, unique_source_ports=1,
            tcp_syn_count=20, tcp_ack_count=20, udp_packet_count=0, icmp_packet_count=0,
        )
    if label_name == "data_exfiltration":
        # Direction-reversed, matching RuleBasedExfiltrationDetector's own
        # documented contract: the device (10.0.0.10) is the traffic
        # source, the attacker-controlled sink (10.0.0.100) the destination.
        return FlowFeatures(
            source_ip="10.0.0.10", destination_ip="10.0.0.100", protocol="TCP",
            duration=5.0, packet_count=8, packets_per_second=1.6, bytes_total=9600,
            average_packet_size=1200.0, unique_destination_ports=1, unique_source_ports=1,
            tcp_syn_count=8, tcp_ack_count=8, udp_packet_count=0, icmp_packet_count=0,
        )
    if label_name == "exploit_payload_injection":
        # Few connections, single port, but a notably larger payload than
        # any normal heartbeat -- matching RuleBasedExploitDetector's own
        # thresholds (250-550 byte average, well clear of normal traffic's
        # real observed max of ~119 bytes and exfiltration's real floor of
        # 600+).
        return FlowFeatures(
            source_ip="10.0.0.100", destination_ip="10.0.0.10", protocol="TCP",
            duration=3.0, packet_count=4, packets_per_second=1.5, bytes_total=1400,
            average_packet_size=350.0, unique_destination_ports=1, unique_source_ports=1,
            tcp_syn_count=4, tcp_ack_count=4, udp_packet_count=0, icmp_packet_count=0,
        )
    raise ValueError(f"no fixture defined for label {label_name!r}")


def dataset_5class(rows_per_class: int = 12) -> pd.DataFrame:
    """A balanced dataset spanning every currently registered class, not
    just normal/reconnaissance -- the RF pipeline and its rule-based
    comparison baseline have both been genuinely 5-class since Phase 4,
    but were never exercised as such by this suite until now."""
    rows = []
    run = 0
    for label_name, label in sorted(_LABEL_NAME_TO_INT.items(), key=lambda item: item[1]):
        for _ in range(rows_per_class):
            rows.append(
                flow_to_dataset_row(
                    flow_for_label(label_name),
                    flow_id=f"flow-{run}",
                    run_id=f"run-{run}",
                    scenario_id=label_name,
                    label=label,
                )
            )
            run += 1
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


def test_data_validation_over_five_classes():
    """validate_dataset must accept every registered label, not just the
    0/1 pair the original binary-era dataset ever produced."""
    data = dataset_5class()
    assert set(data["label"]) == set(LABEL_NAMES)
    assert validate_dataset(data) == ["duplicate_feature_label_rows"]
    data.loc[0, "label"] = max(LABEL_NAMES) + 1
    assert "unsupported_labels" in validate_dataset(data)


def test_classification_metrics_multiclass_branch():
    """With 3+ classes present, classification_metrics must switch from
    the binary tn/fp/fn/tp shape to the macro-averaged/per-class one, and
    report every registered label even though this split contains no
    mistakes for two of them."""
    y_true = [0, 1, 2, 3, 4, 0, 1, 2, 3, 4]
    y_pred = [0, 1, 3, 3, 4, 0, 1, 2, 3, 4]  # single mistake: true=2 predicted as 3
    metrics = classification_metrics(y_true, y_pred)
    assert "tn" not in metrics
    assert metrics["labels"] == sorted(LABEL_NAMES)
    assert metrics["accuracy"] == 0.9
    assert set(metrics["per_class"]) == {str(label) for label in LABEL_NAMES}
    for per_class in metrics["per_class"].values():
        assert 0.0 <= per_class["f1"] <= 1.0


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


def test_random_forest_training_is_genuinely_five_class(tmp_path: Path):
    """Regression test for the gap found in the Phase 0-5 audit: the RF
    training/evaluation path had never been exercised end-to-end against
    all 5 registered classes by an automated test, only by one-off real
    Mininet runs during manual review."""
    data_path = tmp_path / "flows.csv"
    model_path = tmp_path / "rf.joblib"
    dataset_5class().to_csv(data_path, index=False)
    metrics = train_and_evaluate(dataset_path=data_path, model_path=model_path, seed=7)
    assert model_path.exists()
    assert set(metrics["class_counts"]) == {str(label) for label in LABEL_NAMES}
    # Every row within a class shares an identical feature vector (see
    # flow_for_label), so both the trained model and the rule-based
    # baseline face a trivially separable problem here -- this test is
    # about exercising the 5-class *pipeline* end-to-end, not benchmarking
    # accuracy on realistic noisy data (that's what the 125-row real
    # Mininet dataset in data/ml/ is for).
    assert "tn" not in metrics["random_forest"]
    assert metrics["random_forest"]["accuracy"] == 1.0
    assert metrics["rule_based"]["accuracy"] == 1.0

    detector = RandomForestDetector(model_path)
    for label_name in LABEL_NAMES.values():
        result = detector.detect(flow_for_label(label_name).to_dict())
        assert result.attack_type == label_name


def test_reconnaissance_traffic_no_bind():
    # Mock host object that just returns the command
    class MockHost:
        def cmd(self, command: str) -> str:
            return command

    command = _reconnaissance_traffic(MockHost(), "10.0.0.1", [80, 443], 0.01)
    assert "sock.bind" not in command

def test_start_tcp_listener_command():
    class MockHost:
        def cmd(self, command: str) -> str:
            # First call starts the listener (PID); every call after that
            # is the readiness poll -- report "listening" immediately so
            # the test doesn't actually wait out the real poll timeout.
            return "1234" if "ss -ltn" not in command else "LISTEN 0 128 *:8080"

    pid = _start_tcp_listener(MockHost(), 8080)
    assert pid == "1234"


def test_start_tcp_listener_heredoc_terminator_is_valid_shell_syntax():
    """Regression test: the heredoc terminator line must be exactly "PY"
    with nothing else on it, or bash never recognizes it as the end of the
    heredoc and host.cmd() blocks forever waiting for a line that never
    comes. A previous version appended " & echo $!" directly onto the
    terminator line, which is invalid and caused a real, reproduced hang
    during dataset generation.
    """
    captured: dict[str, str] = {}

    class RecordingHost:
        def cmd(self, command: str) -> str:
            if "ss -ltn" in command:
                return "LISTEN 0 128 *:8080"  # readiness poll: report ready immediately
            captured["command"] = command
            return "1234"

    _start_tcp_listener(RecordingHost(), 8080)
    lines = captured["command"].splitlines()
    terminator_lines = [line for line in lines if line.strip() == "PY"]
    assert terminator_lines, "heredoc terminator 'PY' must appear alone on its own line"
    # Nothing may follow "PY" on the same line as the terminator itself.
    for line in lines:
        if line.startswith("PY") and line != "PY":
            raise AssertionError(f"heredoc terminator line has trailing content: {line!r}")


def test_start_tcp_listener_waits_for_readiness_before_returning():
    """The listener must not be reported ready until an `ss` check actually
    confirms the port is listening -- this is the fix for a real race where
    traffic was sent before the backgrounded listener had finished binding."""
    calls: list[str] = []

    class SlowToStartHost:
        def cmd(self, command: str) -> str:
            calls.append(command)
            if "ss -ltn" in command:
                # Not listening on the first check, listening on the second.
                ss_calls = [c for c in calls if "ss -ltn" in c]
                return "" if len(ss_calls) <= 1 else "LISTEN 0 128 *:9090"
            return "5678"

    pid = _start_tcp_listener(SlowToStartHost(), 9090)
    assert pid == "5678"
    ss_call_count = sum(1 for c in calls if "ss -ltn" in c)
    assert ss_call_count >= 2, "must poll again if the first readiness check reports not-yet-listening"
