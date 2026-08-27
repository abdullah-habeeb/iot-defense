"""Canonical dataset schema derived from FlowFeatures."""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from iot_defense.detection.flow_features import FlowFeatures


FEATURE_COLUMNS = (
    "protocol",
    "duration",
    "packet_count",
    "packets_per_second",
    "bytes_total",
    "average_packet_size",
    "unique_destination_ports",
    "unique_source_ports",
    "tcp_syn_count",
    "tcp_ack_count",
    "udp_packet_count",
    "icmp_packet_count",
)
AUDIT_COLUMNS = (
    "flow_id",
    "run_id",
    "scenario_id",
    "source_ip",
    "destination_ip",
    "label",
    "label_name",
)
DATASET_COLUMNS = AUDIT_COLUMNS + FEATURE_COLUMNS
LABEL_NAMES = {0: "normal", 1: "reconnaissance_port_scan"}
NUMERIC_FEATURE_COLUMNS = tuple(column for column in FEATURE_COLUMNS if column != "protocol")


def flow_to_dataset_row(
    flow: FlowFeatures,
    *,
    flow_id: str,
    run_id: str,
    scenario_id: str,
    label: int,
) -> dict[str, Any]:
    """Convert a canonical FlowFeatures record to an auditable labelled row."""
    if label not in LABEL_NAMES:
        raise ValueError(f"Unsupported label: {label}")
    values = flow.to_dict()
    row = {
        "flow_id": flow_id,
        "run_id": run_id,
        "scenario_id": scenario_id,
        "source_ip": flow.source_ip,
        "destination_ip": flow.destination_ip,
        "label": label,
        "label_name": LABEL_NAMES[label],
    }
    row.update({column: values[column] for column in FEATURE_COLUMNS})
    return row


def validate_dataset(data: pd.DataFrame) -> list[str]:
    """Return documented data-quality anomalies without silently removing rows."""
    anomalies: list[str] = []
    missing_columns = [column for column in DATASET_COLUMNS if column not in data.columns]
    if missing_columns:
        return [f"missing_columns:{','.join(missing_columns)}"]
    if data.empty:
        anomalies.append("empty_dataset")
    if data[list(DATASET_COLUMNS)].isna().any().any():
        anomalies.append("missing_values")
    numeric = data[list(NUMERIC_FEATURE_COLUMNS)]
    if not np.isfinite(numeric.to_numpy(dtype=float)).all():
        anomalies.append("nan_or_infinite_numeric_values")
    if (numeric < 0).any().any():
        anomalies.append("negative_numeric_feature")
    if not set(data["label"].dropna().astype(int)).issubset(LABEL_NAMES):
        anomalies.append("unsupported_labels")
    if not data["protocol"].dropna().isin(["TCP", "UDP", "ICMP", "ARP", "UNKNOWN"]).all():
        anomalies.append("unexpected_protocol")
    if data.duplicated(subset=list(FEATURE_COLUMNS) + ["label"]).any():
        anomalies.append("duplicate_feature_label_rows")
    return anomalies
