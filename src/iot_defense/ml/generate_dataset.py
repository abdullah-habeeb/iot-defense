"""Generate labelled FlowFeatures rows from independent Mininet executions."""

from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path
from typing import Any

import pandas as pd

from iot_defense.detection.flow_features import FeatureAggregator
from iot_defense.monitoring.monitor import PacketMonitor
from iot_defense.network.topology import create_mininet_network
from iot_defense.ml.schema import DATASET_COLUMNS, flow_to_dataset_row, validate_dataset


def _normal_traffic(host: Any, target_ip: str, port: int, packet_count: int, payload_size: int) -> str:
    return host.cmd(
        "python3 - <<'PY'\n"
        "import socket, time\n"
        f"payload = b'x' * {payload_size}\n"
        "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        f"for _ in range({packet_count}):\n"
        f"    sock.sendto(payload, ('{target_ip}', {port}))\n"
        "    time.sleep(0.05)\n"
        "sock.close()\n"
        "print('normal_dataset_traffic_done')\n"
        "PY"
    )


def _reconnaissance_traffic(host: Any, target_ip: str, ports: list[int], interval: float) -> str:
    ports_literal = repr(ports)
    return host.cmd(
        "python3 - <<'PY'\n"
        "import socket, time\n"
        f"ports = {ports_literal}\n"
        "for port in ports:\n"
        "    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "    sock.settimeout(0.15)\n"
        "    try:\n"
        f"        sock.connect(('{target_ip}', port))\n"
        "    except OSError:\n"
        "        pass\n"
        "    finally:\n"
        "        sock.close()\n"
        f"    time.sleep({interval})\n"
        "print('recon_dataset_traffic_done')\n"
        "PY"
    )


def generate_dataset(
    *,
    runs: int = 160,
    seed: int = 7,
    output_path: str | Path = "data/ml/controlled_flows.csv",
) -> dict[str, Any]:
    """Run fresh Mininet networks and write one or more labelled flow rows per run."""
    if runs < 6:
        raise ValueError("At least six independent runs are required for group-aware evaluation.")
    rng = random.Random(seed)
    target_options = [("sensor", "10.0.0.10"), ("camera", "10.0.0.20"), ("smart_plug", "10.0.0.30")]
    normal_ports = [5683, 1883, 8080, 9999, 10001]
    known_scan_port_sets = [
        [22, 80, 443, 8080],
        [21, 23, 53, 8080],
        [22, 80, 8000, 8443],
        [25, 110, 143, 993, 995],
    ]
    unseen_scan_port_sets = [
        [22, 81, 444, 8081, 9000],
        [24, 88, 8008, 8444, 10080, 10443],
        [26, 808, 3000, 5000, 8888, 9001, 9443],
    ]
    rows: list[dict[str, Any]] = []
    aggregator = FeatureAggregator(window_seconds=3.0)

    for run_number in range(runs):
        scenario = "normal" if run_number % 2 == 0 else "reconnaissance_port_scan"
        unseen_pattern = scenario == "reconnaissance_port_scan" and run_number >= int(runs * 0.8)
        target_name, target_ip = rng.choice(target_options)
        net = None
        try:
            monitor = PacketMonitor(base_dir=f"/tmp/iot-defense-dataset/run-{run_number:04d}")
            net = create_mininet_network()
            net.start()
            capture_path = monitor.capture_host_packets(net, target_name, packet_limit=200, capture_seconds=2)
            if scenario == "normal":
                source_name, source_ip = (
                    ("smart_plug", "10.0.0.30")
                    if target_name != "smart_plug"
                    else ("camera", "10.0.0.20")
                )
                source = net.get(source_name)
                port = rng.choice(normal_ports)
                packet_count = rng.randint(4, 8)
                payload_size = rng.randint(12, 48)
                _normal_traffic(source, target_ip, port, packet_count, payload_size)
            else:
                source = net.get("attacker")
                port_sets = unseen_scan_port_sets if unseen_pattern else known_scan_port_sets
                ports = rng.choice(port_sets)
                interval = rng.choice([0.01, 0.03, 0.05, 0.08])
                _reconnaissance_traffic(source, target_ip, ports, interval)
            time.sleep(1.0)
            net.get(target_name).cmd("pkill tcpdump || true")
            time.sleep(0.1)
            events = monitor.read_capture(net, target_name, capture_path)
            features = aggregator.aggregate(events)
            selected = [
                feature
                for feature in features
                if feature.destination_ip == target_ip
                and (
                    (scenario == "normal" and feature.source_ip in {"10.0.0.30", "10.0.0.20"})
                    or (scenario == "reconnaissance_port_scan" and feature.source_ip == "10.0.0.100")
                )
            ]
            if not selected:
                raise RuntimeError(f"No expected {scenario} flow captured in run {run_number}.")
            for flow_number, feature in enumerate(selected):
                rows.append(
                    flow_to_dataset_row(
                        feature,
                        flow_id=f"run-{run_number:04d}-flow-{flow_number:02d}",
                        run_id=f"run-{run_number:04d}",
                        scenario_id=(
                            f"unseen_reconnaissance_pattern-{run_number:04d}"
                            if unseen_pattern
                            else f"{scenario}-{run_number:04d}"
                        ),
                        label=0 if scenario == "normal" else 1,
                    )
                )
        finally:
            if net is not None:
                net.stop()

    data = pd.DataFrame(rows, columns=DATASET_COLUMNS)
    anomalies = validate_dataset(data)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    data.to_csv(output, index=False)
    metadata = {
        "seed": seed,
        "requested_runs": runs,
        "rows": len(data),
        "class_counts": {str(key): int(value) for key, value in data["label"].value_counts().sort_index().items()},
        "unique_runs": int(data["run_id"].nunique()),
        "unique_scenarios": int(data["scenario_id"].nunique()),
        "unseen_pattern_rows": int(data["scenario_id"].str.startswith("unseen_").sum()),
        "anomalies": anomalies,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": "real Mininet packet capture and FlowFeatures aggregation",
        "output_path": str(output),
    }
    output.with_suffix(".metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2))
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=160)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--output", default="data/ml/controlled_flows.csv")
    args = parser.parse_args()
    generate_dataset(runs=args.runs, seed=args.seed, output_path=args.output)


if __name__ == "__main__":
    main()
