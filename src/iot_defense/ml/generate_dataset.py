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


def _start_tcp_listener(host: Any, port: int) -> str:
    """Start a temporary TCP listener inside the host namespace."""
    script = f"""
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', {port}))
    s.listen(1)
    s.settimeout(10.0)
    conn, addr = s.accept()
    conn.settimeout(5.0)
    conn.recv(1024)
    conn.sendall(b'ok')
    conn.close()
    s.close()
except socket.timeout:
    sys.exit(1)
except Exception:
    sys.exit(1)
finally:
    try:
        s.close()
    except:
        pass
"""
    cmd = (
        "python3 - <<'PY' &\n"
        f"{script}\n"
        "PY"
        " & echo $!"
    )
    return host.cmd(cmd).strip()


def _stop_tcp_listener(host: Any, pid: str) -> None:
    """Stop the temporary TCP listener."""
    host.cmd(f"kill {pid} 2>/dev/null || true")


def _normal_traffic(host: Any, target_ip: str, traffic_plan: list[dict[str, Any]], delay: float) -> str:
    plan_literal = json.dumps(traffic_plan)
    return host.cmd(
        "python3 - <<'PY'\n"
        "import socket, time, json\n"
        f"plan = json.loads('{plan_literal}')\n"
        "for item in plan:\n"
        "    protocol = socket.SOCK_DGRAM if item['proto'] == 'DGRAM' else socket.SOCK_STREAM\n"
        "    port = item['port']\n"
        "    payload = b'x' * item['size']\n"
        "    sock = socket.socket(socket.AF_INET, protocol)\n"
        "    if protocol == socket.SOCK_STREAM:\n"
        "        sock.connect(('{target_ip}', port))\n"
        "        sock.sendall(payload)\n"
        "        sock.close()\n"
        "    else:\n"
        f"        for _ in range(item['count']):\n"
        f"            sock.sendto(payload, ('{target_ip}', port))\n"
        f"            time.sleep({delay})\n"
        "        sock.close()\n"
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


def get_scenario_type(run_number: int) -> str:
    """Deterministically assign scenario type based on run number."""
    if run_number % 2 == 0:
        # Normal (normal_udp, normal_tcp, normal_mixed)
        sub_type = (run_number // 2) % 3
        if sub_type == 0: return 'normal_udp'
        if sub_type == 1: return 'normal_tcp'
        return 'normal_mixed'
    else:
        # Recon (reconnaissance_known, reconnaissance_unseen)
        # 70/30 split for known/unseen
        if (run_number // 2) % 10 < 7: return 'reconnaissance_known'
        return 'reconnaissance_unseen'

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
    
    # Benign variations
    normal_ports_pool = [5683, 1883, 80, 443, 8080, 9999, 10001]
    
    # Recon variations - split into known and unseen
    recon_known_port_sets = [
        [22, 80, 443, 8080],
        [21, 23, 53, 8080],
        [22, 80, 8000, 8443],
        [25, 110, 143, 993, 995],
        [80, 8080, 8888],
    ]
    recon_unseen_port_sets = [
        [22, 81, 444, 8081, 9000],
        [24, 88, 8008, 8444, 10080, 10443],
        [26, 808, 3000, 5000, 8888, 9001, 9443],
    ]
    
    rows: list[dict[str, Any]] = []
    aggregator = FeatureAggregator(window_seconds=3.0)
    
    successful_runs = 0
    failed_runs = []

    for run_number in range(runs):
        scenario = get_scenario_type(run_number)
        target_name, target_ip = rng.choice(target_options)
        net = None
        listener_pids = []
        
        # Stage tracking for failure accounting
        current_stage = "start_network"
        try:
            net = create_mininet_network()
            net.start()
            
            # Start capture BEFORE traffic
            current_stage = "start_monitor"
            monitor = PacketMonitor(base_dir=f"/tmp/iot-defense-dataset/run-{run_number:04d}")
            capture_path = monitor.capture_host_packets(net, target_name, packet_limit=500, capture_seconds=4)
            time.sleep(0.5) # Give tcpdump a moment to initialize
            
            current_stage = "start_traffic"
            if scenario.startswith("normal"):
                source_name, source_ip = (
                    ("smart_plug", "10.0.0.30")
                    if target_name != "smart_plug"
                    else ("camera", "10.0.0.20")
                )
                source = net.get(source_name)
                
                # Create protocol/port traffic plan based on scenario type
                traffic_plan = []
                
                # Normal TCP listeners/traffic
                if scenario in ['normal_tcp', 'normal_mixed']:
                    for _ in range(rng.randint(1, 2)):
                        port = rng.choice([80, 443, 8080, 10001])
                        traffic_plan.append({'proto': 'STREAM', 'port': port, 'count': 1, 'size': rng.randint(64, 256)})
                        pid = _start_tcp_listener(net.get(target_name), port)
                        listener_pids.append(pid)
                
                # Normal UDP traffic
                if scenario in ['normal_udp', 'normal_mixed']:
                    for _ in range(rng.randint(1, 3)):
                        port = rng.choice([5683, 1883, 9999])
                        traffic_plan.append({'proto': 'DGRAM', 'port': port, 'count': 3, 'size': rng.randint(16, 64)})
                
                delay = rng.choice([0.01, 0.05, 0.1, 0.5])
                _normal_traffic(source, target_ip, traffic_plan, delay)
            else:
                # Recon traffic
                source = net.get("attacker")
                ports = rng.choice(recon_known_port_sets if scenario == 'reconnaissance_known' else recon_unseen_port_sets)
                interval = rng.choice([0.01, 0.05, 0.1])
                _reconnaissance_traffic(source, target_ip, ports, interval)
                
            time.sleep(1.0)
            net.get(target_name).cmd("pkill tcpdump || true")
            time.sleep(0.5)
            
            current_stage = "process_capture"
            events = monitor.read_capture(net, target_name, capture_path)
            features = aggregator.aggregate(events)
            
            # Label flows
            run_rows = 0
            for feature in features:
                if feature.destination_ip == target_ip:
                    # In normal, we trust the source IP. In recon, we look for attacker IP.
                    is_recon = (scenario.startswith("reconnaissance") and feature.source_ip == "10.0.0.100")
                    is_normal = (scenario.startswith("normal") and feature.source_ip in {"10.0.0.30", "10.0.0.20"})
                    
                    if is_recon or is_normal:
                        rows.append(
                            flow_to_dataset_row(
                                feature,
                                flow_id=f"run-{run_number:04d}-flow-{len(rows):04d}",
                                run_id=f"run-{run_number:04d}",
                                scenario_id=f"{scenario}-{run_number:04d}",
                                label=1 if is_recon else 0,
                            )
                        )
                        run_rows += 1
            if run_rows == 0:
                raise RuntimeError(f"No captured flow for {scenario}")
            successful_runs += 1
        except Exception as e:
            failed_runs.append({
                "run": run_number,
                "scenario": scenario,
                "stage": current_stage,
                "error": str(e)
            })
        finally:
            # Cleanup listeners
            for pid in listener_pids:
                _stop_tcp_listener(net.get(target_name), pid)
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
        "successful_runs": successful_runs,
        "failed_runs": len(failed_runs),
        "failure_details": failed_runs,
        "rows": len(data),
        "class_counts": {str(key): int(value) for key, value in data["label"].value_counts().sort_index().items()},
        "unique_runs": int(data["run_id"].nunique()),
        "unique_scenarios": int(data["scenario_id"].nunique()),
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
