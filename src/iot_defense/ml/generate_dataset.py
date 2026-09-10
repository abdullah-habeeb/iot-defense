"""Generate labelled FlowFeatures rows from independent Mininet executions."""

from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path
from typing import Any

import pandas as pd

from iot_defense.attacks.registry import ATTACK_SCENARIOS
from iot_defense.detection.flow_features import FeatureAggregator
from iot_defense.monitoring.monitor import PacketMonitor
from iot_defense.network.topology import create_mininet_network
from iot_defense.ml.schema import DATASET_COLUMNS, flow_to_dataset_row, validate_dataset
from iot_defense.simulation.traffic import start_multi_connection_listener

# Registry key -> sub-scenario dispatch for get_scenario_type(). Each new
# attack's dataset-generation logic is inherently bespoke (its own traffic
# shape, sub-variations, and labeling condition), so this file still needs
# one branch added per new attack -- what's generic here is only the bucket
# *count*, which grows automatically as ATTACK_SCENARIOS grows.
_ATTACK_KEYS = tuple(ATTACK_SCENARIOS.keys())


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
    # The heredoc terminator ("PY") must be alone on its own line for bash to
    # recognize it -- appending " & echo $!" directly after it on the same
    # line (as this previously did) makes the terminator invalid, so the
    # shell waits forever for a line that is only "PY" and host.cmd() hangs
    # indefinitely. Backgrounding happens on the opening line; $! is read
    # with a separate command after the heredoc has properly closed.
    #
    # Mininet's host.cmd() detects a command's completion by watching for a
    # sentinel byte in the *shell's own* output stream -- so a backgrounded
    # process whose stdout/stderr are never redirected writes directly into
    # that same stream. When this listener later exits (or bash prints its
    # own job-completion notice), that output lands in the exact channel
    # every later host.cmd() call on this host reads from -- including the
    # tcpdump capture polling running on this same host -- corrupting
    # whatever that later call was trying to read. Every other backgrounded
    # command in this codebase (tcpdump in monitor.py) already redirects
    # its output for this reason; this one didn't, which is why only
    # listener-using scenarios were affected.
    log_path = f"/tmp/tcp_listener_{port}.log"
    cmd = (
        f"python3 - <<'PY' >{log_path} 2>&1 &\n"
        f"{script}\n"
        "PY\n"
        "echo $!"
    )
    pid = host.cmd(cmd).strip()
    # host.cmd() returns as soon as the listener process is backgrounded --
    # not once it has actually bound and is ready to accept. Without
    # confirming that, traffic sent immediately afterward can race the
    # listener's own socket.bind()/listen() and simply be refused, which
    # showed up as real dataset-generation runs silently capturing no
    # traffic at all for every normal_tcp/normal_mixed scenario.
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        listening = host.cmd(f"ss -ltn 'sport = :{port}' 2>/dev/null")
        if f":{port}" in listening:
            break
        time.sleep(0.05)
    return pid


def _stop_tcp_listener(host: Any, pid: str) -> None:
    """Stop the temporary TCP listener."""
    host.cmd(f"kill {pid} 2>/dev/null || true")


def _normal_traffic(host: Any, target_ip: str, traffic_plan: list[dict[str, Any]], delay: float) -> str:
    """Send the planned traffic, one item at a time.

    Each item runs in its own try/except and the TCP branch retries its
    connect a few times with a short backoff: a single refused/failed
    connection attempt (e.g. a listener that isn't quite ready yet) must
    not silently abort every remaining item in the plan, which previously
    meant one failed TCP connect could also kill unrelated queued UDP
    traffic in the same normal_mixed run with no error surfaced anywhere.
    """
    plan_literal = json.dumps(traffic_plan)
    return host.cmd(
        "python3 - <<'PY'\n"
        "import socket, time, json\n"
        f"plan = json.loads('{plan_literal}')\n"
        "for item in plan:\n"
        "    protocol = socket.SOCK_DGRAM if item['proto'] == 'DGRAM' else socket.SOCK_STREAM\n"
        "    port = item['port']\n"
        "    payload = b'x' * item['size']\n"
        "    try:\n"
        "        if protocol == socket.SOCK_STREAM:\n"
        "            sock = None\n"
        "            for attempt in range(5):\n"
        "                try:\n"
        "                    sock = socket.socket(socket.AF_INET, protocol)\n"
        "                    sock.settimeout(1.0)\n"
        f"                    sock.connect(('{target_ip}', port))\n"
        "                    break\n"
        "                except OSError:\n"
        "                    sock.close()\n"
        "                    sock = None\n"
        "                    time.sleep(0.2)\n"
        "            if sock is not None:\n"
        "                sock.sendall(payload)\n"
        "                sock.close()\n"
        "        else:\n"
        "            sock = socket.socket(socket.AF_INET, protocol)\n"
        f"            for _ in range(item['count']):\n"
        f"                sock.sendto(payload, ('{target_ip}', port))\n"
        f"                time.sleep({delay})\n"
        "            sock.close()\n"
        "    except Exception:\n"
        "        pass\n"
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


def _dos_traffic(host: Any, target_ip: str, port: int, duration: float) -> str:
    """Bounded UDP flood at a single fixed port -- the opposite signature of
    a port scan (very high rate, essentially no port diversity)."""
    return host.cmd(
        "python3 - <<'PY'\n"
        "import socket, time\n"
        "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "payload = b'x' * 64\n"
        "start = time.time()\n"
        f"while time.time() - start < {duration}:\n"
        f"    sock.sendto(payload, ('{target_ip}', {port}))\n"
        "sock.close()\n"
        "print('dos_dataset_traffic_done')\n"
        "PY"
    )


def _brute_force_traffic(host: Any, target_ip: str, port: int, duration: float, interval: float) -> str:
    """Repeated real TCP connect attempts against a single fixed port at a
    moderate, sustained rate -- unlike a scan (many ports) or a flood (one
    port, raw packet-rate burst).

    The connect timeout (0.15s) matches simulation/traffic.py's
    generate_brute_force_mininet_traffic after a live run there showed a
    0.3s timeout close to real RST latency produces barely enough packets
    to clear RuleBasedBruteForceDetector's min_packet_count -- this
    dataset-generation copy still had the old 0.3s value and, verified
    against real Mininet, was producing runs as low as 9 packets against
    a threshold of 12: a ground-truth "brute_force" label the live rule-
    based detector couldn't actually have recognized as one.

    Requires a real listener already running on `port` on the target host
    (see the call site's start_multi_connection_listener) -- without one,
    connect() is refused before sendall() ever runs, and a real captured
    flow never actually contains this function's own "USER admin" payload
    even though shape-based detection is unaffected. Found via the same
    real evaluation that caught simulation/traffic.py's identical gap;
    `interval` needs to be tuned for *successful* connections (a full
    handshake + teardown, several packets) rather than a refused one
    (SYN+immediate RST, one or two) for the same reason documented there.
    """
    return host.cmd(
        "python3 - <<'PY'\n"
        "import socket, time\n"
        "start = time.time()\n"
        f"while time.time() - start < {duration}:\n"
        "    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "    sock.settimeout(0.15)\n"
        "    try:\n"
        f"        sock.connect(('{target_ip}', {port}))\n"
        "        sock.sendall(b'USER admin\\r\\nPASS wrong\\r\\n')\n"
        "    except OSError:\n"
        "        pass\n"
        "    finally:\n"
        "        sock.close()\n"
        f"    time.sleep({interval})\n"
        "print('brute_force_dataset_traffic_done')\n"
        "PY"
    )


def _exfiltration_traffic(host: Any, attacker_ip: str, port: int, duration: float) -> str:
    """Repeated large UDP transfers from a compromised device out to an
    attacker-controlled sink. Direction is reversed from every other
    dataset scenario here: `host` is the compromised device itself (the
    traffic source), not the attacker."""
    return host.cmd(
        "python3 - <<'PY'\n"
        "import socket, time\n"
        "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "payload = b'x' * 1200\n"
        "start = time.time()\n"
        f"while time.time() - start < {duration}:\n"
        f"    sock.sendto(payload, ('{attacker_ip}', {port}))\n"
        "    time.sleep(1.0)\n"
        "sock.close()\n"
        "print('exfiltration_dataset_traffic_done')\n"
        "PY"
    )


def _exploit_traffic(host: Any, target_ip: str, port: int, duration: float) -> str:
    """A small number of oversized UDP packets -- unlike brute-force (many
    small attempts) or exfiltration (a steady small UDP trickle out),
    this attack's defining signature is payload *size*, not packet count
    or rate. Matches simulation/traffic.py's generate_exploit_mininet_
    traffic (400-byte payload, at most 4 attempts, 0.8s pauses).

    UDP, not TCP: this copy originally used TCP connect()+sendall(), the
    same mistake simulation/traffic.py's own generator had before a live
    run showed it there -- nothing listens on the target's management
    port outside an active DECOY response, so connect() is refused before
    sendall() ever runs and only bare ~74-byte SYN/RST packets get
    captured, never the actual payload. Confirmed happening here too:
    every exploit-labeled row in a real 156-run dataset had
    average_packet_size=74.0 and packet_count=4 (matching 4 refused
    connection attempts) instead of a real oversized payload. UDP's
    sendto() puts the full packet on the wire regardless of whether
    anything is listening, exactly like the other UDP-based generators
    in this file already rely on.
    """
    return host.cmd(
        "python3 - <<'PY'\n"
        "import socket, time\n"
        "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "payload = b'A' * 400\n"
        "start = time.time()\n"
        "attempts = 0\n"
        f"while time.time() - start < {duration} and attempts < 4:\n"
        f"    sock.sendto(payload, ('{target_ip}', {port}))\n"
        "    attempts += 1\n"
        "    time.sleep(0.8)\n"
        "sock.close()\n"
        "print('exploit_dataset_traffic_done')\n"
        "PY"
    )


def get_scenario_type(run_number: int) -> str:
    """Deterministically assign scenario type based on run number.

    Bucket 0 is always normal traffic; each subsequent bucket is one
    registered attack, in ATTACK_SCENARIOS order -- so the bucket count
    grows automatically as new attacks are registered. Registering a new
    attack key still requires adding its own dispatch branch below, since
    each attack's sub-variations and traffic shape are attack-specific.
    """
    num_buckets = 1 + len(_ATTACK_KEYS)
    bucket = run_number % num_buckets
    if bucket == 0:
        # Normal (normal_udp, normal_tcp, normal_mixed)
        sub_type = (run_number // num_buckets) % 3
        if sub_type == 0: return 'normal_udp'
        if sub_type == 1: return 'normal_tcp'
        return 'normal_mixed'

    attack_key = _ATTACK_KEYS[bucket - 1]
    if attack_key == "reconnaissance":
        # 70/30 split for known/unseen port sets
        if (run_number // num_buckets) % 10 < 7: return 'reconnaissance_known'
        return 'reconnaissance_unseen'
    if attack_key == "dos":
        return 'dos_flood'
    if attack_key == "brute_force":
        return 'brute_force'
    if attack_key == "exfiltration":
        return 'exfiltration'
    if attack_key == "exploit":
        return 'exploit_payload_injection'
    raise ValueError(f"No dataset-generation dispatch registered for attack key: {attack_key!r}")

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

    # DoS flood target ports -- always a single fixed port per run
    dos_target_ports = [5683, 1883, 8080, 9999]

    # Brute-force target port -- a single simulated login/management port
    brute_force_target_ports = [2222, 8022, 9022]

    # Exfiltration sink port -- a single attacker-controlled port
    exfiltration_target_ports = [4444, 5555, 6666]
    attacker_ip = "10.0.0.100"

    # Exploit target port -- a single simulated management/control port
    exploit_target_ports = [22, 7001, 7002]


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

            # Start capture BEFORE traffic. start_capture() blocks only
            # until tcpdump confirms it is actually listening (not a fixed
            # guess), and later stop_capture() guarantees termination --
            # polling for tcpdump's own completion marker with a bounded
            # timeout, falling back to SIGTERM if it hasn't hit its packet
            # limit yet -- instead of relying on a separate, unguarded
            # `pkill tcpdump` call that leaves nothing running tcpdump
            # forever if anything goes wrong before it.
            current_stage = "start_monitor"
            monitor = PacketMonitor(base_dir=f"/tmp/iot-defense-dataset/run-{run_number:04d}")
            capture_session = monitor.start_capture(net, target_name, packet_limit=500)

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

                # Normal TCP listeners/traffic. Deliberately all unprivileged
                # (>1024) ports -- binding to 80/443 inside the Mininet host
                # namespace was silently failing (permission/capability
                # issue), which killed the listener immediately and made
                # every connection attempt correctly refused no matter how
                # much retry logic wrapped the connect. The literal port
                # number carries no meaning for FlowFeatures-based training
                # data, so there's no reason to risk privileged ports here.
                if scenario in ['normal_tcp', 'normal_mixed']:
                    for _ in range(rng.randint(1, 2)):
                        port = rng.choice([8080, 8443, 8888, 10001])
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
            elif scenario.startswith("reconnaissance"):
                # Recon traffic
                source = net.get("attacker")
                ports = rng.choice(recon_known_port_sets if scenario == 'reconnaissance_known' else recon_unseen_port_sets)
                interval = rng.choice([0.01, 0.05, 0.1])
                _reconnaissance_traffic(source, target_ip, ports, interval)
            elif scenario == "dos_flood":
                # DoS flood traffic
                source = net.get("attacker")
                dos_port = rng.choice(dos_target_ports)
                _dos_traffic(source, target_ip, dos_port, duration=2.0)
            elif scenario == "brute_force":
                # Brute-force traffic -- a real listener on bf_port is
                # required (see _brute_force_traffic's docstring): without
                # one, connect() is refused before the payload is ever
                # sent. Tracked in listener_pids for the same cleanup
                # normal_tcp/normal_mixed's own listeners already use.
                source = net.get("attacker")
                bf_port = rng.choice(brute_force_target_ports)
                bf_listener_pid = start_multi_connection_listener(net.get(target_name), bf_port)
                listener_pids.append(bf_listener_pid)
                # duration=6.0 with a 0.7-0.9s interval: tuned for
                # *successful* connections (a full handshake + teardown
                # per attempt, several packets), not refused ones (a bare
                # SYN+RST, one or two) -- a live run at the old 0.1-0.2s
                # interval (tuned back when every connection here was
                # refused) measured packets_per_second well past
                # RuleBasedDosDetector's own floor, misclassifying the run
                # as a flood instead of brute-force. See
                # simulation/traffic.py's generate_brute_force_mininet_
                # traffic for the identical real-Mininet measurement this
                # mirrors.
                bf_interval = rng.choice([0.7, 0.8, 0.9])
                _brute_force_traffic(source, target_ip, bf_port, duration=6.0, interval=bf_interval)
            elif scenario == "exploit_payload_injection":
                # Exploit-payload traffic -- a few oversized requests to a
                # single management port.
                source = net.get("attacker")
                exploit_port = rng.choice(exploit_target_ports)
                _exploit_traffic(source, target_ip, exploit_port, duration=4.0)
            else:
                # Exfiltration traffic -- direction reversed: the chosen
                # target device is the compromised traffic *source*, not
                # the destination.
                source = net.get(target_name)
                exfil_port = rng.choice(exfiltration_target_ports)
                _exfiltration_traffic(source, attacker_ip, exfil_port, duration=5.0)

            current_stage = "process_capture"
            capture_path = monitor.stop_capture(net, capture_session, completion_timeout=4.0)
            events = monitor.read_capture(net, target_name, capture_path)
            features = aggregator.aggregate(events)

            # Label flows. Every scenario except exfiltration has the
            # target device as the flow's destination and the attacker (or
            # a trusted normal-traffic source) as its source; exfiltration
            # reverses that -- the target device is the flow's *source*,
            # sending out to the attacker as destination -- so it needs
            # its own direction-aware condition rather than sharing the
            # single "destination_ip == target_ip" gate the others use.
            #
            # A single stray packet (packet_count < 2, duration == 0) is
            # capture noise, not a real representative flow -- a real run
            # produced exactly this once (one packet labeled brute_force,
            # found reviewing the 130-run dataset), and training on it
            # would teach the model a signature no real traffic actually
            # has. Excluded from labeling entirely rather than kept and
            # hoped to average out.
            run_rows = 0
            for feature in features:
                if feature.packet_count < 2:
                    continue
                is_recon = (
                    scenario.startswith("reconnaissance")
                    and feature.destination_ip == target_ip
                    and feature.source_ip == "10.0.0.100"
                )
                is_dos = (
                    scenario == "dos_flood"
                    and feature.destination_ip == target_ip
                    and feature.source_ip == "10.0.0.100"
                )
                is_brute_force = (
                    scenario == "brute_force"
                    and feature.destination_ip == target_ip
                    and feature.source_ip == "10.0.0.100"
                )
                is_exfiltration = (
                    scenario == "exfiltration"
                    and feature.source_ip == target_ip
                    and feature.destination_ip == "10.0.0.100"
                )
                is_exploit = (
                    scenario == "exploit_payload_injection"
                    and feature.destination_ip == target_ip
                    and feature.source_ip == "10.0.0.100"
                )
                is_normal = (
                    scenario.startswith("normal")
                    and feature.destination_ip == target_ip
                    and feature.source_ip in {"10.0.0.30", "10.0.0.20"}
                )

                if is_recon or is_dos or is_brute_force or is_exfiltration or is_exploit or is_normal:
                    label = (
                        5 if is_exploit
                        else 4 if is_exfiltration
                        else 3 if is_brute_force
                        else 2 if is_dos
                        else 1 if is_recon
                        else 0
                    )
                    rows.append(
                        flow_to_dataset_row(
                            feature,
                            flow_id=f"run-{run_number:04d}-flow-{len(rows):04d}",
                            run_id=f"run-{run_number:04d}",
                            scenario_id=f"{scenario}-{run_number:04d}",
                            label=label,
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
