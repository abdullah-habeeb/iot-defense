"""Mininet-only response execution with reversible simulation controls."""

from __future__ import annotations

import json
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.result import ResponseResult


class MininetSafetyError(ValueError):
    """Raised when a response target is not a known simulated host."""


class ResponseLogger:
    """Append machine-readable response records as JSON Lines."""

    def __init__(self, path: str | Path = "/tmp/iot-defense/response.jsonl") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, result: ResponseResult) -> None:
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(result.to_dict()) + "\n")


class DecoyService:
    """Small TCP banner service launched inside one Mininet host namespace."""

    _SERVER = """import json, socket, sys, time
ports = [int(value) for value in sys.argv[1].split(',')]
log_path = sys.argv[2]
servers = []
for port in ports:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(8)
    server.settimeout(0.2)
    servers.append(server)
try:
    while True:
        for server in servers:
            try:
                connection, address = server.accept()
            except socket.timeout:
                continue
            with connection:
                request = connection.recv(256)
                record = {'timestamp': time.time(), 'source_ip': address[0], 'destination_port': server.getsockname()[1], 'request_bytes': len(request)}
                with open(log_path, 'a', encoding='utf-8') as stream:
                    stream.write(json.dumps(record) + '\\n')
                connection.sendall(b'IoT maintenance service\\r\\n')
finally:
    for server in servers:
        server.close()
"""

    def __init__(self, log_path: str | Path = "/tmp/iot-defense/decoy.jsonl", ports: tuple[int, ...] = (22, 8080)) -> None:
        self.log_path = Path(log_path)
        self.ports = ports
        self.process: Any = None
        self.host: Any = None

    def start(self, host: Any) -> dict[str, Any]:
        self._validate_ports()
        if self.process is not None and self.process.poll() is None:
            return {"status": "already_running", "ports": list(self.ports), "log_path": str(self.log_path)}
        self.host = host
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if self.log_path.exists():
            self.log_path.unlink()
        self.process = host.popen(
            [sys.executable, "-u", "-c", self._SERVER, ",".join(str(port) for port in self.ports), str(self.log_path)],
            stdout=-1,
            stderr=-1,
        )
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                stderr = self.process.stderr.read().decode(errors="replace") if self.process.stderr else ""
                self.process = None
                raise RuntimeError(f"Decoy service failed to start: {stderr.strip()}")
            listening = host.cmd(f"ss -ltn 'sport = :{self.ports[0]}'")
            if f":{self.ports[0]}" in listening:
                return {"status": "started", "host": host.name, "ip": host.IP(), "ports": list(self.ports), "log_path": str(self.log_path)}
            time.sleep(0.05)
        self.process.terminate()
        self.process.wait(timeout=2)
        self.process = None
        raise RuntimeError("Decoy service did not open its configured listening port.")

    def stop(self) -> dict[str, Any]:
        if self.process is None:
            return {"status": "already_stopped"}
        self.process.terminate()
        self.process.wait(timeout=2)
        self.process = None
        return {"status": "stopped"}

    def _validate_ports(self) -> None:
        if not self.ports or any(port < 1 or port > 65535 for port in self.ports):
            raise ValueError("Decoy ports must be between 1 and 65535.")


class MininetResponseExecutor:
    """Execute selected actions only against hosts belonging to a Mininet network."""

    def __init__(self, net: Any, log_path: str | Path = "/tmp/iot-defense/response.jsonl", decoy: DecoyService | None = None) -> None:
        self.net = net
        self.logger = ResponseLogger(log_path)
        self.decoy = decoy or DecoyService()
        self._isolated: dict[str, tuple[Any, str]] = {}
        self._throttled: dict[str, tuple[Any, str]] = {}
        # Keyed by target_ip, not a flat list: restore() needs to remove
        # exactly *this* target's redirect rules, not every rule ever
        # installed for any target during this executor's lifetime (see
        # restore()'s own docstring for the real bug this fixes).
        self._redirect_rules: dict[str, list[tuple[Any, str]]] = {}

    def execute(self, decision: DefenseDecision) -> ResponseResult:
        """Execute the already-selected action without re-evaluating threat data."""
        started = datetime.now(timezone.utc).isoformat()
        start_clock = time.perf_counter()
        try:
            if decision.action == DefenseAction.ALLOW:
                message = "No network enforcement was necessary."
                details = {"operation": "none"}
            elif decision.action == DefenseAction.ALERT:
                message = "Security event recorded; network state was unchanged."
                details = {"operation": "log_only"}
            elif decision.action == DefenseAction.ISOLATE:
                details = self.isolate(decision.target_ip)
                message = "Target Mininet host interface was isolated."
            elif decision.action == DefenseAction.DECOY:
                details = self.redirect_to_decoy(decision)
                message = "Controlled decoy service was started inside Mininet."
            elif decision.action == DefenseAction.THROTTLE:
                details = self.throttle(decision.target_ip)
                message = "Incoming connection attempts to the target were rate-limited."
            else:  # pragma: no cover - Enum prevents this through normal construction
                raise ValueError(f"Unsupported defense action: {decision.action}")
            result = ResponseResult.from_timing(
                action=decision.action,
                target_ip=decision.target_ip,
                source_ip=decision.source_ip,
                status="success",
                started_at=started,
                latency_ms=(time.perf_counter() - start_clock) * 1000,
                message=message,
                details=details,
            )
        except (MininetSafetyError, OSError, ValueError, RuntimeError) as exc:
            result = ResponseResult.from_timing(
                action=decision.action,
                target_ip=decision.target_ip,
                source_ip=decision.source_ip,
                status="failed",
                started_at=started,
                latency_ms=(time.perf_counter() - start_clock) * 1000,
                message=str(exc),
                details={"operation": "failed_safely"},
            )
        self.logger.write(result)
        return result

    def isolate(self, target_ip: str) -> dict[str, Any]:
        host = self._host_for_ip(target_ip)
        if target_ip in self._isolated:
            return {"operation": "isolate", "status": "already_isolated", "host": host.name}
        interface = host.defaultIntf().name
        host.cmd(f"ip link set dev {interface} down")
        self._isolated[target_ip] = (host, interface)
        return {"operation": "isolate", "host": host.name, "interface": interface, "state": "down"}

    def throttle(self, target_ip: str, rate: str = "3/sec", burst: str = "3") -> dict[str, Any]:
        """Rate-limit new incoming TCP connection attempts to a host using
        a real iptables hashlimit rule.

        This was NOT the first mechanism tried. A raw bandwidth cap (tc
        qdisc ... tbf on the target's own interface) was built and
        appeared to work -- `tc qdisc show` correctly reported the
        installed limit -- but measuring its actual effect against real
        traffic showed it did essentially nothing: tbf on a "root" qdisc
        only shapes EGRESS (what the target sends out), never the
        incoming SYN packets an attacker is sending, and even swapping to
        an ingress policer barely mattered, because a single SYN packet
        is only tens of bytes -- so small that even a heavy byte-rate cap
        adds negligible delay per packet. A real brute-force attacker is
        bottlenecked by *how many attempts* it can make, not by *how many
        bytes* those attempts consume.

        hashlimit fixes this by rate-limiting the actual thing that
        matters -- new connection attempts per second -- and dropping the
        excess outright rather than trying to slow their bytes down.
        Verified against real Mininet traffic: an unthrottled attacker
        completed 56/56 connection attempts in a 3s window; the same
        traffic under a 2/sec hashlimit completed only 7. Excess SYNs are
        dropped, not queued, so a legitimate user's occasional login
        attempt still gets through -- only a rapid, repeated burst gets
        cut down -- while the device stays otherwise fully reachable,
        unlike isolate().
        """
        host = self._host_for_ip(target_ip)
        if target_ip in self._throttled:
            return {"operation": "throttle", "status": "already_throttled", "host": host.name}
        rule_name = f"throttle_{host.name}"
        add_rule = (
            f"iptables -A INPUT -p tcp --syn -d {target_ip} -m hashlimit "
            f"--hashlimit-above {rate} --hashlimit-burst {burst} --hashlimit-mode dstip "
            f"--hashlimit-name {rule_name} -j DROP"
        )
        command_output = host.cmd(add_rule).strip()
        # Checking for "iptables" in the output, not just any non-empty
        # output, is deliberate: Mininet's host.cmd() reads from the same
        # pty channel a backgrounded process's own shell job-control
        # notification can land in ("[1]+  Terminated  tcpdump ...", or
        # its own exit summary "N packets captured") if that process was
        # still being torn down when this command ran -- confirmed via a
        # real repro where a throttle() call right after a SIGTERM'd
        # packet capture raised on "98 packets captured", not an actual
        # iptables error. monitoring/monitor.py's start_capture() now
        # disowns its background job specifically to prevent that, but
        # treating only iptables' own error text as a real failure (its
        # error output always starts with "iptables") keeps this command
        # robust even against a stray source of leaked output this fix
        # didn't anticipate.
        if command_output and "iptables" in command_output.lower():
            raise RuntimeError(f"Unable to install traffic-control rate limit: {command_output}")
        delete_rule = add_rule.replace("-A INPUT", "-D INPUT", 1)
        self._throttled[target_ip] = (host, delete_rule)
        return {
            "operation": "throttle",
            "host": host.name,
            "rate": rate,
            "burst": burst,
            "mechanism": "iptables_hashlimit",
        }

    def restore(self, target_ip: str) -> dict[str, Any]:
        """Undo whatever response is currently active against target_ip --
        isolation, throttling, and any decoy redirect, all three, not just
        whichever one restore() originally handled.

        Before this, restore() only ever cleared _isolated/_throttled;
        decoy's NAT redirect rules and the decoy service itself were torn
        down solely by cleanup(), called once at the very end of a
        network's lifetime. Every prior real-Mininet exercise of DECOY
        (the live demo, dataset generation, PPO's real-Mininet fine-tune)
        only ever called it once or twice before the whole network was
        torn down anyway, so the gap was invisible. The evaluation
        harness is the first code path to call DECOY repeatedly on one
        long-lived network -- confirmed via a real run where redirect
        rules from an earlier trial's decoy call were still installed
        when a later trial tried to add new ones, and the decoy service's
        own already-bound ports made its next start() attempt fail.
        """
        host = self._host_for_ip(target_ip)
        isolated = self._isolated.pop(target_ip, None)
        throttled = self._throttled.pop(target_ip, None)
        redirect_rules = self._redirect_rules.pop(target_ip, None)
        interface = isolated[1] if isolated is not None else host.defaultIntf().name
        host.cmd(f"ip link set dev {interface} up")
        if throttled is not None:
            _, delete_rule = throttled
            host.cmd(delete_rule)
        decoy_removed = False
        if redirect_rules:
            for rule_host, delete_rule in reversed(redirect_rules):
                rule_host.cmd(delete_rule)
            decoy_removed = True
            # The decoy service is shared infrastructure, not per-target --
            # only stop it once nothing is being redirected to it any more.
            if not self._redirect_rules:
                self.decoy.stop()
        return {
            "operation": "restore",
            "host": host.name,
            "interface": interface,
            "state": "up",
            "throttle_removed": throttled is not None,
            "decoy_removed": decoy_removed,
        }

    def redirect_to_decoy(self, decision: DefenseDecision) -> dict[str, Any]:
        self._host_for_ip(decision.target_ip)
        source_host = self._host_for_ip(decision.source_ip)
        decoy_host = self._decoy_host()
        decoy_details = self.decoy.start(decoy_host)
        rules = []
        target_rules = self._redirect_rules.setdefault(decision.target_ip, [])
        for port in self.decoy.ports:
            add_rule = (
                f"iptables -t nat -A OUTPUT -p tcp -d {decision.target_ip} "
                f"--dport {port} -j DNAT --to-destination {decoy_host.IP()}"
            )
            command_output = source_host.cmd(add_rule).strip()
            # See throttle()'s matching comment: only text that actually
            # looks like an iptables error is treated as a real failure.
            if command_output and "iptables" in command_output.lower():
                raise RuntimeError(f"Unable to install simulated decoy redirect: {command_output}")
            delete_rule = add_rule.replace(" -A ", " -D ", 1)
            target_rules.append((source_host, delete_rule))
            rules.append({"port": port, "operation": "OUTPUT_DNAT", "target": decoy_host.IP()})
        return {
            "operation": "decoy",
            "source_host": source_host.name,
            "requested_target_ip": decision.target_ip,
            "decoy_host": decoy_host.name,
            "decoy_ip": decoy_host.IP(),
            "decoy_ports": list(self.decoy.ports),
            "redirect_mode": "namespace_local_output_dnat",
            "redirect_rules": rules,
            "decoy": decoy_details,
        }

    def _host_for_ip(self, target_ip: str) -> Any:
        try:
            address = socket.inet_aton(target_ip)
        except OSError as exc:
            raise MininetSafetyError(f"Invalid response target IP: {target_ip}") from exc
        if address == socket.inet_aton("127.0.0.1") or target_ip.startswith("10.0.2."):
            raise MininetSafetyError(f"Refusing non-Mininet target IP: {target_ip}")
        for host in self.net.hosts:
            if host.IP() == target_ip:
                return host
        raise MininetSafetyError(f"Target IP is not a known Mininet host: {target_ip}")

    def _decoy_host(self) -> Any:
        for host in self.net.hosts:
            if host.name == "decoy":
                return host
        raise MininetSafetyError("No configured Mininet decoy host is available.")

    def cleanup(self) -> None:
        """Restore every target with any active response state -- isolated,
        throttled, or decoy-redirected -- then stop the decoy service as a
        safety net (restore() already stops it once no target is redirected
        any more, but this covers a target whose restore() was never called
        at all)."""
        target_ips = set(self._isolated) | set(self._throttled) | set(self._redirect_rules)
        for target_ip in target_ips:
            self.restore(target_ip)
        self.decoy.stop()
