"""Mininet-only response execution with reversible simulation controls."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
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
        try:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                # A stuck terminate() must not leave self.process pointing
                # at a process this instance believes is still "running" --
                # the next start() call would see poll() is None and
                # report "already_running" without actually starting a
                # fresh decoy, even though the old one is on its way out
                # (or already unreachable). Escalate and reap it for real.
                self.process.kill()
                self.process.wait(timeout=2)
            return {"status": "stopped"}
        finally:
            self.process = None

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
        # One target can accumulate more than one blocked source over the
        # executor's lifetime (a second trial reusing the same target),
        # so this is a list per target, not a single tuple -- mirrors
        # _redirect_rules' own reasoning above.
        self._blocked_sources: dict[str, list[tuple[Any, str, str]]] = {}
        self._quarantined: dict[str, tuple[Any, list[str]]] = {}
        self._bandwidth_capped: dict[str, tuple[Any, str]] = {}

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
                protocol = (
                    decision.context.get("beliefs", {}).get("observed_features", {}).get("protocol", "TCP")
                )
                details = self.throttle(decision.target_ip, protocol=protocol)
                message = "Incoming connection attempts to the target were rate-limited."
            elif decision.action == DefenseAction.BLOCK_SOURCE:
                details = self.block_source(decision.target_ip, decision.source_ip)
                message = "The identified attacker source was blocked at the target."
            elif decision.action == DefenseAction.QUARANTINE:
                details = self.quarantine(decision.target_ip, decision.source_ip)
                message = "Target was quarantined to a default-deny allowlist of known-legitimate peers."
            elif decision.action == DefenseAction.RESET_SESSIONS:
                details = self.reset_sessions(decision.target_ip, decision.source_ip)
                message = "Live connections between the target and the attacker source were terminated."
            elif decision.action == DefenseAction.FORENSIC_CAPTURE:
                details = self.forensic_capture(decision.target_ip, decision.source_ip)
                message = "Evidence was captured without disrupting target service."
            elif decision.action == DefenseAction.BANDWIDTH_CAP:
                details = self.bandwidth_cap(decision.target_ip, decision.source_ip)
                message = "The attacker's own outbound bandwidth was capped."
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
        """Take the target's interface down for real, and confirm it, not
        just fire the command and assume it worked. Every other action in
        this class already verifies its own real effect -- throttle()
        checks its iptables command's output for error text, DecoyService
        .start() polls until the port is genuinely listening -- isolate()
        used to be the one exception, unconditionally reporting
        "state": "down" even if `ip link set ... down` silently failed
        (a stale interface name, a permission issue, or the same kind of
        leaked-shell-output pty corruption already found and fixed
        elsewhere in this project this session). host.cmd() never raises
        on a failed command, so nothing would have surfaced that."""
        host = self._host_for_ip(target_ip)
        if target_ip in self._isolated:
            return {"operation": "isolate", "status": "already_isolated", "host": host.name}
        interface = host.defaultIntf().name
        host.cmd(f"ip link set dev {interface} down")
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            status = host.cmd(f"ip link show dev {interface}")
            if "state DOWN" in status:
                self._isolated[target_ip] = (host, interface)
                return {"operation": "isolate", "host": host.name, "interface": interface, "state": "down"}
            time.sleep(0.05)
        raise RuntimeError(f"Failed to bring interface {interface} down on host {host.name}.")

    def throttle(self, target_ip: str, rate: str = "3/sec", burst: str = "3", protocol: str = "TCP") -> dict[str, Any]:
        """Rate-limit new incoming connection attempts (or, for
        connectionless protocols, incoming packets) to a host using a
        real iptables hashlimit rule.

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
        bytes* those attempts consume. (BANDWIDTH_CAP below revisits this
        same tc/tbf mechanism, applied instead to the *attacker's* own
        egress interface for attacks it actually fits -- bulk-payload
        floods, not tiny per-packet ones.)

        hashlimit fixes this by rate-limiting the actual thing that
        matters -- new connection attempts per second -- and dropping the
        excess outright rather than trying to slow their bytes down.
        Verified against real Mininet traffic: an unthrottled attacker
        completed 56/56 connection attempts in a 3s window; the same
        traffic under a 2/sec hashlimit completed only 7. Excess packets
        are dropped, not queued, so a legitimate user's occasional
        request still gets through -- only a rapid, repeated burst gets
        cut down -- while the device stays otherwise fully reachable,
        unlike isolate().

        `protocol` matters and defaults to TCP for backward compatibility,
        but must be passed explicitly for anything else: the original
        version of this rule hardcoded `-p tcp --syn`, which matches
        precisely zero packets of a UDP or ICMP flood -- found via a live
        run where icmp_ping_flood's own THROTTLE response reported
        "success" (no iptables error) while doing nothing at all to the
        actual ICMP traffic, since the installed rule could never match
        it. ICMP has no per-connection "new attempt" concept the way TCP
        SYNs or UDP's first-packet-of-a-flow do, so its rule rate-limits
        raw echo-request packets directly rather than "new connections".
        """
        host = self._host_for_ip(target_ip)
        if target_ip in self._throttled:
            return {"operation": "throttle", "status": "already_throttled", "host": host.name}
        rule_name = f"throttle_{host.name}"
        protocol_match = {
            "TCP": "-p tcp --syn",
            "UDP": "-p udp",
            "ICMP": "-p icmp --icmp-type echo-request",
        }.get(protocol.upper(), "-p tcp --syn")
        add_rule = (
            f"iptables -A INPUT {protocol_match} -d {target_ip} -m hashlimit "
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
            "protocol": protocol.upper(),
            "mechanism": "iptables_hashlimit",
        }

    def block_source(self, target_ip: str, source_ip: str) -> dict[str, Any]:
        """Drop all inbound traffic from one specific, already-identified
        source at the target -- a real iptables per-source DROP rule.

        Structurally different from both existing containment actions:
        THROTTLE rate-limits *everyone* hitting the target (a legitimate
        user's occasional request can still get dropped in the burst);
        ISOLATE cuts the target off from *everyone*. BLOCK_SOURCE blocks
        exactly the identified attacker's address and nothing else, so a
        legitimate user on a different address is completely unaffected
        throughout -- strictly less collateral than either, whenever the
        attack genuinely has one identifiable, persistent source (true of
        this lab's brute_force and credential_replay traffic, both driven
        from one fixed attacker host). It is NOT a general replacement
        for THROTTLE: a real distributed/botnet-driven brute force has no
        single source to block, which is exactly the case THROTTLE still
        exists to cover.

        Only meaningful when source_ip is genuinely the attacker's own
        address, which is why this is never the preferred_action for the
        registry's reversed-direction attacks (data_exfiltration,
        dns_tunneling_exfiltration, firmware_tampering): for those,
        beliefs.source_device is the attacker's *destination* for the
        leak, and the actual malicious traffic is the compromised
        device's own outbound flow -- an INPUT-chain drop of the
        attacker's address would block their replies, not the leak
        itself.
        """
        host = self._host_for_ip(target_ip)
        existing = self._blocked_sources.get(target_ip, [])
        if any(blocked_source == source_ip for _, _, blocked_source in existing):
            return {"operation": "block_source", "status": "already_blocked", "host": host.name, "source_ip": source_ip}
        add_rule = f"iptables -A INPUT -s {source_ip} -d {target_ip} -j DROP"
        command_output = host.cmd(add_rule).strip()
        if command_output and "iptables" in command_output.lower():
            raise RuntimeError(f"Unable to install source block: {command_output}")
        deadline = time.monotonic() + 2.0
        installed = False
        while time.monotonic() < deadline:
            rule_table = host.cmd("iptables -L INPUT -n")
            if source_ip in rule_table and "DROP" in rule_table:
                installed = True
                break
            time.sleep(0.05)
        if not installed:
            raise RuntimeError(f"Source block rule for {source_ip} did not appear in iptables -L INPUT.")
        delete_rule = add_rule.replace("-A INPUT", "-D INPUT", 1)
        self._blocked_sources.setdefault(target_ip, []).append((host, delete_rule, source_ip))
        return {"operation": "block_source", "host": host.name, "source_ip": source_ip, "mechanism": "iptables_source_drop"}

    def quarantine(self, target_ip: str, source_ip: str) -> dict[str, Any]:
        """Default-deny containment: the target keeps talking only to the
        network's other known-legitimate hosts (every registered Mininet
        host except the target itself and the identified attacker
        source), everything else dropped -- real iptables default DROP
        policy on both INPUT and OUTPUT with explicit ACCEPT rules
        allowlisting the legitimate peers, installed before the DROP-all
        rules so they win on iptables' own first-match evaluation order.

        Deliberately a different POLICY STRUCTURE from both existing
        containment actions, not just a different parameter on the same
        one: ISOLATE takes the interface down (nothing reaches the target
        at all, including legitimate peers); BLOCK_SOURCE is default-
        ALLOW with one address denied. QUARANTINE is default-DENY with an
        explicit allowlist -- appropriate for a device that's confirmed
        compromised but still needs to stay reachable for remediation
        (firmware_tampering's own use case: the device can still receive
        a corrective push from a legitimate peer while cut off from
        whatever it was tampering towards). On this lab's own flat
        5-host topology the practical reachability set this produces
        looks similar to BLOCK_SOURCE's; the two remain genuinely
        different mechanisms; a larger or differently-trusted topology is
        exactly where that policy-structure difference would start to
        matter in practice, not the specific 5-host lab network.
        """
        host = self._host_for_ip(target_ip)
        if target_ip in self._quarantined:
            return {"operation": "quarantine", "status": "already_quarantined", "host": host.name}
        allowed_ips = sorted(
            {h.IP() for h in self.net.hosts if h.IP() not in (target_ip, source_ip)}
        )
        delete_rules: list[str] = []
        for allowed_ip in allowed_ips:
            for chain, add_rule in (
                ("INPUT", f"iptables -A INPUT -s {allowed_ip} -j ACCEPT"),
                ("OUTPUT", f"iptables -A OUTPUT -d {allowed_ip} -j ACCEPT"),
            ):
                host.cmd(add_rule)
                delete_rules.append(add_rule.replace(f"-A {chain}", f"-D {chain}", 1))
        deny_in = "iptables -A INPUT -j DROP"
        deny_out = "iptables -A OUTPUT -j DROP"
        host.cmd(deny_in)
        host.cmd(deny_out)
        delete_rules.append(deny_in.replace("-A INPUT", "-D INPUT", 1))
        delete_rules.append(deny_out.replace("-A OUTPUT", "-D OUTPUT", 1))
        deadline = time.monotonic() + 2.0
        installed = False
        while time.monotonic() < deadline:
            input_rules = host.cmd("iptables -L INPUT -n")
            output_rules = host.cmd("iptables -L OUTPUT -n")
            if "DROP" in input_rules and "DROP" in output_rules:
                installed = True
                break
            time.sleep(0.05)
        if not installed:
            raise RuntimeError(f"Quarantine default-deny policy did not appear on host {host.name}.")
        self._quarantined[target_ip] = (host, delete_rules)
        return {
            "operation": "quarantine",
            "host": host.name,
            "allowed_ips": allowed_ips,
            "denied_source": source_ip,
            "mechanism": "iptables_default_deny_allowlist",
        }

    def reset_sessions(self, target_ip: str, source_ip: str) -> dict[str, Any]:
        """Forcibly terminate any live TCP connection(s) between source_ip
        and target_ip using `ss -K` (kernel socket destruction over
        netlink), rather than installing any standing firewall rule.

        Genuinely different in *kind* from every other response here: it
        is a one-time point action with no lasting state to restore
        afterward (restore() has nothing to undo for this action --
        there's no rule to remove, the connection is just gone and a
        fresh one is free to open normally). Purpose-built for the
        registry's one genuinely session-oriented attack,
        buffer_overflow_probe: that attack sends its entire oversized-
        payload campaign over ONE persistent TCP connection, so killing
        exactly that connection stops the campaign outright without
        touching the target's interface or any other traffic -- a more
        surgical response than ISOLATE for an attack whose real mechanism
        is "one long-lived connection", not "many separate attempts" the
        way brute_force or a flood is.
        """
        host = self._host_for_ip(target_ip)
        kill_output = host.cmd(f"ss -K dst {source_ip}").strip()
        deadline = time.monotonic() + 2.0
        cleared = False
        while time.monotonic() < deadline:
            # `ss -tn state established dst ADDR` already filters down to
            # only established connections to that address, so any row
            # beyond the header means "still established" -- no state
            # column to look for (confirmed via a real live run: with a
            # plain -tn, ss never prints a State/ESTAB column at all, only
            # "Recv-Q Send-Q Local Address:Port  Peer Address:Port
            # Process"). An earlier version of this check tried to
            # exclude the header by assuming it started with "State",
            # which a real run showed was never true -- the header always
            # survived into remaining_lines, so this reported "still
            # established" on every call regardless of whether ss -K had
            # actually cleared the connection (confirmed live: ss -K
            # genuinely destroys the socket -- verified directly against
            # a real connection, with ss -tn showing zero data rows
            # immediately after).
            remaining = host.cmd(f"ss -tn state established dst {source_ip}").strip()
            remaining_lines = [
                line for line in remaining.splitlines() if line and not line.startswith("Recv-Q")
            ]
            if not remaining_lines:
                cleared = True
                break
            time.sleep(0.05)
        if not cleared:
            raise RuntimeError(f"Connections to {source_ip} on host {host.name} were still established after ss -K.")
        return {
            "operation": "reset_sessions",
            "host": host.name,
            "source_ip": source_ip,
            "mechanism": "ss_kill",
            "kill_output": kill_output,
        }

    # A classic libpcap global header alone is exactly this many bytes --
    # a capture that opened and closed having seen zero packets is still
    # this large on disk, so "real evidence" must mean strictly more than
    # this, not just a non-empty file.
    _PCAP_HEADER_SIZE = 24

    def forensic_capture(
        self,
        target_ip: str,
        source_ip: str,
        duration_seconds: float = 5.0,
        evidence_dir: str | Path = "/tmp/iot-defense/forensics",
        detection_capture_dir: str | Path = "/tmp/iot-defense",
    ) -> dict[str, Any]:
        """Preserve evidence without disrupting service: real traffic
        copied from the detection pipeline's own already-captured pcap
        (falling back to a fresh live capture only if none is available),
        plus a companion text snapshot of live connection/neighbor state
        (`ss -tapn`, `ip neigh`) -- all real files written to evidence_dir.

        This originally always opened a FRESH live capture here, which
        turned out to be structurally unable to produce real evidence: a
        response only ever runs after detection has already classified
        the attack's *complete* capture, meaning the attack's own traffic
        generation has already finished by the time this method starts --
        a fresh capture opened now sees a quiet network. Confirmed via a
        real live run: every one of several real rogue_config_beacon
        responses produced an exact 24-byte pcap (a valid but empty
        capture -- see _PCAP_HEADER_SIZE above), and the original
        `size > 0` check couldn't tell that apart from real evidence,
        since a pcap's own header is already non-zero bytes.

        PacketMonitor's own detection capture already contains the real
        attack traffic and sits at a fixed, predictable path
        (`{detection_capture_dir}/{host.name}_capture.pcap`) that
        survives until the *next* capture starts -- copying it here is
        both more honest and more useful than a doomed fresh capture of
        silence. A fresh capture is still attempted as a fallback (real
        value if source_ip happens to still be active, or in a context
        with no prior detection capture at all); either way, verification
        now genuinely requires real captured bytes, not just a file.
        """
        host = self._host_for_ip(target_ip)
        evidence_path = Path(evidence_dir)
        evidence_path.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        pcap_path = evidence_path / f"{host.name}_{stamp}.pcap"
        state_path = evidence_path / f"{host.name}_{stamp}_state.txt"

        preserved_from_detection = False
        detection_capture = Path(detection_capture_dir) / f"{host.name}_capture.pcap"
        if detection_capture.exists() and detection_capture.stat().st_size > self._PCAP_HEADER_SIZE:
            shutil.copy2(detection_capture, pcap_path)
            preserved_from_detection = True
        else:
            interface = host.defaultIntf().name
            capture_cmd = (
                f"timeout {duration_seconds + 1:.0f} tcpdump -i {interface} -w {pcap_path} "
                f"'host {source_ip}' >{evidence_path}/{host.name}_{stamp}.log 2>&1 & disown"
            )
            host.cmd(capture_cmd)
            time.sleep(duration_seconds)

        state_output = host.cmd("ss -tapn") + "\n---\n" + host.cmd("ip neigh")
        state_path.write_text(state_output, encoding="utf-8")

        deadline = time.monotonic() + 2.0
        captured = False
        while time.monotonic() < deadline:
            if pcap_path.exists() and pcap_path.stat().st_size > self._PCAP_HEADER_SIZE:
                captured = True
                break
            time.sleep(0.1)
        if not captured:
            raise RuntimeError(
                f"Forensic capture produced no real evidence at {pcap_path} -- no prior "
                "detection capture was available to preserve, and the live capture window "
                "saw no matching traffic."
            )
        return {
            "operation": "forensic_capture",
            "host": host.name,
            "source_ip": source_ip,
            "pcap_path": str(pcap_path),
            "state_path": str(state_path),
            "preserved_from_detection": preserved_from_detection,
            "mechanism": "detection_capture_preserved" if preserved_from_detection else "tcpdump_plus_state_snapshot",
        }

    def bandwidth_cap(
        self, target_ip: str, source_ip: str, rate: str = "50kbit", burst: str = "5kb", latency: str = "400ms"
    ) -> dict[str, Any]:
        """Cap the attacker's own outbound bandwidth using a real tc tbf
        egress qdisc installed on the *attacker's* interface, not the
        target's.

        THROTTLE's own docstring already documents why a tc/tbf bandwidth
        cap failed as a response applied to the target's ingress: a
        single SYN or small UDP packet is too few bytes for a byte-rate
        cap to meaningfully delay. That reasoning flips for an attack
        whose real mechanism IS bulk byte volume rather than packet
        count -- dns_amplification's reflected UDP responses are ~570
        bytes each, sent rapidly -- and applying the cap at its real
        source (the attacker/reflector's own egress) rather than the
        target's ingress means it constrains the actual thing generating
        the flood, not a side effect of it.

        `tc qdisc show` confirming the installed tbf entry only proves
        the rule exists, not that it does anything -- the same
        false-success risk THROTTLE's own docstring warns about. Real
        verification needs to measure DELIVERED throughput at the
        destination, not how long the attacker's own sendto() calls
        take: UDP's sendto() is fire-and-forget and returns immediately
        regardless of any qdisc downstream, so send-side timing before
        vs. after installing the cap shows no real difference (confirmed
        directly -- measuring it that way gave 3.7ms uncapped vs. 2.5ms
        capped, i.e. nothing, on a burst of 300 sends). What tbf actually
        does is drop the excess at its own queue once its burst
        allowance is exceeded, which only shows up in what the
        *receiver* actually gets: a real 300-packet UDP burst from the
        attacker to a listening receiver measured 300/300 delivered
        uncapped vs. 20/300 delivered under this same 50kbit/5kb-burst
        cap -- a real, large, measured drop in delivered volume, not an
        inert rule.

        Keyed by target_ip, not source_ip, even though the qdisc itself
        lives on the attacker's interface -- mirrors redirect_to_decoy's
        own _redirect_rules convention below, for the same reason:
        restore(target_ip) is the only calling convention every real call
        site (demo/controller.py, ppo_real_env.py, cleanup()) actually
        uses, keyed off the incident's target, not whichever host a given
        response happens to act on.
        """
        host = self._host_for_ip(source_ip)
        if target_ip in self._bandwidth_capped:
            return {"operation": "bandwidth_cap", "status": "already_capped", "host": host.name}
        interface = host.defaultIntf().name
        add_qdisc = f"tc qdisc add dev {interface} root tbf rate {rate} burst {burst} latency {latency}"
        command_output = host.cmd(add_qdisc).strip()
        if command_output and ("error" in command_output.lower() or "invalid" in command_output.lower()):
            raise RuntimeError(f"Unable to install bandwidth cap: {command_output}")
        deadline = time.monotonic() + 2.0
        installed = False
        while time.monotonic() < deadline:
            qdisc_state = host.cmd(f"tc qdisc show dev {interface}")
            if "tbf" in qdisc_state:
                installed = True
                break
            time.sleep(0.05)
        if not installed:
            raise RuntimeError(f"tbf qdisc did not appear on {interface} after installation.")
        self._bandwidth_capped[target_ip] = (host, interface)
        return {"operation": "bandwidth_cap", "host": host.name, "interface": interface, "rate": rate, "mechanism": "tc_tbf_egress"}

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
        blocked_sources = self._blocked_sources.pop(target_ip, None)
        quarantined = self._quarantined.pop(target_ip, None)
        bandwidth_capped = self._bandwidth_capped.pop(target_ip, None)
        interface = isolated[1] if isolated is not None else host.defaultIntf().name
        host.cmd(f"ip link set dev {interface} up")
        if throttled is not None:
            _, delete_rule = throttled
            host.cmd(delete_rule)
        if blocked_sources:
            for rule_host, delete_rule, _source_ip in blocked_sources:
                rule_host.cmd(delete_rule)
        if quarantined is not None:
            _, delete_rules = quarantined
            for delete_rule in reversed(delete_rules):
                host.cmd(delete_rule)
        if bandwidth_capped is not None:
            capped_host, capped_interface = bandwidth_capped
            capped_host.cmd(f"tc qdisc del dev {capped_interface} root")
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
            "block_source_removed": bool(blocked_sources),
            "quarantine_removed": quarantined is not None,
            "bandwidth_cap_removed": bandwidth_capped is not None,
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
        throttled, blocked, quarantined, bandwidth-capped, or decoy-
        redirected -- then stop the decoy service as a safety net
        (restore() already stops it once no target is redirected any
        more, but this covers a target whose restore() was never called
        at all)."""
        target_ips = (
            set(self._isolated)
            | set(self._throttled)
            | set(self._redirect_rules)
            | set(self._blocked_sources)
            | set(self._quarantined)
            | set(self._bandwidth_capped)
        )
        for target_ip in target_ips:
            self.restore(target_ip)
        self.decoy.stop()
