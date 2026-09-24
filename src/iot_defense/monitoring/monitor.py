"""Packet capture and observation helpers for real Mininet traffic."""

from __future__ import annotations

import itertools
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any

from scapy.all import Packet, rdpcap

_PID_RE = re.compile(r"^\d+$")


class PacketMonitor:
    """Capture packets from a Mininet host and convert them into structured events."""

    def __init__(self, base_dir: str | Path = "/tmp/iot-defense") -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        # A monotonic counter, not a fixed per-host filename: found via a
        # real repro (evaluation/adaptive.py's multi-round campaigns) that
        # reusing the same capture_path/log_path for every call on a given
        # host lets a not-yet-terminated tcpdump from an earlier round keep
        # writing into the very file a later round is about to read,
        # corrupting or zeroing that round's capture. A zombie process from
        # one round no longer has anywhere to collide with a later one.
        self._session_counter = itertools.count()

    def capture_host_packets(self, net: Any, host_name: str, packet_limit: int = 25, capture_seconds: int = 8) -> str:
        """Launch tcpdump on a host interface and return the capture filepath."""
        host = net.get(host_name)
        interface = host.defaultIntf().name
        capture_path = str(self.base_dir / f"{host_name}_capture.pcap")
        if os.path.exists(capture_path):
            os.remove(capture_path)

        command = (
            f"tcpdump -i {interface} -nn -s 0 -c {packet_limit} -w {capture_path} "
            f">/tmp/{host_name}_tcpdump.log 2>&1 & disown; echo $!"
        )
        host.cmd(command)
        time.sleep(capture_seconds)
        return capture_path

    def start_capture(
        self, net: Any, host_name: str, packet_limit: int = 25, watchdog_seconds: float | None = None
    ) -> dict[str, Any]:
        """Launch tcpdump and block only until it confirms it is actually listening.

        Unlike capture_host_packets, this does not sleep for a fixed window --
        it waits for tcpdump's own "listening on ..." line, so the caller can
        safely start generating traffic the moment capture is truly active
        instead of guessing how long startup takes.

        watchdog_seconds, when given, wraps tcpdump in `timeout` -- a real,
        previously-missing safety net for a genuinely hung capture or a
        generate_traffic() call that never returns, neither of which
        anything currently bounds (stop_capture()'s own completion_timeout
        only starts counting *after* generate_traffic() has already
        returned). Deliberately NOT AttackScenario.capture_duration_seconds'
        own value directly -- that field is consistently *smaller* than
        capture_completion_timeout for every registered attack (it predates
        that field and was never reconciled with it; see
        test_capture_duration_seconds_stays_under_completion_timeout in
        test_attack_registry.py for the newly-enforced invariant), so using
        it here directly would kill every capture before stop_capture() ever
        gets a fair chance. Callers should pass something safely larger than
        their own completion_timeout instead (e.g. completion_timeout + 60).
        """
        host = net.get(host_name)
        interface = host.defaultIntf().name
        session_id = f"{os.getpid()}_{next(self._session_counter)}"
        capture_path = str(self.base_dir / f"{host_name}_capture_{session_id}.pcap")
        log_path = f"/tmp/{host_name}_tcpdump_{session_id}.log"

        # `disown` after backgrounding, not just output redirection: when
        # stop_capture() has to SIGTERM this process (its packet limit
        # wasn't reached in time), bash's own job-control notification for
        # the now-terminated background job ("[1]+  Terminated  tcpdump...")
        # is printed by the shell itself, not by tcpdump -- so redirecting
        # tcpdump's own stdout/stderr to log_path never touches it. That
        # notification lands in the same pty channel Mininet's host.cmd()
        # reads from on its *next* call on this host, corrupting whatever
        # that later, unrelated command was trying to read. Confirmed via a
        # real repro: a throttle() call issued right after a SIGTERM'd
        # capture raised "Unable to install traffic-control rate limit: 98
        # packets captured" -- tcpdump's own exit summary, misread as
        # iptables error output. disown removes the job from the shell's
        # job table so its completion is never reported at all.
        tcpdump_cmd = f"tcpdump -i {interface} -nn -s 0 -c {packet_limit} -w {capture_path}"
        if watchdog_seconds is not None:
            tcpdump_cmd = f"timeout {watchdog_seconds}s {tcpdump_cmd}"
        command = f"{tcpdump_cmd} >{log_path} 2>&1 & disown; echo $!"
        pid = host.cmd(command).strip()
        self._wait_for_log_marker(host, log_path, "listening on", timeout=2.0)
        return {"capture_path": capture_path, "log_path": log_path, "pid": pid, "host_name": host_name}

    def stop_capture(self, net: Any, session: dict[str, Any], completion_timeout: float = 6.0) -> str:
        """Block until tcpdump has actually exited and flushed its pcap file.

        Polls for tcpdump's own exit summary ("... packets captured") instead
        of assuming a fixed sleep was long enough -- reading the pcap file
        before tcpdump has flushed it produces a truncated/unparseable
        capture even when packets were genuinely captured. If tcpdump has not
        hit its packet limit within completion_timeout, it is sent SIGTERM.

        A low-traffic capture (e.g. a handful of benign packets) leaves
        tcpdump mostly idle, blocked in libpcap's own read loop between
        packets -- it doesn't always notice and act on SIGTERM instantly,
        so a short grace window after sending it isn't always long enough
        even though the signal itself was delivered. A high-traffic capture
        doesn't have this problem, since its read loop is cycling
        constantly and reacts to the signal almost immediately -- which is
        exactly why this only ever showed up on low-traffic captures. The
        grace window is generous enough to cover that, and SIGKILL is a
        last-resort fallback that guarantees the process is gone (accepting
        a possibly-truncated file over hanging indefinitely) so this method
        never returns while tcpdump might still be mid-write.
        """
        host = net.get(session["host_name"])
        log_path = session["log_path"]
        capture_path = session["capture_path"]
        completed = self._wait_for_log_marker(host, log_path, "packets captured", timeout=completion_timeout)
        if not completed:
            # host.cmd()'s return value for the original launch command has
            # been observed, in a real repro, to come back contaminated
            # with stray output from an unrelated prior command sharing
            # this host's pty channel -- a corrupted/multi-line "pid" then
            # makes `kill -TERM {pid}` a no-op against the real tcpdump,
            # which keeps running (see the module docstring's own capture_
            # path/log_path uniqueness fix, the other half of this same
            # failure). pkill -f against this session's own unique
            # capture_path is correct regardless of whether pid is trustworthy,
            # since no other process (this run's or any concurrent one) will
            # ever share that exact, once-only filename. The raw pid kill
            # stays as a first attempt (cheaper, no process-table scan) with
            # this as the real fallback, not the only mechanism.
            pid = session.get("pid", "")
            if _PID_RE.match(pid):
                host.cmd(f"kill -TERM {pid} 2>/dev/null")
            host.cmd(f"pkill -TERM -f {capture_path} 2>/dev/null")
            completed = self._wait_for_log_marker(host, log_path, "packets captured", timeout=3.0)
            if not completed:
                if _PID_RE.match(pid):
                    host.cmd(f"kill -KILL {pid} 2>/dev/null")
                host.cmd(f"pkill -KILL -f {capture_path} 2>/dev/null")
                time.sleep(0.3)
        # Some callers (harness.py's _preserve_pcap, executor.py's
        # FORENSIC_CAPTURE) intentionally read from the conventional,
        # host-fixed path rather than this session's own unique one --
        # both predate per-session uniqueness and document relying on it
        # being "the latest capture" for this host. Keep that contract:
        # mirror this session's real capture there too, best-effort (a
        # capture that never actually produced a file, e.g. a fully
        # SIGKILL'd empty run, leaves the fixed path exactly as absent as
        # it always would have been -- not a new failure mode).
        if os.path.exists(capture_path):
            conventional_path = str(self.base_dir / f"{session['host_name']}_capture.pcap")
            shutil.copy2(capture_path, conventional_path)
        return capture_path

    def _wait_for_log_marker(self, host: Any, log_path: str, marker: str, timeout: float, poll_interval: float = 0.05) -> bool:
        """Poll a log file for a marker string without blocking longer than timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            output = host.cmd(f"grep -m1 -F '{marker}' {log_path} 2>/dev/null")
            if output.strip():
                return True
            time.sleep(poll_interval)
        return False

    def read_capture(self, net: Any, host_name: str, capture_path: str) -> list[dict[str, Any]]:
        """Read a pcap and return a list of packet event dictionaries."""
        if not os.path.exists(capture_path):
            return []

        try:
            host_ip = net.get(host_name).IP()
        except Exception:  # noqa: BLE001
            host_ip = None

        try:
            packets = rdpcap(capture_path)
        except Exception:  # noqa: BLE001
            # Defense in depth: stop_capture() should already guarantee
            # tcpdump has exited and flushed by the time this runs, but a
            # single retry after a brief pause costs nothing and protects
            # against any residual filesystem-visibility race.
            time.sleep(0.5)
            packets = rdpcap(capture_path)
        events: list[dict[str, Any]] = []
        for packet in packets:
            if not hasattr(packet, "payload"):
                continue
            ip_layer = packet.getlayer("IP")
            arp_layer = packet.getlayer("ARP")
            tcp_layer = packet.getlayer("TCP")
            tcp_udp_layer = tcp_layer or packet.getlayer("UDP")
            protocol_name = "UNKNOWN"
            if tcp_udp_layer is not None:
                protocol_name = "TCP" if tcp_udp_layer.name == "TCP" else "UDP"
            if packet.haslayer("ICMP"):
                protocol_name = "ICMP"
            if packet.haslayer("ARP"):
                protocol_name = "ARP"

            src_ip = ip_layer.src if ip_layer is not None else (arp_layer.psrc if arp_layer is not None else "unknown")
            dst_ip = ip_layer.dst if ip_layer is not None else (arp_layer.pdst if arp_layer is not None else "unknown")

            direction = "unknown"
            if host_ip is not None:
                if dst_ip == host_ip:
                    direction = "inbound"
                elif src_ip == host_ip:
                    direction = "outbound"

            event = {
                "timestamp": float(packet.time),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol_name,
                "src_port": getattr(tcp_udp_layer, "sport", None),
                "dst_port": getattr(tcp_udp_layer, "dport", None),
                "packet_length": len(packet),
                "ttl": int(ip_layer.ttl) if ip_layer is not None else None,
                "direction": direction,
                # int(), not the raw FlagValue -- keeps the event dict JSON-safe
                # for the dashboard's SSE feed while still carrying real SYN/ACK
                # bits for FeatureAggregator (port presence alone can't tell
                # SYN/ACK apart -- every TCP packet has both ports set).
                "tcp_flags": int(tcp_layer.flags) if tcp_layer is not None else None,
            }
            events.append(event)
        return events
