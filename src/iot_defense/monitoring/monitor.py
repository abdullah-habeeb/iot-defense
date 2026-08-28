"""Packet capture and observation helpers for real Mininet traffic."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from scapy.all import Packet, rdpcap


class PacketMonitor:
    """Capture packets from a Mininet host and convert them into structured events."""

    def __init__(self, base_dir: str | Path = "/tmp/iot-defense") -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def capture_host_packets(self, net: Any, host_name: str, packet_limit: int = 25, capture_seconds: int = 8) -> str:
        """Launch tcpdump on a host interface and return the capture filepath."""
        host = net.get(host_name)
        interface = host.defaultIntf().name
        capture_path = str(self.base_dir / f"{host_name}_capture.pcap")
        if os.path.exists(capture_path):
            os.remove(capture_path)

        command = (
            f"tcpdump -i {interface} -nn -s 0 -c {packet_limit} -w {capture_path} "
            f">/tmp/{host_name}_tcpdump.log 2>&1 & echo $!"
        )
        host.cmd(command)
        time.sleep(capture_seconds)
        return capture_path

    def start_capture(self, net: Any, host_name: str, packet_limit: int = 25) -> dict[str, Any]:
        """Launch tcpdump and block only until it confirms it is actually listening.

        Unlike capture_host_packets, this does not sleep for a fixed window --
        it waits for tcpdump's own "listening on ..." line, so the caller can
        safely start generating traffic the moment capture is truly active
        instead of guessing how long startup takes.
        """
        host = net.get(host_name)
        interface = host.defaultIntf().name
        capture_path = str(self.base_dir / f"{host_name}_capture.pcap")
        log_path = f"/tmp/{host_name}_tcpdump.log"
        if os.path.exists(capture_path):
            os.remove(capture_path)

        command = (
            f"tcpdump -i {interface} -nn -s 0 -c {packet_limit} -w {capture_path} "
            f">{log_path} 2>&1 & echo $!"
        )
        pid = host.cmd(command).strip()
        self._wait_for_log_marker(host, log_path, "listening on", timeout=2.0)
        return {"capture_path": capture_path, "log_path": log_path, "pid": pid, "host_name": host_name}

    def stop_capture(self, net: Any, session: dict[str, Any], completion_timeout: float = 6.0) -> str:
        """Block until tcpdump has actually exited and flushed its pcap file.

        Polls for tcpdump's own exit summary ("... packets captured") instead
        of assuming a fixed sleep was long enough -- reading the pcap file
        before tcpdump has flushed it produces a truncated/unparseable
        capture even when packets were genuinely captured. If tcpdump has not
        hit its packet limit within completion_timeout, it is sent SIGTERM
        (tcpdump flushes and exits cleanly on termination) so the file is
        always safe to read when this returns.
        """
        host = net.get(session["host_name"])
        log_path = session["log_path"]
        completed = self._wait_for_log_marker(host, log_path, "packets captured", timeout=completion_timeout)
        if not completed and session.get("pid"):
            host.cmd(f"kill -TERM {session['pid']} 2>/dev/null")
            self._wait_for_log_marker(host, log_path, "packets captured", timeout=1.0)
        return session["capture_path"]

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

        packets = rdpcap(capture_path)
        events: list[dict[str, Any]] = []
        for packet in packets:
            if not hasattr(packet, "payload"):
                continue
            ip_layer = packet.getlayer("IP")
            arp_layer = packet.getlayer("ARP")
            tcp_udp_layer = packet.getlayer("TCP") or packet.getlayer("UDP")
            protocol_name = "UNKNOWN"
            if tcp_udp_layer is not None:
                protocol_name = "TCP" if tcp_udp_layer.name == "TCP" else "UDP"
            if packet.haslayer("ICMP"):
                protocol_name = "ICMP"
            if packet.haslayer("ARP"):
                protocol_name = "ARP"

            src_ip = ip_layer.src if ip_layer is not None else (arp_layer.psrc if arp_layer is not None else "unknown")
            dst_ip = ip_layer.dst if ip_layer is not None else (arp_layer.pdst if arp_layer is not None else "unknown")

            event = {
                "timestamp": float(packet.time),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol_name,
                "src_port": getattr(tcp_udp_layer, "sport", None),
                "dst_port": getattr(tcp_udp_layer, "dport", None),
                "packet_length": len(packet),
            }
            events.append(event)
        return events
