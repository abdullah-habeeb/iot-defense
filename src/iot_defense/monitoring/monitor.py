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
