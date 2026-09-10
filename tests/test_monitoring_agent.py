"""MonitoringAgent unit tests.

Regression coverage for a real bug: observe() rebuilds every packet into a
fixed-field dict, and it once silently dropped "tcp_flags" -- a field
PacketMonitor.read_capture() populates but observe() didn't whitelist yet --
so FeatureAggregator's real SYN/ACK counting silently saw tcp_flags=None for
every live-captured packet even after the aggregator itself was fixed.
"""

from iot_defense.agents.monitoring_agent import MonitoringAgent


def test_observe_passes_through_real_tcp_flags():
    agent = MonitoringAgent()
    packet = {
        "src_ip": "10.0.0.100", "dst_ip": "10.0.0.10", "protocol": "TCP",
        "src_port": 40000, "dst_port": 22, "packet_length": 60,
        "timestamp": 1.0, "tcp_flags": 0x02, "ttl": 64, "direction": "inbound",
    }
    observed = agent.observe(packet)
    assert observed["tcp_flags"] == 0x02
    assert observed["ttl"] == 64
    assert observed["direction"] == "inbound"


def test_observe_defaults_missing_fields_without_crashing():
    agent = MonitoringAgent()
    # A non-IP packet (e.g. ARP) has no ttl and no tcp_flags at all --
    # observe() must default safely, not raise on int(None).
    packet = {"src_ip": "unknown", "dst_ip": "unknown", "protocol": "ARP"}
    observed = agent.observe(packet)
    assert observed["ttl"] == 0
    assert observed["tcp_flags"] is None
    assert observed["direction"] == "unknown"
