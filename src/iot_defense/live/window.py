"""Rolling-window detection for traffic arriving on a real network interface.

The lab pipeline analyses one capture per scripted scenario. A real network has
no scenario boundary, so this keeps the last few seconds of packets addressed
to the protected host and asks the same detectors, over that window, whether
what arrived looks like an attack. Nothing here knows which attack to expect.
"""

from __future__ import annotations

import ipaddress
from collections import deque
from typing import Any, Iterable

from iot_defense.detection.detector import UnifiedRuleBasedDetector
from iot_defense.detection.flow_features import FeatureAggregator
from iot_defense.detection.threat_event import ThreatEvent


def sustained_alarms(alarms: list[dict[str, Any]], confirm_ticks: int = 2, step: float = 1.0) -> list[dict[str, Any]]:
    """Runs of consecutive alarms from one source: the only ones the defender would act on.

    The defender needs `confirm_ticks` flagged checks in a row before it changes the firewall, because the
    first packets of any new client are few and large and read for one check as an exploit. Returns one
    entry per run that long: {source_ip, attack_type, start, checks}."""
    runs: list[dict[str, Any]] = []
    open_runs: dict[str, dict[str, Any]] = {}
    for alarm in sorted(alarms, key=lambda a: float(a["at"])):
        source = alarm["source_ip"]
        current = open_runs.get(source)
        if current is not None and float(alarm["at"]) - current["last"] <= step * 1.5:
            current["checks"] += 1
            current["last"] = float(alarm["at"])
        else:
            current = {"source_ip": source, "attack_type": alarm["attack_type"], "start": float(alarm["at"]),
                       "checks": 1, "last": float(alarm["at"])}
            open_runs[source] = current
            runs.append(current)
    return [{k: v for k, v in run.items() if k != "last"} for run in runs if run["checks"] >= confirm_ticks]


def is_routable_peer(address: str) -> bool:
    """A source address worth analysing (and, if it attacks, worth blocking):
    a real unicast IPv4 peer, not loopback, multicast, broadcast or unset."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.version == 4 and not (ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_reserved)


class WindowedDetector:
    def __init__(
        self,
        protected_ips: Iterable[str],
        *,
        window_seconds: float = 5.0,
        max_events: int = 50_000,
        detector: UnifiedRuleBasedDetector | None = None,
    ) -> None:
        self.protected_ips = frozenset(protected_ips)
        self.window_seconds = float(window_seconds)
        self.detector = detector or UnifiedRuleBasedDetector()
        self.aggregator = FeatureAggregator(window_seconds=window_seconds)
        self._events: deque[dict[str, Any]] = deque(maxlen=max_events)

    def ingest(self, event: dict[str, Any]) -> bool:
        """Keep an event if it is IPv4 traffic from a real peer to a protected
        address. Returns whether it was kept."""
        if event.get("dst_ip") not in self.protected_ips:
            return False
        source = str(event.get("src_ip", ""))
        if source in self.protected_ips or not is_routable_peer(source):
            return False
        self._events.append(event)
        return True

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._events and float(self._events[0].get("timestamp", 0.0)) < cutoff:
            self._events.popleft()

    def window_events(self, now: float, sources: set[str] | None = None) -> list[dict[str, Any]]:
        self._prune(now)
        return [e for e in self._events if sources is None or e["src_ip"] in sources]

    def evaluate(self, now: float, ignore_sources: set[str] | frozenset[str] = frozenset()) -> ThreatEvent | None:
        """The first attack the detectors see in the current window, or None.
        Sources in `ignore_sources` (already blocked, or trusted) are excluded
        so a blocked attacker's continuing packets do not re-trigger."""
        self._prune(now)
        candidates = [e for e in self._events if e["src_ip"] not in ignore_sources]
        if not candidates:
            return None
        flows = self.aggregator.aggregate(candidates)
        if not flows:
            return None
        event = self.detector.detect_flows(flows)
        return None if event.attack_type == "normal" else event

    def scan_for_false_alarms(self, events: Iterable[dict[str, Any]], step: float = 1.0) -> list[dict[str, Any]]:
        """Replay recorded *normal* traffic and report every moment the
        detectors would have raised an alarm. Used to calibrate on a quiet
        network before an attack is introduced; the expected answer is none."""
        alarms: list[dict[str, Any]] = []
        ordered = sorted(events, key=lambda e: float(e.get("timestamp", 0.0)))
        if not ordered:
            return alarms
        probe = WindowedDetector(self.protected_ips, window_seconds=self.window_seconds, detector=self.detector)
        clock = float(ordered[0]["timestamp"])
        cursor = 0
        end = float(ordered[-1]["timestamp"])
        while clock <= end + step:
            while cursor < len(ordered) and float(ordered[cursor]["timestamp"]) <= clock:
                probe.ingest(ordered[cursor])
                cursor += 1
            threat = probe.evaluate(clock)
            if threat is not None:
                alarms.append(
                    {"at": clock, "source_ip": threat.source_ip, "attack_type": threat.attack_type, "reason": threat.detection_reason}
                )
            clock += step
        return alarms
