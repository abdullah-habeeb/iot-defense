from iot_defense.observability.metrics import MetricsCollector


def test_summary_counts_totals_and_suspicious():
    collector = MetricsCollector()
    collector.record({"action": "allow", "suspicious": False})
    collector.record({"action": "alert", "suspicious": True})
    summary = collector.summary()
    assert summary["total_events"] == 2
    assert summary["suspicious_events"] == 1


def test_blocked_events_counts_isolate():
    collector = MetricsCollector()
    collector.record({"action": "isolate", "suspicious": True})
    collector.record({"action": "allow", "suspicious": False})
    assert collector.summary()["blocked_events"] == 1


def test_blocked_events_counts_throttle():
    """Regression test: blocked_events previously only checked
    action == "isolate", silently excluding THROTTLE -- the preferred
    response for brute-force since Phase 3 -- from the dashboard's own
    containment total."""
    collector = MetricsCollector()
    collector.record({"action": "throttle", "suspicious": True})
    assert collector.summary()["blocked_events"] == 1


def test_blocked_events_counts_isolate_and_throttle_together():
    collector = MetricsCollector()
    collector.record({"action": "isolate", "suspicious": True})
    collector.record({"action": "throttle", "suspicious": True})
    collector.record({"action": "decoy", "suspicious": True})
    collector.record({"action": "alert", "suspicious": True})
    collector.record({"action": "allow", "suspicious": False})
    summary = collector.summary()
    assert summary["total_events"] == 5
    assert summary["suspicious_events"] == 4
    assert summary["blocked_events"] == 2


def test_blocked_events_ignores_missing_action():
    collector = MetricsCollector()
    collector.record({"suspicious": True})
    assert collector.summary()["blocked_events"] == 0


def test_blocked_events_counts_the_four_new_containment_actions():
    """Regression test for the same class of bug test_blocked_events_
    counts_throttle already caught once: _BLOCKING_ACTIONS was never
    updated when block_source/quarantine/reset_sessions/bandwidth_cap
    were added, silently excluding all four (and, transitively, every
    attack reassigned to one of them -- brute_force, credential_replay,
    firmware_tampering, buffer_overflow_probe, dns_amplification) from
    the dashboard's own containment total."""
    collector = MetricsCollector()
    for action in ("block_source", "quarantine", "reset_sessions", "bandwidth_cap"):
        collector.record({"action": action, "suspicious": True})
    assert collector.summary()["blocked_events"] == 4


def test_blocked_events_excludes_forensic_capture():
    """forensic_capture takes zero enforcement action -- the same reason
    ALERT and DECOY are excluded -- so it must not count as containment."""
    collector = MetricsCollector()
    collector.record({"action": "forensic_capture", "suspicious": True})
    assert collector.summary()["blocked_events"] == 0
