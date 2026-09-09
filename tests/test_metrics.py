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
