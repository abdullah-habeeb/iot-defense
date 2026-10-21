"""Attack briefings for the dashboard's "Attack Briefing" card.

The card is only useful if every attack has a briefing, so these tests fail
the moment an attack is registered without one (or a briefing outlives its
attack), instead of leaving the card blank for that attack at demo time.
"""

from __future__ import annotations

import pytest

from iot_defense.attacks.briefings import BRIEFINGS, describe_attack
from iot_defense.attacks.registry import ATTACK_SCENARIOS


def test_every_registered_attack_has_a_briefing_and_none_are_orphaned():
    assert set(BRIEFINGS) == set(ATTACK_SCENARIOS)


@pytest.mark.parametrize("key", sorted(ATTACK_SCENARIOS))
def test_briefing_is_complete_and_beginner_sized(key):
    briefing = BRIEFINGS[key]
    assert briefing.category.strip()
    assert 40 <= len(briefing.summary) <= 260
    assert len(briefing.steps) == 3
    for step in briefing.steps:
        assert 25 <= len(step) <= 260
    assert 15 <= len(briefing.impact) <= 260
    assert 25 <= len(briefing.tell) <= 300
    for text in (briefing.summary, briefing.impact, briefing.tell, *briefing.steps):
        assert text == text.strip() and "  " not in text
        assert text[-1] in ".?!'"


@pytest.mark.parametrize("key", sorted(ATTACK_SCENARIOS))
def test_describe_attack_reads_facts_from_the_registry(key):
    scenario = ATTACK_SCENARIOS[key]
    info = describe_attack(key)
    assert info["key"] == key and info["label"] == scenario.label
    assert info["direction"] == scenario.traffic_direction
    assert info["distributed"] == bool(scenario.sender_ips)
    assert info["sources"] == (len(scenario.sender_ips) or 1)
    assert "10.0.0.100" in info["lab_note"] and "10.0.0.10" in info["lab_note"]


def test_lab_note_matches_the_direction_and_source_pattern():
    assert "already been compromised" in describe_attack("exfiltration")["lab_note"]
    assert describe_attack("exfiltration")["direction"] == "outbound"
    inbound = describe_attack("dos")
    assert inbound["direction"] == "inbound" and not inbound["distributed"]
    assert "compromised" not in inbound["lab_note"]
    distributed = describe_attack("dos_distributed")
    assert distributed["distributed"] and distributed["sources"] > 1
    assert "forged" in distributed["lab_note"]


def test_attacks_endpoint_serves_a_briefing_for_every_attack():
    from fastapi.testclient import TestClient

    from iot_defense.dashboard.server import app

    payload = TestClient(app).get("/attacks").json()
    assert [a["key"] for a in payload] == list(ATTACK_SCENARIOS)
    for item in payload:
        assert item["label"] and item["summary"] and len(item["steps"]) == 3
        assert item["lab_note"] and item["category"]
