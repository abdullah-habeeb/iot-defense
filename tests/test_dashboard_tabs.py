"""The two dashboards: Mininet simulation at / and the live physical demo at /live.

They share a stylesheet and the renderers in dashboard.js, but each page has its
own layout, script and state file, so nothing on one can overwrite the other.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import iot_defense.dashboard.server as server

STATIC = Path(__file__).resolve().parents[1] / "data" / "dashboard" / "static"
IDS = lambda html: set(re.findall(r'\bid="([^"]+)"', html))


@pytest.fixture(scope="module")
def sim_html():
    return (STATIC / "index.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def live_html():
    return (STATIC / "live.html").read_text(encoding="utf-8")


@pytest.fixture
def client():
    return TestClient(server.app)


class TestRoutes:
    def test_each_dashboard_is_served_at_its_own_address_with_cache_busted_assets(self, client):
        sim, live = client.get("/"), client.get("/live")
        assert sim.status_code == live.status_code == 200
        assert 'data-page="sim"' in sim.text and 'data-page="live"' in live.text
        assert re.search(r"/static/dashboard\.js\?v=\d+", sim.text)
        for asset in ("style.css", "live.css", "dashboard.js", "live.js"):
            assert re.search(rf"/static/{re.escape(asset)}\?v=\d+", live.text), asset
        assert "live.js" not in sim.text and "live.css" not in sim.text
        assert sim.headers["cache-control"] == live.headers["cache-control"] == "no-cache"

    def test_the_live_state_defaults_to_idle_when_no_defender_has_run(self, client, tmp_path, monkeypatch):
        monkeypatch.setattr(server, "_LIVE_STATE_FILE", tmp_path / "missing.json")
        assert client.get("/live/state").json() == {"phase": "IDLE", "live": None}

    def test_the_live_state_and_the_simulation_state_are_separate_files(self, client, tmp_path, monkeypatch):
        live_file, sim_file = tmp_path / "live_state.json", tmp_path / "state.json"
        live_file.write_text(json.dumps({"phase": "BLOCKED_SOURCE", "live": {"box_ip": "192.168.43.10"}}))
        sim_file.write_text(json.dumps({"phase": "RESTORED"}))
        monkeypatch.setattr(server, "_LIVE_STATE_FILE", live_file)
        monkeypatch.setattr(server, "_STATE_FILE", sim_file)
        assert client.get("/live/state").json()["phase"] == "BLOCKED_SOURCE"
        assert client.get("/state").json()["phase"] == "RESTORED"
        assert server._LIVE_STATE_FILE != server._STATE_FILE

    def test_the_defender_writes_to_the_live_file_not_the_simulations(self):
        from iot_defense.live import defender

        assert defender.STATE_PATH.name == "live_state.json"
        assert defender.STATE_PATH.name != server._STATE_FILE.name

    def test_the_live_stream_is_an_event_stream(self):
        stream = [route for route in server.app.routes if getattr(route, "path", "") == "/live/stream"]
        assert stream and "GET" in stream[0].methods
        assert any(getattr(route, "path", "") == "/stream" for route in server.app.routes)


class TestPages:
    def test_both_pages_carry_the_same_tabs_with_the_right_one_active(self, sim_html, live_html):
        for html, active in ((sim_html, "Mininet Simulation"), (live_html, "Live Physical Demo")):
            tabs = re.findall(r'<a class="site-tab( active)?" href="([^"]+)"[^>]*>([^<]+)</a>', html)
            assert [(href, label) for _, href, label in tabs] == [("/", "Mininet Simulation"), ("/live", "Live Physical Demo")]
            assert [label for flag, _, label in tabs if flag] == [active]

    def test_the_simulation_page_carries_none_of_the_live_pieces(self, sim_html):
        ids = IDS(sim_html)
        assert not {i for i in ids if i.startswith(("dev-", "live-", "setup-", "guard-", "lm-", "defender-"))}
        assert {"topology-svg", "run-attack-btn", "run-attack-select"} <= ids
        assert "section-live" not in ids

    def test_the_live_page_has_its_own_layout_and_none_of_the_simulations_controls(self, live_html):
        ids = IDS(live_html)
        assert {"section-devices", "section-setup", "section-guard", "section-livemetrics", "defender-badge", "live-blocks"} <= ids
        assert not ids & {"topology-svg", "run-attack-btn", "run-attack-select", "section-topology", "section-metrics", "section-response"}

    def test_every_element_a_shared_renderer_writes_to_exists_on_the_live_page(self, live_html):
        """The live page reuses dashboard.js's renderers; each looks up fixed element ids. A missing
        one would silently stop that card from updating."""
        required = {
            # renderHeader / updatePipeline
            "phase-badge", "attack-mode-badge", "pipe-network", "pipe-recovery",
            # renderTraffic, renderThreat, renderContext, renderTimeline
            "traffic-tbody", "traffic-count-badge", "traffic-window-note", "threat-status-bar", "threat-details-wrap",
            "feature-grid", "bdi-body", "timeline-wrap", "timeline-count",
            # renderPolicies, renderArbiter, renderBriefing
            "policy-grid", "selected-action-wrap", "sel-policy-name", "section-arbiter", "arbiter-hero", "evidence-tbody",
            "arbiter-footnote", "section-briefing", "briefing-steps", "briefing-live-text", "briefing-toggle",
            # the page's own renderers
            "dev-box-ip", "dev-phone-status", "dev-attacker-facts", "setup-body", "setup-toggle", "guard-response",
            "lm-packets", "lm-served", "conn-indicator", "conn-label", "header-clock", "alert-banner",
        }
        assert required <= IDS(live_html), sorted(required - IDS(live_html))

    def test_no_duplicate_element_ids_on_either_page(self, sim_html, live_html):
        for html in (sim_html, live_html):
            ids = re.findall(r'\bid="([^"]+)"', html)
            assert len(ids) == len(set(ids)), sorted({i for i in ids if ids.count(i) > 1})

    def test_the_simulation_boot_code_stands_aside_on_the_live_page(self):
        js = (STATIC / "dashboard.js").read_text(encoding="utf-8")
        assert "document.body.dataset.page === 'live'" in js
        live_js = (STATIC / "live.js").read_text(encoding="utf-8")
        assert "document.body.dataset.page !== 'live'" in live_js and "/live/stream" in live_js and "/live/state" in live_js
        assert "/stream'" not in live_js.replace("/live/stream", "")  # never reads the simulation's stream
