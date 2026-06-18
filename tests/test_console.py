"""Tests for the AI Asset Management console page (Gap roadmap Phase 1 / C2 / D3)."""
from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path

import pytest

CONSOLE = Path(__file__).resolve().parents[1] / "dashboard" / "console.html"


def test_console_file_exists():
    assert CONSOLE.exists()


def test_console_html_parses():
    HTMLParser().feed(CONSOLE.read_text())  # raises on malformed structure


def test_console_uses_cytoscape_dagre():
    html = CONSOLE.read_text()
    assert "cytoscape" in html and "dagre" in html
    assert 'rankDir:"LR"' in html  # hierarchical left->right DAG


def test_console_has_stat_strip():
    html = CONSOLE.read_text()
    for stat in ("stat-agents", "stat-tools", "stat-mcp", "stat-vulns"):
        assert stat in html


def test_console_wires_kill_flow():
    html = CONSOLE.read_text()
    assert "/api/kill/" in html
    assert "/cascade" in html
    assert "/reverse" in html
    assert "/preview" in html
    assert "Rip Credentials" in html


def test_console_pulls_asset_inventory():
    assert "/api/assets/scans" in CONSOLE.read_text()


# ── route ─────────────────────────────────────────────────────────────────────

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "console.db"))
    import api as app_module
    from fastapi.testclient import TestClient
    return TestClient(app_module.app, raise_server_exceptions=False)


def test_console_route_serves_page(client):
    r = client.get("/console")
    assert r.status_code == 200
    assert "AI Asset Management" in r.text
    assert "cytoscape" in r.text
