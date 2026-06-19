"""Tests for the interactive demo: seeder populates every feature, /demo serves."""
from __future__ import annotations

import json
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEMO_HTML = ROOT / "dashboard" / "demo.html"


# ── static console checks (no DB) ──────────────────────────────────────────────

def test_demo_html_exists_and_parses():
    HTMLParser().feed(DEMO_HTML.read_text())


def test_demo_html_covers_every_feature_area():
    html = DEMO_HTML.read_text()
    for marker in ("Kill", "AI Workflow Scanner", "Governed Retrieval", "Campaign", "Policy Guard",
                   "Permission Drift", "MCP Inspector", "Blast Radius", "Intent Correlation",
                   "Honeypot", "SIEM", "Passport", "Discovery", "Compliance",
                   "Bedrock", "/console", "/dashboard"):
        assert marker in html, f"demo console missing {marker}"


def test_demo_route_serves(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "demo.db"))
    import api
    from fastapi.testclient import TestClient
    c = TestClient(api.app)
    r = c.get("/demo")
    assert r.status_code == 200
    assert "Interactive Demo" in r.text


# ── seeder populates every feature store (fresh subprocess for correct DB bind) ─

_SEED_AND_QUERY = r"""
import json, sys, os
sys.path.insert(0, "scripts")
import demo_seed_gap
demo_seed_gap.seed_gap("acme")
import api
from fastapi.testclient import TestClient
c = TestClient(api.app)
out = {}
out["asset_scans"] = c.get("/api/assets/scans").json().get("count")
prev = c.get("/api/kill/triage-agent/preview").json()["planes"]
out["kill_planes"] = len(prev)
out["kill_connected"] = sum(1 for p in prev if p["status"] == "killed")
out["retrieval"] = c.get("/api/retrieval/sources?agent_id=triage-agent").json().get("count")
out["campaigns"] = c.get("/api/campaigns").json().get("count")
out["siem"] = c.get("/api/siem/mcp-calls?target=ecs").json().get("count")
out["certs"] = c.get("/api/certs/fleet").json().get("total")
out["inventory"] = len(c.get("/api/agents/inventory").json().get("agents", []))
out["intent"] = len(c.get("/api/intent/matches").json().get("matches", []))
rip = c.post("/api/kill/triage-agent", json={"reason": "test"}).json()
out["rip_overall"] = rip.get("overall")
out["rip_killed"] = rip.get("killed")
print("RESULT=" + json.dumps(out))
"""


@pytest.fixture(scope="module")
def seeded(tmp_path_factory):
    db = str(tmp_path_factory.mktemp("demo") / "demo.db")
    env = {
        "PATH": __import__("os").environ.get("PATH", ""),
        "DATA_DB_PATH": db, "TOKENDNA_MCP_GATEWAY_DB": db, "TOKENDNA_BEHAVIORAL_DB": db,
        "DEV_MODE": "true", "DEV_TENANT_ID": "acme", "TOKENDNA_DEMO": "acme",
        "ENVIRONMENT": "dev", "ATTESTATION_CA_SECRET": "demo-secret-32-bytes-aaaaaaaaaaaa",
    }
    proc = subprocess.run([sys.executable, "-c", _SEED_AND_QUERY], cwd=str(ROOT),
                          env=env, capture_output=True, text=True)
    assert proc.returncode == 0, f"seed+query failed:\n{proc.stdout}\n{proc.stderr}"
    line = next(ln for ln in proc.stdout.splitlines() if ln.startswith("RESULT="))
    return json.loads(line[len("RESULT="):])


def test_asset_inventory_seeded(seeded):
    assert seeded["asset_scans"] >= 2


def test_kill_switch_all_planes_connected(seeded):
    # 6 planes: decision, edge, idp_okta, idp_entra, mcp, live_sessions
    assert seeded["kill_planes"] == 6
    assert seeded["kill_connected"] == 6  # all show connected in the demo


def test_kill_rip_executes(seeded):
    assert seeded["rip_overall"] == "complete"
    assert seeded["rip_killed"] == 6


def test_governed_retrieval_seeded(seeded):
    assert seeded["retrieval"] >= 1


def test_campaigns_seeded(seeded):
    assert seeded["campaigns"] >= 1


def test_siem_calls_seeded(seeded):
    assert seeded["siem"] >= 1


def test_certs_seeded(seeded):
    assert seeded["certs"] >= 3


def test_agent_inventory_seeded(seeded):
    assert seeded["inventory"] >= 5


def test_intent_feed_seeded(seeded):
    assert seeded["intent"] >= 3


# ── trust graph explorer ───────────────────────────────────────────────────────

TRUSTGRAPH = ROOT / "dashboard" / "trustgraph.html"


def test_trustgraph_html_parses():
    HTMLParser().feed(TRUSTGRAPH.read_text())


def test_trustgraph_has_toggle_views():
    html = TRUSTGRAPH.read_text()
    for marker in ('data-mode="nodes"', 'data-mode="edges"', 'data-mode="anomalies"',
                   'data-mode="correlate"', "/api/graph/data", "/api/graph/anomalies", "cytoscape"):
        assert marker in html, f"trust graph missing {marker}"


def test_trustgraph_route_serves(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "tg.db"))
    import api
    from fastapi.testclient import TestClient
    r = TestClient(api.app).get("/trust-graph")
    assert r.status_code == 200
    assert "Trust Graph" in r.text
