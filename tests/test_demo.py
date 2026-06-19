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
                   'data-mode="correlate"', "/api/graph/data", "/api/graph/anomalies",
                   "TrustGraphEngine", "/static/trustgraph-engine.js"):
        assert marker in html, f"trust graph missing {marker}"
    # the standalone page must be fully offline — no third-party CDN
    for bad in ("cytoscape", "jsdelivr", "cdnjs", "unpkg"):
        assert bad not in html, f"trust graph still references {bad}"


def test_trustgraph_route_serves(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "tg.db"))
    import api
    from fastapi.testclient import TestClient
    r = TestClient(api.app).get("/trust-graph")
    assert r.status_code == 200
    assert "Trust Graph" in r.text


# ── Dashboard Trust Graph — fully offline (no CDN) ─────────────────────────────

DASHBOARD = ROOT / "dashboard" / "index.html"
CONSOLE = ROOT / "dashboard" / "console.html"
STATIC = ROOT / "dashboard" / "static"
ENGINE = STATIC / "trustgraph-engine.js"
FIXTURE = STATIC / "trustgraph-fixture.js"
ALL_HTML = [DASHBOARD, TRUSTGRAPH, CONSOLE, DEMO_HTML]


def test_dashboard_assets_have_no_external_cdn():
    """Every dashboard page must run fully offline — zero third-party URLs."""
    for f in ALL_HTML:
        html = f.read_text()
        for bad in ("jsdelivr", "cdnjs", "unpkg", "cdn."):
            assert bad not in html, f"{f.name} still references a CDN ({bad})"
        # no remote <script> resources
        assert 'src="http' not in html, f"{f.name} has a remote <script src>"
        # no remote <link> stylesheet (a display-only literal URL is allowed)
        for line in html.splitlines():
            if 'href="http' in line:
                assert "auth.acme.io" in line, f"{f.name} has a remote stylesheet: {line.strip()[:80]}"


def test_dashboard_vendors_react_locally():
    html = DASHBOARD.read_text()
    assert "/static/vendor/react.production.min.js" in html
    assert "/static/vendor/react-dom.production.min.js" in html
    assert (STATIC / "vendor" / "react.production.min.js").exists()
    assert (STATIC / "vendor" / "react-dom.production.min.js").exists()


def test_dependency_free_engine_exists():
    assert ENGINE.exists() and FIXTURE.exists()
    eng = ENGINE.read_text()
    # plain SVG renderer — no graph library calls, no module imports, no CDN
    for bad in ("jsdelivr", "cdnjs", "unpkg", "cytoscape.use", "cytoscape(", "import ", "require("):
        assert bad not in eng, f"engine should be dependency-free; found {bad}"
    for marker in ("TrustGraphEngine", "buildElements", "COLLAPSE_MIN", "createElementNS", "focusLabel"):
        assert marker in eng, f"engine missing {marker}"


def test_dashboard_loads_local_engine_and_fixture():
    html = DASHBOARD.read_text()
    for marker in ("/static/trustgraph-engine.js", "/static/trustgraph-fixture.js",
                   "TrustGraphEngine", "TRUSTGRAPH_FIXTURE"):
        assert marker in html, f"dashboard missing {marker}"
    # old cytoscape layout fully removed
    assert "function forceLayout" not in html and "function GraphCanvas" not in html


def test_dashboard_graph_interactive_components():
    html = DASHBOARD.read_text()
    for marker in ("function CytoGraph", "function ContextPanel", "function NodesModal",
                   "function EdgesModal", "function AnomalyDetailModal", "function IntentMatchModal"):
        assert marker in html, f"dashboard missing {marker}"


def test_dashboard_wires_real_killswitch():
    html = DASHBOARD.read_text()
    assert "/api/enforcement/killswitch/" in html
    assert "activated_by" in html


def test_dashboard_clickable_cards_and_feeds():
    html = DASHBOARD.read_text()
    assert "gotoPage" in html and "tokendna:nav" in html
    assert "h(IntentMatchModal" in html  # intent feed tiles open detail
    assert "h(AnomalyDetailModal" in html  # anomaly stream tiles open detail
    assert 'setDrill("nodes")' in html and 'setDrill("anomalies")' in html
    assert "gotoGraphNode" in html  # cross-page focus from feed modals


def test_console_uses_dependency_free_engine():
    html = CONSOLE.read_text()
    assert "/static/trustgraph-engine.js" in html and "TrustGraphEngine" in html
    assert "cytoscape" not in html


def test_dashboard_route_serves_offline_graph(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "dash.db"))
    import api
    from fastapi.testclient import TestClient
    c = TestClient(api.app)
    r = c.get("/dashboard")
    assert r.status_code == 200
    assert "Live Trust Graph" in r.text and "TrustGraphEngine" in r.text
    assert "jsdelivr" not in r.text and "cdnjs" not in r.text and "cdn." not in r.text


def test_static_assets_served_locally(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "s.db"))
    import api
    from fastapi.testclient import TestClient
    c = TestClient(api.app)
    for p in ("/static/trustgraph-engine.js", "/static/trustgraph-fixture.js",
              "/static/workflow-fixtures.js",
              "/static/vendor/react.production.min.js", "/static/vendor/react-dom.production.min.js"):
        r = c.get(p)
        assert r.status_code == 200, f"{p} not served (HTTP {r.status_code})"
    assert "TrustGraphEngine" in c.get("/static/trustgraph-engine.js").text


# ── Workflows page — staged agent pipeline (matches reference Example) ──────────

WF_FIXTURES = STATIC / "workflow-fixtures.js"


def test_workflow_fixtures_exist_and_are_staged():
    assert WF_FIXTURES.exists()
    js = WF_FIXTURES.read_text()
    assert "WORKFLOW_FIXTURES" in js
    # staged pipeline must use multiple ranks: start + agents + tools/mcp + guardrail + end
    for t in ("start", "agent", "tool", "mcp_server", "guardrail", "end"):
        assert '"' + t + '"' in js or "'" + t + "'" in js, f"fixture missing node type {t}"
    assert "airline-agent-demo" in js  # the reference-style demo


def test_workflows_page_renders_pipeline():
    html = DASHBOARD.read_text()
    assert "function WorkflowsPage" in html
    assert "WORKFLOW_FIXTURES" in html and "/static/workflow-fixtures.js" in html
    assert "workflows: WorkflowsPage" in html  # nav wired to the pipeline view
    assert "h(CytoGraph" in html  # reuses the shared engine wrapper


def test_pages_have_distinguishing_helper_text():
    html = DASHBOARD.read_text()
    assert "For a single staged agent pipeline, see Workflows." in html
    assert "Staged left→right view of one agent workflow" in html


def test_path_finder_constrains_to_reachable():
    """The 'To' dropdown only offers nodes reachable from the chosen 'From'."""
    html = DASHBOARD.read_text()
    assert "function reachableLabelsFrom" in html
    # 'To' options are filtered by the reachable set; 'From' lists all nodes
    assert "reachable && reachable.has(n.label)" in html
    assert "reachableLabelsFrom(graphData, fromLabel)" in html
    # invalid 'To' is auto-cleared when 'From' changes
    assert "!reachable.has(toLabel)) setToLabel(\"\")" in html


def test_find_path_isolates_path_in_graph():
    """Clicking Find Path highlights only that path in the Live Trust Graph."""
    html = DASHBOARD.read_text()
    eng = ENGINE.read_text()
    assert "prototype.showPath" in eng and "prototype._fitToIds" in eng
    assert "ctrl.current.showPath" in html
    assert "showPath:(ids)=>eng.showPath(ids)" in html
    assert "clientShortestPath" in html  # works offline / when API unreachable


def test_intent_playbooks_clickable():
    html = DASHBOARD.read_text()
    assert "function PlaybookModal" in html
    assert "playbook-row clickable" in html
    assert "setSelPlaybook" in html
    assert "Attack sequence" in html


def test_honeypot_tiles_clickable():
    html = DASHBOARD.read_text()
    assert "function DetailModal" in html
    assert "setHitDetail" in html and "setDecoyDetail" in html
    assert "h(DetailModal" in html


# ── Dev caching: edits show up on a normal reload ──────────────────────────────

def test_engine_grid_wraps_large_ranks():
    """Star/bipartite data must spread in 2D, not collapse to a vertical line."""
    eng = ENGINE.read_text()
    assert "Math.ceil(Math.sqrt" in eng  # grid sub-columns for big ranks
    assert "WRAP" in eng


def test_dashboard_assets_are_version_busted():
    html = DASHBOARD.read_text()
    # local scripts carry a cache-busting version placeholder
    assert "/static/trustgraph-engine.js?v=__ASSET_VER__" in html


def test_html_served_with_no_store_and_version(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "c.db"))
    import api
    from fastapi.testclient import TestClient
    c = TestClient(api.app)
    for route in ("/dashboard", "/trust-graph", "/console"):
        r = c.get(route)
        assert r.status_code == 200
        assert "no-store" in r.headers.get("cache-control", ""), f"{route} not no-store"
        # placeholder must be replaced with a real version token in the served HTML
        assert "__ASSET_VER__" not in r.text, f"{route} left an unresolved version placeholder"
        assert "?v=" in r.text, f"{route} missing versioned script URLs"


def test_static_assets_are_no_store(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "c2.db"))
    import api
    from fastapi.testclient import TestClient
    r = TestClient(api.app).get("/static/trustgraph-engine.js")
    assert r.status_code == 200
    assert "no-store" in r.headers.get("cache-control", "")


def test_asset_version_changes_on_edit(tmp_path, monkeypatch):
    from api_routers import _shared
    monkeypatch.setattr(_shared, "_STATIC_DIR", tmp_path)
    (tmp_path / "a.js").write_text("x")
    v1 = _shared.asset_version()
    (tmp_path / "a.js").write_text("xy")  # content + size change
    v2 = _shared.asset_version()
    assert v1 != v2 and len(v1) == 12
