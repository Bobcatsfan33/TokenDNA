"""Tests for the AI Workflow Scanner + Asset Inventory (Epic 3.1 / C1)."""
from __future__ import annotations

import importlib

import pytest


@pytest.fixture()
def ai(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "assets.db"))
    import modules.identity.asset_inventory as m
    importlib.reload(m)
    m.init_db()
    return m


TENANT = "tenant-assets"

LANGGRAPH = {
    "framework": "langgraph",
    "nodes": [
        {"name": "planner", "tools": ["search", "calculator"]},
        {"name": "executor", "tools": [{"name": "http_get", "input_schema": {"url": "str"}}]},
    ],
    "edges": [["planner", "executor"]],
    "mcp_servers": [{"name": "files-mcp", "auth": "none", "tools": ["read", "write"]}],
    "observability": {"siem": "splunk"},
}

OPENAI_AGENTS = {
    "framework": "openai-agents",
    "agents": [
        {"name": "triage", "tools": ["transfer_to_billing"]},
        {"name": "billing", "tools": ["update_policy"]},  # self-modification
    ],
}

CREWAI = {
    "crew": "research",
    "agents": [{"role": "researcher", "tools": ["serp"]}],
    "tasks": [{"description": "find"}],
}

AUTOGEN = {
    "agents": [
        {"name": "assistant", "system_message": "you are helpful", "functions": ["run_code"]},
    ],
}

MCP_MANIFEST = {
    "servers": [
        {"name": "db-mcp", "auth": "oauth", "tools": ["query"]},
        {"name": "shell-mcp", "tools": ["exec"]},  # no auth -> vuln
    ],
}


# ── framework detection ──────────────────────────────────────────────────────

def test_detect_langgraph(ai):
    assert ai.detect_framework({"nodes": [], "edges": []}) == "langgraph"


def test_detect_crewai(ai):
    assert ai.detect_framework(CREWAI) == "crewai"


def test_detect_autogen(ai):
    assert ai.detect_framework(AUTOGEN) == "autogen"


def test_detect_openai_agents(ai):
    assert ai.detect_framework({"agents": [{"name": "x"}]}) == "openai-agents"


def test_detect_mcp_manifest(ai):
    assert ai.detect_framework(MCP_MANIFEST) == "mcp-manifest"


def test_explicit_framework_wins(ai):
    assert ai.detect_framework({"framework": "crewai", "agents": []}) == "crewai"


# ── normalization ─────────────────────────────────────────────────────────────

def test_langgraph_inventory(ai):
    r = ai.scan_workflow(tenant_id=TENANT, definition=LANGGRAPH)
    assert r["framework"] == "langgraph"
    assert {a["name"] for a in r["agents"]} == {"planner", "executor"}
    assert {t["name"] for t in r["tools"]} >= {"search", "calculator", "http_get"}
    assert {m["name"] for m in r["mcp_servers"]} == {"files-mcp"}


def test_tools_deduped_across_agents(ai):
    defn = {"framework": "openai-agents", "agents": [
        {"name": "a", "tools": ["shared", "x"]},
        {"name": "b", "tools": ["shared", "y"]},
    ]}
    r = ai.scan_workflow(tenant_id=TENANT, definition=defn)
    names = [t["name"] for t in r["tools"]]
    assert names.count("shared") == 1


def test_crewai_uses_role_as_name(ai):
    r = ai.scan_workflow(tenant_id=TENANT, definition=CREWAI)
    assert r["agents"][0]["name"] == "researcher"


# ── vulnerability rules ────────────────────────────────────────────────────────

def _vuln_names(r):
    return {v["name"] for v in r["vulnerabilities"]}


def test_unauthenticated_mcp_flagged(ai):
    r = ai.scan_workflow(tenant_id=TENANT, definition=MCP_MANIFEST)
    assert "unauthenticated_mcp_server" in _vuln_names(r)
    # only shell-mcp (no auth), not db-mcp (oauth)
    vulns = [v for v in r["vulnerabilities"] if v["name"] == "unauthenticated_mcp_server"]
    assert all(v["target"] == "shell-mcp" for v in vulns)


def test_missing_observability_flagged(ai):
    r = ai.scan_workflow(tenant_id=TENANT, definition=MCP_MANIFEST)
    assert "missing_observability" in _vuln_names(r)


def test_observability_present_not_flagged(ai):
    r = ai.scan_workflow(tenant_id=TENANT, definition=LANGGRAPH)  # has observability
    assert "missing_observability" not in _vuln_names(r)


def test_self_modification_flagged(ai):
    r = ai.scan_workflow(tenant_id=TENANT, definition=OPENAI_AGENTS)
    assert "self_modification_risk" in _vuln_names(r)


def test_cascading_injection_surface(ai):
    r = ai.scan_workflow(tenant_id=TENANT, definition=OPENAI_AGENTS)
    assert "cascading_injection_surface" in _vuln_names(r)


def test_single_agent_no_cascade(ai):
    r = ai.scan_workflow(tenant_id=TENANT, definition=AUTOGEN)
    assert "cascading_injection_surface" not in _vuln_names(r)


# ── persistence + history ──────────────────────────────────────────────────────

def test_scan_persisted_and_listed(ai):
    ai.scan_workflow(tenant_id=TENANT, definition=LANGGRAPH, source="airline-demo")
    ai.scan_workflow(tenant_id=TENANT, definition=MCP_MANIFEST)
    scans = ai.list_scans(tenant_id=TENANT)
    assert len(scans) == 2
    assert scans[0]["scanned_at"] >= scans[1]["scanned_at"]  # newest first


def test_get_scan_groups_items(ai):
    r = ai.scan_workflow(tenant_id=TENANT, definition=LANGGRAPH)
    detail = ai.get_scan(tenant_id=TENANT, scan_id=r["scan_id"])
    assert detail["items"]["agent"] and detail["items"]["mcp_server"]
    assert detail["scan"]["framework"] == "langgraph"


def test_get_scan_filter_by_kind(ai):
    r = ai.scan_workflow(tenant_id=TENANT, definition=MCP_MANIFEST)
    detail = ai.get_scan(tenant_id=TENANT, scan_id=r["scan_id"], kind="vulnerability")
    assert detail["items"]["vulnerability"]
    assert not detail["items"]["agent"]


def test_scan_scoped_to_tenant(ai):
    ai.scan_workflow(tenant_id=TENANT, definition=LANGGRAPH)
    assert ai.list_scans(tenant_id="other-tenant") == []


def test_bad_definition_raises(ai):
    with pytest.raises(ValueError):
        ai.scan_workflow(tenant_id=TENANT, definition="not a dict")


# ── API ────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "assets_api.db"))
    import api as app_module
    from fastapi.testclient import TestClient
    from modules.security import rbac
    from modules.product import commercial_tiers as ct
    from modules.tenants.models import Plan, TenantContext

    tenant = TenantContext(tenant_id="t-api", tenant_name="T", plan=Plan.ENTERPRISE,
                           api_key_id="k", role="owner")
    app_module.app.dependency_overrides[rbac._get_tenant_ctx] = lambda: tenant
    app_module.app.dependency_overrides[ct.get_tenant] = lambda: tenant
    yield TestClient(app_module.app, raise_server_exceptions=False)
    app_module.app.dependency_overrides.clear()


def test_api_scan_and_history(client):
    r = client.post("/api/assets/scan", json={"definition": LANGGRAPH, "source": "demo"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["counts"]["agents"] == 2
    sid = body["scan_id"]

    hist = client.get("/api/assets/scans").json()
    assert hist["count"] >= 1

    detail = client.get(f"/api/assets/scans/{sid}").json()
    assert detail["scan"]["framework"] == "langgraph"


def test_api_scan_requires_definition(client):
    r = client.post("/api/assets/scan", json={})
    assert r.status_code == 400
