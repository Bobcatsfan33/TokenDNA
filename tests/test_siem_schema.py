"""Tests for per-MCP-call SIEM schema + mappings (Gap roadmap Epic 4.2 / B2)."""
from __future__ import annotations

import pytest

from modules.identity import siem_schema as ss


def _enf(outcome="block", blocked=True):
    return {
        "enforcement_id": "e1", "session_id": "sess-1", "tenant_id": "t1",
        "agent_id": "agent-A", "server_id": "files-mcp", "tool_name": "read_file",
        "params": {"path": "/etc/passwd"}, "outcome": outcome, "blocked": blocked,
        "risk_score": 0.9, "reasons": ["forbidden_path"], "inspector_used": True,
        "created_at": "2026-06-18T12:00:00+00:00",
    }


# ── normalization ─────────────────────────────────────────────────────────────

def test_normalize_fields():
    e = ss.normalize_mcp_call(_enf())
    assert e["action"] == "mcp.tool_call"
    assert e["agent_id"] == "agent-A"
    assert e["mcp_server"] == "files-mcp"
    assert e["blocked"] is True


def test_params_hashed_not_raw():
    e = ss.normalize_mcp_call(_enf())
    assert e["params_hash"].startswith("sha256:")
    # raw param value never present anywhere in the event
    assert "/etc/passwd" not in str(e)


def test_params_hash_stable():
    a = ss.normalize_mcp_call(_enf())["params_hash"]
    b = ss.normalize_mcp_call(_enf())["params_hash"]
    assert a == b


# ── vendor mappings ───────────────────────────────────────────────────────────

def test_ecs_mapping():
    ecs = ss.to_ecs(ss.normalize_mcp_call(_enf()))
    assert ecs["@timestamp"] == "2026-06-18T12:00:00+00:00"
    assert ecs["event"]["outcome"] == "failure"  # blocked
    assert ecs["event"]["action"] == "mcp.tool_call"
    assert ecs["user"]["id"] == "agent-A"
    assert ecs["service"]["name"] == "files-mcp"
    assert ecs["labels"]["tokendna_tool"] == "read_file"


def test_ecs_allowed_outcome():
    ecs = ss.to_ecs(ss.normalize_mcp_call(_enf(outcome="allow", blocked=False)))
    assert ecs["event"]["outcome"] == "success"
    assert ecs["event"]["type"] == ["allowed"]


def test_splunk_mapping():
    hec = ss.to_splunk(ss.normalize_mcp_call(_enf()))
    assert hec["sourcetype"] == "tokendna:mcp:call"
    assert isinstance(hec["time"], float) and hec["time"] > 0
    assert hec["event"]["tool_name"] == "read_file"


def test_sentinel_mapping():
    s = ss.to_sentinel(ss.normalize_mcp_call(_enf()))
    assert s["TimeGenerated"] == "2026-06-18T12:00:00+00:00"
    assert s["ToolName"] == "read_file"
    assert s["Blocked"] is True


def test_export_event_targets():
    e = ss.normalize_mcp_call(_enf())
    assert "@timestamp" in ss.export_event(e, "ecs")
    assert "sourcetype" in ss.export_event(e, "splunk")
    assert "TimeGenerated" in ss.export_event(e, "sentinel")
    assert ss.export_event(e, "canonical") == e


def test_unsupported_target():
    with pytest.raises(ValueError):
        ss.export_event(ss.normalize_mcp_call(_enf()), "qradar")


def test_canonical_schema():
    sch = ss.canonical_schema()
    assert sch["action"] == "mcp.tool_call"
    assert "tool_name" in sch["fields"]
    assert "ecs" in sch["targets"]


# ── sourcing from gateway + API ────────────────────────────────────────────────

@pytest.fixture()
def gw(tmp_path, monkeypatch):
    import importlib
    monkeypatch.setenv("TOKENDNA_MCP_GATEWAY_DB", str(tmp_path / "gw.db"))
    import modules.identity.mcp_gateway as g
    importlib.reload(g)
    g.init_db()
    return g


def test_export_mcp_calls_from_gateway(gw, monkeypatch):
    monkeypatch.setattr("modules.identity.siem_schema.mcp_gateway", gw, raising=False)
    sess = gw.open_session(tenant_id="t1", agent_id="agent-A", server_id="files-mcp", mode="block")
    gw.enforce(session_id=sess["session_id"], tenant_id="t1", tool_name="read_file",
               params={"path": "/x"})
    out = ss.export_mcp_calls(tenant_id="t1", target="ecs", limit=10)
    assert len(out) >= 1
    assert out[0]["event"]["action"] == "mcp.tool_call"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "siem_api.db"))
    import api as app_module
    from fastapi.testclient import TestClient
    from modules.product import commercial_tiers as ct
    from modules.tenants.models import Plan, TenantContext

    tenant = TenantContext(tenant_id="t", tenant_name="T", plan=Plan.ENTERPRISE,
                           api_key_id="k", role="owner")
    app_module.app.dependency_overrides[ct.get_tenant] = lambda: tenant
    yield TestClient(app_module.app, raise_server_exceptions=False)
    app_module.app.dependency_overrides.clear()


def test_api_schema_and_format(client):
    assert client.get("/api/siem/schema").json()["action"] == "mcp.tool_call"
    r = client.post("/api/siem/format", json={"enforcement": _enf(), "target": "ecs"})
    assert r.status_code == 200, r.text
    assert r.json()["event"]["action"] == "mcp.tool_call"


def test_api_format_bad_target(client):
    r = client.post("/api/siem/format", json={"enforcement": _enf(), "target": "qradar"})
    assert r.status_code == 400
