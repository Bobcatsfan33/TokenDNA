"""Tests for MCP credential brokering + revocation (Gap roadmap Epic 2.2)."""
from __future__ import annotations

import importlib

import pytest


@pytest.fixture()
def gw(tmp_path, monkeypatch):
    monkeypatch.setenv("TOKENDNA_MCP_GATEWAY_DB", str(tmp_path / "gw.db"))
    import modules.identity.mcp_gateway as g
    importlib.reload(g)
    g.init_db()
    return g


TENANT = "tenant-mcp"
AGENT = "agent-rogue"


def test_grant_and_list(gw):
    gw.grant_credential(tenant_id=TENANT, agent_id=AGENT, server_id="srv1", credential_ref="vault://k1")
    gw.grant_tool(tenant_id=TENANT, agent_id=AGENT, server_id="srv1", tool_name="search")
    gw.open_session(tenant_id=TENANT, agent_id=AGENT, server_id="srv1")
    grants = gw.list_agent_grants(tenant_id=TENANT, agent_id=AGENT)
    assert len(grants["credentials"]) == 1
    assert len(grants["tool_grants"]) == 1
    assert len(grants["open_sessions"]) == 1


def test_revoke_agent_mcp_counts(gw):
    gw.grant_credential(tenant_id=TENANT, agent_id=AGENT, server_id="s", credential_ref="r1")
    gw.grant_credential(tenant_id=TENANT, agent_id=AGENT, server_id="s", credential_ref="r2")
    gw.grant_tool(tenant_id=TENANT, agent_id=AGENT, server_id="s", tool_name="t1")
    gw.open_session(tenant_id=TENANT, agent_id=AGENT, server_id="s")
    res = gw.revoke_agent_mcp(tenant_id=TENANT, agent_id=AGENT, revoked_by="ops")
    assert res == {"credentials_revoked": 2, "tool_grants_disabled": 1, "sessions_closed": 1}
    # everything cleared
    grants = gw.list_agent_grants(tenant_id=TENANT, agent_id=AGENT)
    assert grants["credentials"] == [] and grants["tool_grants"] == [] and grants["open_sessions"] == []


def test_revoke_idempotent(gw):
    gw.grant_credential(tenant_id=TENANT, agent_id=AGENT, server_id="s", credential_ref="r1")
    gw.revoke_agent_mcp(tenant_id=TENANT, agent_id=AGENT, revoked_by="ops")
    second = gw.revoke_agent_mcp(tenant_id=TENANT, agent_id=AGENT, revoked_by="ops")
    assert second == {"credentials_revoked": 0, "tool_grants_disabled": 0, "sessions_closed": 0}


def test_revoke_requires_actor(gw):
    with pytest.raises(ValueError):
        gw.revoke_agent_mcp(tenant_id=TENANT, agent_id=AGENT, revoked_by="")


def test_revoke_scoped_to_agent(gw):
    gw.grant_credential(tenant_id=TENANT, agent_id=AGENT, server_id="s", credential_ref="r1")
    gw.grant_credential(tenant_id=TENANT, agent_id="other", server_id="s", credential_ref="r2")
    gw.revoke_agent_mcp(tenant_id=TENANT, agent_id=AGENT, revoked_by="ops")
    assert len(gw.list_agent_grants(tenant_id=TENANT, agent_id="other")["credentials"]) == 1


# ── connector + bus integration ──────────────────────────────────────────────

def test_connector_revokes_via_bus(gw, monkeypatch):
    from modules.identity import revocation_bus as rb
    from modules.identity import mcp_revocation  # noqa: F401 self-registers
    # connector uses the default _DB_PATH; point it at our reloaded gw module's db
    monkeypatch.setattr("modules.identity.mcp_revocation.mcp_gateway", gw)
    rb.reset_connectors()
    gw.grant_credential(tenant_id=TENANT, agent_id=AGENT, server_id="s", credential_ref="r1")
    gw.grant_tool(tenant_id=TENANT, agent_id=AGENT, server_id="s", tool_name="t1")
    receipt = rb.rip_credentials(TENANT, AGENT, actor="ops", reason="rogue", planes=["mcp"])
    mcp = next(p for p in receipt.planes if p.plane == "mcp")
    assert mcp.status == rb.KILLED
    assert "revoked 1 credential" in mcp.detail


def test_connector_nothing_to_revoke(gw, monkeypatch):
    from modules.identity import revocation_bus as rb
    from modules.identity import mcp_revocation  # noqa: F401
    monkeypatch.setattr("modules.identity.mcp_revocation.mcp_gateway", gw)
    rb.reset_connectors()
    receipt = rb.rip_credentials(TENANT, "clean-agent", actor="ops", reason="x", planes=["mcp"])
    mcp = next(p for p in receipt.planes if p.plane == "mcp")
    assert mcp.status == rb.KILLED
    assert "no MCP" in mcp.detail
