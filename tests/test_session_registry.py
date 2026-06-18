"""Tests for the agent live-session registry + kill connector (Epic 2.3)."""
from __future__ import annotations

import importlib

import pytest


@pytest.fixture()
def sr(tmp_path, monkeypatch):
    # Reload with DATA_DB_PATH set so the module's default db_path binds to tmp.
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "sessions.db"))
    import modules.identity.session_registry as m
    importlib.reload(m)
    m.init_db()
    return m


TENANT = "tenant-s"
AGENT = "agent-rogue"


def test_register_and_list(sr):
    sr.register_session(tenant_id=TENANT, agent_id=AGENT, channel="ws")
    sr.register_session(tenant_id=TENANT, agent_id=AGENT, channel="stream")
    assert len(sr.list_active_sessions(TENANT, AGENT)) == 2


def test_is_session_active(sr):
    s = sr.register_session(tenant_id=TENANT, agent_id=AGENT)
    assert sr.is_session_active(TENANT, s["session_id"]) is True
    assert sr.is_session_active(TENANT, "nonexistent") is False


def test_terminate_invalidates_server_side(sr):
    s = sr.register_session(tenant_id=TENANT, agent_id=AGENT)
    res = sr.terminate_agent_sessions(TENANT, AGENT, terminated_by="ops")
    assert res["sessions_terminated"] == 1
    # server-side invalidation: the runtime's next-frame check now rejects it
    assert sr.is_session_active(TENANT, s["session_id"]) is False
    assert sr.list_active_sessions(TENANT, AGENT) == []


def test_terminate_idempotent(sr):
    sr.register_session(tenant_id=TENANT, agent_id=AGENT)
    sr.terminate_agent_sessions(TENANT, AGENT, terminated_by="ops")
    second = sr.terminate_agent_sessions(TENANT, AGENT, terminated_by="ops")
    assert second["sessions_terminated"] == 0


def test_terminate_requires_actor(sr):
    with pytest.raises(ValueError):
        sr.terminate_agent_sessions(TENANT, AGENT, terminated_by="")


def test_terminate_scoped_to_agent(sr):
    sr.register_session(tenant_id=TENANT, agent_id=AGENT)
    sr.register_session(tenant_id=TENANT, agent_id="other")
    sr.terminate_agent_sessions(TENANT, AGENT, terminated_by="ops")
    assert len(sr.list_active_sessions(TENANT, "other")) == 1


# ── connector + bus ───────────────────────────────────────────────────────────

def test_connector_via_bus(sr, monkeypatch):
    from modules.identity import revocation_bus as rb
    from modules.identity import session_revocation
    # point the connector at the reloaded (tmp-db) registry module
    monkeypatch.setattr(session_revocation, "session_registry", sr)
    rb.reset_connectors()
    sr.register_session(tenant_id=TENANT, agent_id=AGENT)
    receipt = rb.rip_credentials(TENANT, AGENT, actor="ops", reason="rogue", planes=["live_sessions"])
    plane = next(p for p in receipt.planes if p.plane == "live_sessions")
    assert plane.status == rb.KILLED
    assert "terminated 1 live session" in plane.detail
