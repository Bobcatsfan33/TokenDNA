"""
Tests for modules/identity/agent_lifecycle.py — Ghost Agent Offboarding.

Sprint 5-3: covers inventory CRUD, lifecycle state machine, orphan detection,
deception-mesh integration, and heartbeat gating.
"""

from __future__ import annotations

import os
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

# ── Fixture: isolated DB ──────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Each test gets its own SQLite database."""
    db_file = tmp_path / "test_lifecycle.db"
    monkeypatch.setenv("DATA_DB_PATH", str(db_file))
    # Re-import after env var set so module uses correct path
    import importlib
    import modules.identity.agent_lifecycle as al
    importlib.reload(al)
    al.init_db()
    yield al


# ── Helpers ───────────────────────────────────────────────────────────────────

TENANT = "tenant-test-001"


def _register(al, *, name="Test Agent", platform="aws", owner="ops@acme.io",
               creds=None, token=None, agent_id=None):
    return al.register_agent(
        tenant_id=TENANT,
        agent_id=agent_id,
        display_name=name,
        platform=platform,
        owner=owner,
        credential_ids=creds or [],
        last_token_id=token,
    )


# ── Registration ──────────────────────────────────────────────────────────────

def test_register_creates_active_agent(isolated_db):
    al = isolated_db
    agent = _register(al, name="Billing Bot")
    assert agent["status"] == "active"
    assert agent["display_name"] == "Billing Bot"
    assert agent["tenant_id"] == TENANT


def test_register_assigns_uuid_when_no_id_given(isolated_db):
    al = isolated_db
    agent = _register(al)
    assert uuid.UUID(agent["agent_id"])  # valid UUID — no exception


def test_register_custom_agent_id(isolated_db):
    al = isolated_db
    agent = _register(al, agent_id="agt-custom-123")
    assert agent["agent_id"] == "agt-custom-123"


def test_register_duplicate_raises(isolated_db):
    al = isolated_db
    _register(al, agent_id="agt-dup")
    with pytest.raises(ValueError, match="already registered"):
        _register(al, agent_id="agt-dup")


def test_get_agent_not_found_raises(isolated_db):
    al = isolated_db
    with pytest.raises(KeyError):
        al.get_agent(tenant_id=TENANT, agent_id="nonexistent")


def test_register_stores_credential_ids(isolated_db):
    al = isolated_db
    agent = _register(al, creds=["cred-1", "cred-2"])
    assert "cred-1" in agent["credential_ids"]
    assert "cred-2" in agent["credential_ids"]


# ── Heartbeat ─────────────────────────────────────────────────────────────────

def test_heartbeat_updates_last_seen(isolated_db):
    al = isolated_db
    agent = _register(al)
    original_seen = agent["last_seen_at"]
    time.sleep(0.01)
    updated = al.record_heartbeat(tenant_id=TENANT, agent_id=agent["agent_id"])
    assert updated["last_seen_at"] >= original_seen


def test_heartbeat_on_decommissioned_raises(isolated_db):
    al = isolated_db
    agent = _register(al)
    al.decommission_agent(tenant_id=TENANT, agent_id=agent["agent_id"])
    with pytest.raises(ValueError, match="decommissioned"):
        al.record_heartbeat(tenant_id=TENANT, agent_id=agent["agent_id"])


def test_heartbeat_unknown_agent_raises(isolated_db):
    al = isolated_db
    with pytest.raises(KeyError):
        al.record_heartbeat(tenant_id=TENANT, agent_id="ghost-xyz")


# ── Suspension ────────────────────────────────────────────────────────────────

def test_suspend_active_agent(isolated_db):
    al = isolated_db
    agent = _register(al)
    suspended = al.suspend_agent(
        tenant_id=TENANT, agent_id=agent["agent_id"],
        actor="security@acme.io", reason="pilot ended"
    )
    assert suspended["status"] == "suspended"
    assert suspended["suspended_by"] == "security@acme.io"


def test_suspend_already_suspended_raises(isolated_db):
    al = isolated_db
    agent = _register(al)
    al.suspend_agent(tenant_id=TENANT, agent_id=agent["agent_id"])
    with pytest.raises(ValueError, match="Cannot suspend"):
        al.suspend_agent(tenant_id=TENANT, agent_id=agent["agent_id"])


def test_suspend_decommissioned_raises(isolated_db):
    al = isolated_db
    agent = _register(al)
    al.decommission_agent(tenant_id=TENANT, agent_id=agent["agent_id"])
    with pytest.raises(ValueError, match="Cannot suspend"):
        al.suspend_agent(tenant_id=TENANT, agent_id=agent["agent_id"])


# ── Reactivation ──────────────────────────────────────────────────────────────

def test_reactivate_suspended_agent(isolated_db):
    al = isolated_db
    agent = _register(al)
    al.suspend_agent(tenant_id=TENANT, agent_id=agent["agent_id"])
    reactivated = al.reactivate_agent(tenant_id=TENANT, agent_id=agent["agent_id"])
    assert reactivated["status"] == "active"
    assert reactivated["suspended_at"] is None


def test_reactivate_active_raises(isolated_db):
    al = isolated_db
    agent = _register(al)
    with pytest.raises(ValueError, match="Cannot reactivate"):
        al.reactivate_agent(tenant_id=TENANT, agent_id=agent["agent_id"])


def test_reactivate_decommissioned_raises(isolated_db):
    al = isolated_db
    agent = _register(al)
    al.decommission_agent(tenant_id=TENANT, agent_id=agent["agent_id"])
    with pytest.raises(ValueError, match="Cannot reactivate"):
        al.reactivate_agent(tenant_id=TENANT, agent_id=agent["agent_id"])


# ── Decommission ──────────────────────────────────────────────────────────────

def test_decommission_active_agent(isolated_db):
    al = isolated_db
    agent = _register(al)
    result = al.decommission_agent(
        tenant_id=TENANT, agent_id=agent["agent_id"],
        actor="admin@acme.io", reason="project cancelled"
    )
    assert result["status"] == "decommissioned"
    assert result["decommissioned_by"] == "admin@acme.io"
    assert result["decommission_reason"] == "project cancelled"


def test_decommission_suspended_agent(isolated_db):
    al = isolated_db
    agent = _register(al)
    al.suspend_agent(tenant_id=TENANT, agent_id=agent["agent_id"])
    result = al.decommission_agent(tenant_id=TENANT, agent_id=agent["agent_id"])
    assert result["status"] == "decommissioned"


def test_decommission_already_decommissioned_raises(isolated_db):
    al = isolated_db
    agent = _register(al)
    al.decommission_agent(tenant_id=TENANT, agent_id=agent["agent_id"])
    with pytest.raises(ValueError, match="Cannot decommission"):
        al.decommission_agent(tenant_id=TENANT, agent_id=agent["agent_id"])


def test_decommission_creates_decoy_from_token(isolated_db):
    al = isolated_db
    agent = _register(al, token="tok-live-abc123")
    al.decommission_agent(tenant_id=TENANT, agent_id=agent["agent_id"])
    decoys = al.get_decoys(tenant_id=TENANT)
    assert len(decoys) == 1
    assert decoys[0]["token_id"] == "tok-live-abc123"
    assert decoys[0]["source"] == "ghost_agent"
    assert decoys[0]["hits"] == 0


def test_decommission_no_token_no_decoy(isolated_db):
    al = isolated_db
    agent = _register(al)  # no token
    al.decommission_agent(tenant_id=TENANT, agent_id=agent["agent_id"])
    decoys = al.get_decoys(tenant_id=TENANT)
    assert len(decoys) == 0


# ── Deception mesh ────────────────────────────────────────────────────────────

def test_decoy_hit_increments_counter(isolated_db):
    al = isolated_db
    agent = _register(al, token="tok-honeypot")
    al.decommission_agent(tenant_id=TENANT, agent_id=agent["agent_id"])
    result = al.record_decoy_hit(tenant_id=TENANT, token_id="tok-honeypot")
    assert result is not None
    assert result["hits"] == 1


def test_decoy_hit_unknown_token_returns_none(isolated_db):
    al = isolated_db
    result = al.record_decoy_hit(tenant_id=TENANT, token_id="tok-not-a-decoy")
    assert result is None


# ── Inventory listing ─────────────────────────────────────────────────────────

def test_list_inventory_all(isolated_db):
    al = isolated_db
    _register(al, name="A")
    _register(al, name="B")
    agents = al.list_inventory(tenant_id=TENANT)
    assert len(agents) == 2


def test_list_inventory_filter_by_status(isolated_db):
    al = isolated_db
    a = _register(al, name="A")
    _register(al, name="B")
    al.suspend_agent(tenant_id=TENANT, agent_id=a["agent_id"])
    active = al.list_inventory(tenant_id=TENANT, status="active")
    assert all(x["status"] == "active" for x in active)
    assert len(active) == 1


def test_list_inventory_invalid_status_raises(isolated_db):
    al = isolated_db
    with pytest.raises(ValueError, match="Invalid status"):
        al.list_inventory(tenant_id=TENANT, status="zombie")


# ── Orphan detection ──────────────────────────────────────────────────────────

def test_orphan_detection_flags_stale_agents(isolated_db, monkeypatch):
    al = isolated_db
    # Register an agent and manually backdate last_seen_at
    agent = _register(al, name="Old Bot")
    stale_time = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
    import sqlite3
    db_path = os.environ["DATA_DB_PATH"]
    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE agent_inventory SET last_seen_at = ? WHERE agent_id = ?",
        (stale_time, agent["agent_id"]),
    )
    conn.commit()
    conn.close()

    orphans = al.list_orphans(tenant_id=TENANT, orphan_days=30)
    assert len(orphans) == 1
    assert orphans[0]["agent_id"] == agent["agent_id"]
    assert orphans[0]["days_inactive"] >= 45


def test_orphan_detection_excludes_recent_agents(isolated_db):
    al = isolated_db
    _register(al, name="Fresh Bot")
    orphans = al.list_orphans(tenant_id=TENANT, orphan_days=30)
    assert len(orphans) == 0


def test_orphan_detection_excludes_decommissioned(isolated_db, monkeypatch):
    al = isolated_db
    agent = _register(al, name="Old Decommissioned Bot")
    stale_time = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
    import sqlite3
    db_path = os.environ["DATA_DB_PATH"]
    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE agent_inventory SET last_seen_at = ? WHERE agent_id = ?",
        (stale_time, agent["agent_id"]),
    )
    conn.commit()
    conn.close()
    al.decommission_agent(tenant_id=TENANT, agent_id=agent["agent_id"])

    orphans = al.list_orphans(tenant_id=TENANT, orphan_days=30)
    assert len(orphans) == 0  # decommissioned agents excluded


# ── Lifecycle events ──────────────────────────────────────────────────────────

def test_lifecycle_events_recorded(isolated_db):
    al = isolated_db
    agent = _register(al, name="Tracked Bot")
    al.suspend_agent(tenant_id=TENANT, agent_id=agent["agent_id"], reason="test")
    al.reactivate_agent(tenant_id=TENANT, agent_id=agent["agent_id"])
    al.decommission_agent(tenant_id=TENANT, agent_id=agent["agent_id"])
    events = al.get_lifecycle_events(tenant_id=TENANT, agent_id=agent["agent_id"])
    event_types = [e["event_type"] for e in events]
    assert "registered" in event_types
    assert "suspended" in event_types
    assert "reactivated" in event_types
    assert "decommissioned" in event_types


def test_tenant_isolation(isolated_db):
    al = isolated_db
    _register(al, name="Tenant A Bot")
    agents_b = al.list_inventory(tenant_id="other-tenant")
    assert len(agents_b) == 0
