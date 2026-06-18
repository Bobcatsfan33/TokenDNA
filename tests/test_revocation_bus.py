"""Tests for the Revocation Fan-out Bus (Gap roadmap, Challenge D)."""
from __future__ import annotations

import os
import time

import pytest

from modules.identity import revocation_bus as rb


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "rb.db"))
    rb.reset_connectors()
    yield
    rb.reset_connectors()


# ── mock connectors ───────────────────────────────────────────────────────────

class _Mock:
    def __init__(self, plane, *, connected=True, reversible=False, fail=False, delay=0.0):
        self.plane = plane
        self.reversible = reversible
        self._connected = connected
        self._fail = fail
        self._delay = delay
        self.revoked = []
        self.reversed = []

    def is_connected(self, tenant_id):
        return self._connected

    def revoke(self, tenant_id, agent_id, context):
        if self._delay:
            time.sleep(self._delay)
        if self._fail:
            raise RuntimeError("boom")
        self.revoked.append((tenant_id, agent_id, context.get("actor")))
        return f"{self.plane} revoked"

    def reverse(self, tenant_id, agent_id, context):
        self.reversed.append((tenant_id, agent_id))
        return f"{self.plane} restored"


# ── receipt logic ─────────────────────────────────────────────────────────────

def test_overall_complete():
    r = rb.KillReceipt("a", "t", "actor", "r", "rip", planes=[
        rb.PlaneResult("x", rb.KILLED), rb.PlaneResult("y", rb.NOT_CONNECTED)])
    assert r.overall == "complete"


def test_overall_partial():
    r = rb.KillReceipt("a", "t", "actor", "r", "rip", planes=[
        rb.PlaneResult("x", rb.KILLED), rb.PlaneResult("y", rb.FAILED)])
    assert r.overall == "partial"


def test_overall_failed():
    r = rb.KillReceipt("a", "t", "actor", "r", "rip", planes=[
        rb.PlaneResult("x", rb.FAILED), rb.PlaneResult("y", rb.TIMEOUT)])
    assert r.overall == "failed"


def test_overall_noop_when_empty():
    assert rb.KillReceipt("a", "t", "x", "r", "rip").overall == "noop"


# ── rip behavior ───────────────────────────────────────────────────────────────

def test_rip_requires_actor():
    with pytest.raises(ValueError):
        rb.rip_credentials("t", "a", actor="", reason="x")


def test_rip_runs_all_connectors():
    rb.reset_connectors()
    m1, m2 = _Mock("p1"), _Mock("p2")
    rb.register_connector(m1)
    rb.register_connector(m2)
    receipt = rb.rip_credentials("t", "agent", actor="ops", reason="rogue")
    assert receipt.overall == "complete"
    assert {p.plane for p in receipt.planes} >= {"p1", "p2"}
    assert m1.revoked and m2.revoked
    assert m1.revoked[0][2] == "ops"  # actor propagated


def test_rip_failed_plane_is_partial_not_crash():
    rb.reset_connectors()
    rb.register_connector(_Mock("good"))
    rb.register_connector(_Mock("bad", fail=True))
    receipt = rb.rip_credentials("t", "agent", actor="ops", reason="x")
    statuses = {p.plane: p.status for p in receipt.planes}
    assert statuses["good"] == rb.KILLED
    assert statuses["bad"] == rb.FAILED
    assert receipt.overall == "partial"


def test_rip_not_connected_plane_skipped():
    rb.reset_connectors()
    rb.register_connector(_Mock("off", connected=False))
    receipt = rb.rip_credentials("t", "agent", actor="ops", reason="x")
    pr = next(p for p in receipt.planes if p.plane == "off")
    assert pr.status == rb.NOT_CONNECTED


def test_rip_timeout_marked():
    rb.reset_connectors()
    rb.register_connector(_Mock("slow", delay=0.5))
    receipt = rb.rip_credentials("t", "agent", actor="ops", reason="x", timeout_ms=50)
    pr = next(p for p in receipt.planes if p.plane == "slow")
    assert pr.status == rb.TIMEOUT


def test_rip_plane_selection():
    rb.reset_connectors()
    rb.register_connector(_Mock("p1"))
    rb.register_connector(_Mock("p2"))
    receipt = rb.rip_credentials("t", "agent", actor="ops", reason="x", planes=["p1"])
    assert {p.plane for p in receipt.planes} == {"p1"}


def test_rip_idempotent():
    rb.reset_connectors()
    m = _Mock("p1")
    rb.register_connector(m)
    rb.rip_credentials("t", "agent", actor="ops", reason="x")
    rb.rip_credentials("t", "agent", actor="ops", reason="x")
    assert len(m.revoked) == 2  # safe to call twice; connector idempotent


# ── preview ────────────────────────────────────────────────────────────────────

def test_preview_no_side_effects():
    rb.reset_connectors()
    m = _Mock("p1")
    rb.register_connector(m)
    receipt = rb.preview("t", "agent")
    assert receipt.action == "preview"
    assert any(p.plane == "p1" and p.status == rb.KILLED for p in receipt.planes)
    assert m.revoked == []  # preview must not revoke


# ── reverse ────────────────────────────────────────────────────────────────────

def test_reverse_restores_reversible_only():
    rb.reset_connectors()
    rev = _Mock("rev", reversible=True)
    irr = _Mock("irr", reversible=False)
    rb.register_connector(rev)
    rb.register_connector(irr)
    receipt = rb.reverse_rip("t", "agent", actor="ops", reason="restore")
    statuses = {p.plane: p.status for p in receipt.planes}
    assert statuses["rev"] == rb.KILLED
    assert statuses["irr"] == rb.NOT_CONNECTED  # irreversible -> nothing to restore
    assert rev.reversed and not irr.reversed


# ── built-in connectors ────────────────────────────────────────────────────────

def test_decision_connector_activates_kill_switch():
    from modules.identity import enforcement_plane
    c = rb.TokenDNADecisionConnector()
    c.revoke("tenant-x", "agent-x", {"actor": "ops", "reason": "rogue"})
    status = enforcement_plane.get_kill_switch_status("tenant-x", "agent-x")
    assert status["active"] is True


def test_decision_connector_reversible():
    from modules.identity import enforcement_plane
    c = rb.TokenDNADecisionConnector()
    c.revoke("tenant-y", "agent-y", {"actor": "ops"})
    c.reverse("tenant-y", "agent-y", {"actor": "ops"})
    assert enforcement_plane.get_kill_switch_status("tenant-y", "agent-y")["active"] is False


def test_edge_connector_revokes_provided_jtis(monkeypatch):
    # Assert the connector calls revoke_token per jti (no live Redis dependency —
    # cache_redis is best-effort and swallows connection errors).
    import modules.identity.cache_redis as cache_redis
    calls = []
    monkeypatch.setattr(cache_redis, "revoke_token",
                        lambda jti, **kw: calls.append((jti, kw.get("tenant_id"))))
    c = rb.EdgeJWTConnector()
    detail = c.revoke("t", "agent", {"actor": "ops", "jtis": ["jti-1", "jti-2"]})
    assert "2 token" in detail
    assert ("jti-1", "t") in calls and ("jti-2", "t") in calls


def test_edge_connector_no_tokens():
    c = rb.EdgeJWTConnector()
    detail = c.revoke("t", "agent-none", {"actor": "ops"})
    assert "no known token" in detail


# ── audit emission ─────────────────────────────────────────────────────────────

def test_rip_emits_audit(monkeypatch):
    events = []
    import modules.security.audit_log as audit
    monkeypatch.setattr(audit, "log_event",
                        lambda et, *a, **k: events.append(getattr(et, "value", str(et))))
    rb.reset_connectors()
    rb.register_connector(_Mock("p1"))
    rb.register_connector(_Mock("bad", fail=True))
    rb.rip_credentials("t", "agent", actor="ops", reason="x")
    assert "kill.rip.initiated" in events
    assert "kill.plane.revoked" in events
    assert "kill.plane.failed" in events


# ── API layer (TestClient) ─────────────────────────────────────────────────────

@pytest.fixture()
def kill_client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "kill_api.db"))
    import api as app_module
    from fastapi.testclient import TestClient
    from modules.security import rbac
    from modules.tenants.models import Plan, TenantContext

    tenant = TenantContext(
        tenant_id="tenant-kill", tenant_name="K",
        plan=Plan.ENTERPRISE, api_key_id="opskey", role="owner",
    )
    app_module.app.dependency_overrides[rbac._get_tenant_ctx] = lambda: tenant
    rb.reset_connectors()
    rb.register_connector(_Mock("p1"))
    rb.register_connector(_Mock("rev", reversible=True))
    yield TestClient(app_module.app, raise_server_exceptions=False)
    app_module.app.dependency_overrides.clear()
    rb.reset_connectors()


def test_api_preview(kill_client):
    r = kill_client.get("/api/kill/agent-1/preview")
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "preview"
    assert any(p["plane"] == "p1" for p in body["planes"])


def test_api_rip_requires_reason(kill_client):
    r = kill_client.post("/api/kill/agent-1", json={})
    assert r.status_code == 400


def test_api_rip_success(kill_client):
    r = kill_client.post("/api/kill/agent-1", json={"reason": "rogue agent"})
    assert r.status_code == 200
    body = r.json()
    assert body["overall"] == "complete"
    assert body["killed"] >= 1
    assert body["actor"] == "opskey"  # derived from tenant


def test_api_reverse(kill_client):
    kill_client.post("/api/kill/agent-1", json={"reason": "rogue"})
    r = kill_client.post("/api/kill/agent-1/reverse", json={"reason": "false positive"})
    assert r.status_code == 200
    assert r.json()["action"] == "reverse"
