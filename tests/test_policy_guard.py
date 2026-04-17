"""
Tests for TokenDNA PolicyGuard (Sprint 5-1)

RSA'26 Gap 1 — Agent Policy Self-Modification Detection

Covers:
  - PolicyAction dataclass construction
  - Constitutional rules: CONST-01 through CONST-05
  - Disposition logic: ALLOW / FLAG / BLOCK
  - Violation creation and persistence
  - Violation queries: list, get, filter by status/actor/disposition
  - Human approval workflow: approve / reject
  - Violation stats
  - API endpoints: evaluate, violations list, get, approve, reject, stats
  - Tenant isolation
  - Edge cases: missing fields, duplicate approval attempts
"""

from __future__ import annotations

import os
import uuid
from unittest import mock
import importlib

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def pg(tmp_path):
    """Load policy_guard module with isolated SQLite DB."""
    db_file = str(tmp_path / "pg_test.db")
    with mock.patch.dict(os.environ, {"DATA_DB_PATH": db_file}):
        import modules.identity.policy_guard as m
        importlib.reload(m)
        m.init_db()
        yield m


TENANT = "tenant-guard-test"
TENANT_B = "tenant-b"


def make_action(
    actor_id="agent-x",
    actor_type="agent",
    action_type="update",
    target_policy_id="pol-001",
    target_policy_name="edge-access-policy",
    tenant_id=TENANT,
    scope_delta=None,
    metadata=None,
):
    import modules.identity.policy_guard as m
    return m.PolicyAction(
        actor_id=actor_id,
        actor_type=actor_type,
        action_type=action_type,
        target_policy_id=target_policy_id,
        target_policy_name=target_policy_name,
        tenant_id=tenant_id,
        scope_delta=scope_delta or [],
        metadata=metadata or {},
    )


# ===========================================================================
# Disposition tests — ALLOW
# ===========================================================================

class TestAllowDisposition:
    def test_human_actor_allowed(self, pg):
        action = make_action(actor_type="human")
        result = pg.evaluate(action)
        assert result.disposition == pg.Disposition.ALLOW
        assert result.violation_id is None

    def test_agent_no_self_signals_allowed(self, pg):
        """Agent modifying an unrelated policy with no self-signals → ALLOW."""
        action = make_action(actor_type="agent", action_type="update")
        result = pg.evaluate(action)
        assert result.disposition == pg.Disposition.ALLOW

    def test_agent_read_action_allowed(self, pg):
        action = make_action(actor_type="agent", action_type="create",
                              metadata={"is_self_governing": False})
        result = pg.evaluate(action)
        assert result.disposition == pg.Disposition.ALLOW

    def test_empty_scope_delta_allowed(self, pg):
        action = make_action(scope_delta=[])
        result = pg.evaluate(action)
        assert result.disposition == pg.Disposition.ALLOW

    def test_no_violation_created_for_allow(self, pg):
        action = make_action(actor_type="human")
        pg.evaluate(action)
        violations = pg.list_violations(TENANT)
        assert len(violations) == 0


# ===========================================================================
# Disposition tests — BLOCK
# ===========================================================================

class TestBlockDisposition:
    def test_const01_self_scope_expansion(self, pg):
        """CONST-01: agent expands scope on a policy named after itself."""
        action = make_action(
            actor_id="agent-alpha",
            target_policy_name="agent-alpha-permissions",
            scope_delta=["read:prod-db", "write:prod-db"],
        )
        result = pg.evaluate(action)
        assert result.disposition == pg.Disposition.BLOCK
        assert "CONST-01" in result.rules_triggered

    def test_const01_metadata_governed_agent(self, pg):
        """CONST-01 fires via metadata.governed_agent == actor_id."""
        action = make_action(
            actor_id="agent-beta",
            scope_delta=["admin:all"],
            metadata={"governed_agent": "agent-beta"},
        )
        result = pg.evaluate(action)
        assert result.disposition == pg.Disposition.BLOCK
        assert "CONST-01" in result.rules_triggered

    def test_const02_self_restriction_delete(self, pg):
        """CONST-02: agent deletes a policy that governs itself."""
        action = make_action(
            actor_id="agent-rogue",
            action_type="delete",
            target_policy_name="agent-rogue-access-restrictions",
        )
        result = pg.evaluate(action)
        assert result.disposition == pg.Disposition.BLOCK
        assert "CONST-02" in result.rules_triggered

    def test_const02_self_restriction_rollback(self, pg):
        """CONST-02: agent rolls back its governing policy."""
        action = make_action(
            actor_id="agent-rogue",
            action_type="rollback",
            metadata={"governed_agent": "agent-rogue"},
        )
        result = pg.evaluate(action)
        assert result.disposition == pg.Disposition.BLOCK
        assert "CONST-02" in result.rules_triggered

    def test_const03_write_to_governing_policy(self, pg):
        """CONST-03: agent updates policy that is_self_governing."""
        action = make_action(
            actor_id="agent-ceo",
            action_type="update",
            metadata={"is_self_governing": True},
        )
        result = pg.evaluate(action)
        assert result.disposition == pg.Disposition.BLOCK
        assert "CONST-03" in result.rules_triggered

    def test_const03_activate_governed_policy(self, pg):
        """CONST-03: agent activates a policy marked as governing itself."""
        action = make_action(
            actor_id="agent-ceo",
            action_type="activate",
            metadata={"policy_scope": "self"},
        )
        result = pg.evaluate(action)
        assert result.disposition == pg.Disposition.BLOCK
        assert "CONST-03" in result.rules_triggered

    def test_const04_excessive_delegation(self, pg):
        """CONST-04: agent delegates permissions it doesn't have."""
        action = make_action(
            actor_id="agent-limited",
            action_type="create",
            metadata={
                "actor_scopes": ["read:reports"],
                "delegated_scopes": ["read:reports", "admin:all", "write:prod-db"],
            },
        )
        result = pg.evaluate(action)
        assert result.disposition == pg.Disposition.BLOCK
        assert "CONST-04" in result.rules_triggered

    def test_block_creates_violation_record(self, pg):
        action = make_action(
            actor_id="agent-rogue",
            action_type="delete",
            target_policy_name="agent-rogue-access-restrictions",
        )
        result = pg.evaluate(action)
        assert result.violation_id is not None
        violation = pg.get_violation(result.violation_id, TENANT)
        assert violation is not None
        assert violation.disposition == pg.Disposition.BLOCK
        assert violation.status == pg.ViolationStatus.OPEN

    def test_block_proceeds_is_false(self, pg):
        """GuardEvaluation for BLOCK has no 'proceed' field but violation_id set."""
        action = make_action(
            actor_id="agent-rogue",
            metadata={"is_self_governing": True},
        )
        result = pg.evaluate(action)
        assert result.disposition == pg.Disposition.BLOCK
        assert result.violation_id is not None


# ===========================================================================
# Disposition tests — FLAG
# ===========================================================================

class TestFlagDisposition:
    def test_const05_governance_policy_no_human_approval(self, pg):
        """CONST-05: service modifying a governance policy without human_approved."""
        action = make_action(
            actor_type="service",
            target_policy_name="federation-quorum-policy",
            action_type="update",
        )
        result = pg.evaluate(action)
        assert result.disposition == pg.Disposition.FLAG
        assert "CONST-05" in result.rules_triggered

    def test_const05_trust_policy_flagged(self, pg):
        action = make_action(
            actor_type="agent",
            target_policy_name="trust-authority-config",
            action_type="update",
        )
        result = pg.evaluate(action)
        assert result.disposition == pg.Disposition.FLAG

    def test_const05_with_human_approved_allows(self, pg):
        """CONST-05 does NOT fire when human_approved=True in metadata."""
        action = make_action(
            actor_type="service",
            target_policy_name="federation-quorum-policy",
            action_type="update",
            metadata={"human_approved": True},
        )
        result = pg.evaluate(action)
        assert result.disposition == pg.Disposition.ALLOW
        assert "CONST-05" not in result.rules_triggered

    def test_flag_creates_violation_record(self, pg):
        action = make_action(
            actor_type="service",
            target_policy_name="rbac-policy",
            action_type="update",
        )
        result = pg.evaluate(action)
        assert result.violation_id is not None
        violation = pg.get_violation(result.violation_id, TENANT)
        assert violation is not None
        assert violation.disposition == pg.Disposition.FLAG

    def test_block_beats_flag_when_both_triggered(self, pg):
        """If both BLOCK and FLAG rules trigger, disposition is BLOCK."""
        action = make_action(
            actor_id="agent-rogue",
            actor_type="agent",
            action_type="update",
            target_policy_name="agent-rogue-governance-rbac",  # CONST-05 (governance) + CONST-01 if scope_delta
            metadata={"is_self_governing": True},  # CONST-03 BLOCK
        )
        result = pg.evaluate(action)
        assert result.disposition == pg.Disposition.BLOCK


# ===========================================================================
# Violation lifecycle tests
# ===========================================================================

class TestViolationLifecycle:
    def test_list_violations_empty(self, pg):
        assert pg.list_violations(TENANT) == []

    def test_list_violations_after_block(self, pg):
        action = make_action(metadata={"is_self_governing": True})
        pg.evaluate(action)
        violations = pg.list_violations(TENANT)
        assert len(violations) == 1
        assert violations[0].status == pg.ViolationStatus.OPEN

    def test_list_violations_filter_by_status(self, pg):
        action = make_action(metadata={"is_self_governing": True})
        result = pg.evaluate(action)
        pg.approve_violation(result.violation_id, TENANT, "ops-team")
        open_violations = pg.list_violations(TENANT, status="open")
        approved_violations = pg.list_violations(TENANT, status="approved")
        assert len(open_violations) == 0
        assert len(approved_violations) == 1

    def test_list_violations_filter_by_actor(self, pg):
        pg.evaluate(make_action(actor_id="agent-a", metadata={"is_self_governing": True}))
        pg.evaluate(make_action(actor_id="agent-b", metadata={"is_self_governing": True}))
        a_violations = pg.list_violations(TENANT, actor_id="agent-a")
        assert len(a_violations) == 1
        assert a_violations[0].actor_id == "agent-a"

    def test_list_violations_filter_by_disposition(self, pg):
        pg.evaluate(make_action(metadata={"is_self_governing": True}))  # BLOCK
        pg.evaluate(make_action(actor_type="service",
                                target_policy_name="rbac-policy"))  # FLAG
        block_v = pg.list_violations(TENANT, disposition="block")
        flag_v = pg.list_violations(TENANT, disposition="flag")
        assert len(block_v) == 1
        assert len(flag_v) == 1

    def test_get_violation_by_id(self, pg):
        action = make_action(metadata={"is_self_governing": True})
        result = pg.evaluate(action)
        v = pg.get_violation(result.violation_id, TENANT)
        assert v is not None
        assert v.violation_id == result.violation_id
        assert v.actor_id == action.actor_id

    def test_get_nonexistent_violation_returns_none(self, pg):
        assert pg.get_violation("doesnotexist", TENANT) is None

    def test_tenant_isolation_violations(self, pg):
        pg.evaluate(make_action(tenant_id=TENANT, metadata={"is_self_governing": True}))
        v_b = pg.list_violations(TENANT_B)
        assert len(v_b) == 0

    def test_multiple_violations_ordered_newest_first(self, pg):
        import time
        for i in range(3):
            pg.evaluate(make_action(
                actor_id=f"agent-{i}",
                metadata={"is_self_governing": True},
            ))
            time.sleep(0.01)
        violations = pg.list_violations(TENANT)
        # Most recent first
        assert violations[0].detected_at >= violations[-1].detected_at


# ===========================================================================
# Human approval workflow
# ===========================================================================

class TestApprovalWorkflow:
    def test_approve_violation(self, pg):
        result = pg.evaluate(make_action(metadata={"is_self_governing": True}))
        vid = result.violation_id
        v = pg.approve_violation(vid, TENANT, "alice@ops.com", "reviewed — one-time exception")
        assert v is not None
        assert v.status == pg.ViolationStatus.APPROVED
        assert v.resolved_by == "alice@ops.com"
        assert v.resolution_note == "reviewed — one-time exception"
        assert v.resolved_at is not None

    def test_reject_violation(self, pg):
        result = pg.evaluate(make_action(metadata={"is_self_governing": True}))
        vid = result.violation_id
        v = pg.reject_violation(vid, TENANT, "bob@sec.com", "denied — self-modification not permitted")
        assert v is not None
        assert v.status == pg.ViolationStatus.REJECTED
        assert v.resolved_by == "bob@sec.com"

    def test_approve_nonexistent_returns_none(self, pg):
        v = pg.approve_violation("nonexistent", TENANT, "operator")
        assert v is None

    def test_reject_nonexistent_returns_none(self, pg):
        v = pg.reject_violation("nonexistent", TENANT, "operator")
        assert v is None

    def test_approve_already_approved_returns_none(self, pg):
        """Double-approval should fail gracefully (not idempotent)."""
        result = pg.evaluate(make_action(metadata={"is_self_governing": True}))
        vid = result.violation_id
        pg.approve_violation(vid, TENANT, "alice")
        # Second approval attempt — already resolved, should return None
        v = pg.approve_violation(vid, TENANT, "bob")
        assert v is None

    def test_reject_after_approve_returns_none(self, pg):
        result = pg.evaluate(make_action(metadata={"is_self_governing": True}))
        vid = result.violation_id
        pg.approve_violation(vid, TENANT, "alice")
        v = pg.reject_violation(vid, TENANT, "bob")
        assert v is None  # already resolved


# ===========================================================================
# Violation stats
# ===========================================================================

class TestViolationStats:
    def test_empty_stats(self, pg):
        stats = pg.violation_stats(TENANT)
        assert stats["total"] == 0
        assert stats["open"] == 0
        assert stats["blocked"] == 0

    def test_stats_after_violations(self, pg):
        # 2 BLOCK violations
        r1 = pg.evaluate(make_action(actor_id="a1", metadata={"is_self_governing": True}))
        r2 = pg.evaluate(make_action(actor_id="a2", metadata={"is_self_governing": True}))
        # 1 FLAG violation
        pg.evaluate(make_action(actor_type="service", target_policy_name="rbac-policy"))
        # Approve r1
        pg.approve_violation(r1.violation_id, TENANT, "ops")

        stats = pg.violation_stats(TENANT)
        assert stats["total"] == 3
        assert stats["open"] == 2    # r2 + flag
        assert stats["blocked"] == 2
        assert stats["flagged"] == 1
        assert stats["approved"] == 1

    def test_stats_tenant_isolation(self, pg):
        pg.evaluate(make_action(tenant_id=TENANT, metadata={"is_self_governing": True}))
        stats_b = pg.violation_stats(TENANT_B)
        assert stats_b["total"] == 0


# ===========================================================================
# API endpoint tests
# ===========================================================================

@pytest.fixture
def api_client(tmp_path):
    db_file = str(tmp_path / "api_pg_test.db")
    with mock.patch.dict(os.environ, {"DATA_DB_PATH": db_file, "DEV_MODE": "true"}):
        from modules.tenants import store as ts
        importlib.reload(ts)
        ts.init_db()

        import modules.identity.policy_guard as pg
        importlib.reload(pg)
        pg.init_db()

        import modules.tenants.middleware as mw
        importlib.reload(mw)
        import auth as auth_module
        importlib.reload(auth_module)

        from fastapi.testclient import TestClient
        import api as api_module
        importlib.reload(api_module)
        client = TestClient(api_module.app, raise_server_exceptions=False)
        yield client


def _auth():
    return {"X-API-Key": "dev-api-key"}


class TestPolicyGuardAPI:
    def test_evaluate_allow(self, api_client):
        body = {
            "actor_id": "agent-good",
            "actor_type": "human",
            "action_type": "update",
            "target_policy_id": "pol-unrelated",
            "target_policy_name": "unrelated-policy",
        }
        resp = api_client.post("/api/policy/guard/evaluate", json=body, headers=_auth())
        assert resp.status_code == 200
        data = resp.json()
        assert data["disposition"] == "allow"
        assert data["proceed"] is True
        assert data["violation_id"] is None

    def test_evaluate_block_self_modification(self, api_client):
        body = {
            "actor_id": "agent-rogue",
            "actor_type": "agent",
            "action_type": "update",
            "target_policy_id": "pol-001",
            "target_policy_name": "some-policy",
            "metadata": {"is_self_governing": True},
        }
        resp = api_client.post("/api/policy/guard/evaluate", json=body, headers=_auth())
        assert resp.status_code == 200
        data = resp.json()
        assert data["disposition"] == "block"
        assert data["proceed"] is False
        assert data["violation_id"] is not None
        assert len(data["rules_triggered"]) >= 1
        assert len(data["reasons"]) >= 1

    def test_evaluate_missing_fields_returns_400(self, api_client):
        resp = api_client.post("/api/policy/guard/evaluate", json={}, headers=_auth())
        assert resp.status_code == 400

    def test_violations_empty(self, api_client):
        resp = api_client.get("/api/policy/guard/violations", headers=_auth())
        assert resp.status_code == 200
        data = resp.json()
        assert data["violations"] == []
        assert data["count"] == 0

    def test_violations_after_block(self, api_client):
        api_client.post("/api/policy/guard/evaluate", headers=_auth(), json={
            "actor_id": "agent-rogue",
            "actor_type": "agent",
            "action_type": "update",
            "target_policy_id": "pol-001",
            "target_policy_name": "some-policy",
            "metadata": {"is_self_governing": True},
        })
        resp = api_client.get("/api/policy/guard/violations", headers=_auth())
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1

    def test_get_violation_by_id(self, api_client):
        r = api_client.post("/api/policy/guard/evaluate", headers=_auth(), json={
            "actor_id": "agent-rogue",
            "actor_type": "agent",
            "action_type": "update",
            "target_policy_id": "pol-001",
            "target_policy_name": "some-policy",
            "metadata": {"is_self_governing": True},
        }).json()
        vid = r["violation_id"]
        resp = api_client.get(f"/api/policy/guard/violations/{vid}", headers=_auth())
        assert resp.status_code == 200
        assert resp.json()["violation_id"] == vid

    def test_get_nonexistent_violation_returns_404(self, api_client):
        resp = api_client.get("/api/policy/guard/violations/does-not-exist",
                              headers=_auth())
        assert resp.status_code == 404

    def test_approve_violation(self, api_client):
        r = api_client.post("/api/policy/guard/evaluate", headers=_auth(), json={
            "actor_id": "agent-rogue",
            "actor_type": "agent",
            "action_type": "update",
            "target_policy_id": "pol-001",
            "target_policy_name": "some-policy",
            "metadata": {"is_self_governing": True},
        }).json()
        vid = r["violation_id"]
        resp = api_client.post(f"/api/policy/guard/violations/{vid}/approve",
                               json={"approved_by": "alice@ops.com"},
                               headers=_auth())
        assert resp.status_code == 200
        assert resp.json()["status"] == "approved"
        assert resp.json()["proceed"] is True

    def test_reject_violation(self, api_client):
        r = api_client.post("/api/policy/guard/evaluate", headers=_auth(), json={
            "actor_id": "agent-rogue",
            "actor_type": "agent",
            "action_type": "update",
            "target_policy_id": "pol-001",
            "target_policy_name": "some-policy",
            "metadata": {"is_self_governing": True},
        }).json()
        vid = r["violation_id"]
        resp = api_client.post(f"/api/policy/guard/violations/{vid}/reject",
                               json={"rejected_by": "security-team"},
                               headers=_auth())
        assert resp.status_code == 200
        assert resp.json()["status"] == "rejected"
        assert resp.json()["proceed"] is False

    def test_stats_endpoint(self, api_client):
        resp = api_client.get("/api/policy/guard/stats", headers=_auth())
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "open" in data
        assert "blocked" in data

    def test_evaluate_flag_disposition(self, api_client):
        resp = api_client.post("/api/policy/guard/evaluate", headers=_auth(), json={
            "actor_id": "service-worker",
            "actor_type": "service",
            "action_type": "update",
            "target_policy_id": "pol-rbac",
            "target_policy_name": "rbac-policy",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["disposition"] == "flag"
