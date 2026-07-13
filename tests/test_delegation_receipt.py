"""
Tests for modules/identity/delegation_receipt.py

Covers the prompt's gate explicitly:
  - 3-hop chain (human → A → B → C) verifies at every hop.
  - Cascade revocation of A's receipt invalidates B and C.
  - Agent B cannot issue a receipt for a scope wider than its own.

Plus the supporting cases:
  - Scope subset semantics including ``*`` and ``ns:*`` wildcards.
  - Signature tampering is detected.
  - Expired receipts fail verification.
  - Tenant isolation on lookup / verify / revoke.
  - get_receipts_for_agent active-only default.
  - export_chain_report rolls per-hop verification into ``overall_valid``.
  - Route-level integration via TestClient.
"""

from __future__ import annotations

import os
import sys
from datetime import timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def tmp_db(tmp_path, monkeypatch):
    db = str(tmp_path / "delegation.db")
    monkeypatch.setenv("DATA_DB_PATH", db)
    monkeypatch.setenv("TOKENDNA_DELEGATION_SECRET", "test-secret-1234567890")
    yield db


@pytest.fixture()
def dr(tmp_db):
    import importlib
    import modules.identity.delegation_receipt as m
    importlib.reload(m)
    m.init_db()
    return m


TENANT = "tenant-test"
HUMAN = "human:alice"


def _three_hop_chain(dr):
    """human:alice → agt-A → agt-B → agt-C — each hop strictly narrowing."""
    r1 = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:*", "queue:read"], 3600)
    r2 = dr.issue_receipt(TENANT, "agt-A", "agt-B", ["db:read", "db:write"],
                          3600, parent_receipt_id=r1.receipt_id)
    r3 = dr.issue_receipt(TENANT, "agt-B", "agt-C", ["db:read"],
                          3600, parent_receipt_id=r2.receipt_id)
    return r1, r2, r3


# ─────────────────────────────────────────────────────────────────────────────
# Scope subset semantics
# ─────────────────────────────────────────────────────────────────────────────

class TestScopeSubset:
    def test_wildcard_covers_anything(self, dr):
        assert dr._is_subset(["*"], ["db:read", "queue:write"]) is True

    def test_ns_wildcard_covers_within_namespace(self, dr):
        assert dr._is_subset(["db:*"], ["db:read", "db:write"]) is True
        assert dr._is_subset(["db:*"], ["db"]) is True
        assert dr._is_subset(["db:*"], ["queue:read"]) is False

    def test_exact_match_only(self, dr):
        assert dr._is_subset(["db:read"], ["db:read"]) is True
        assert dr._is_subset(["db:read"], ["db:write"]) is False

    def test_empty_child_is_subset(self, dr):
        assert dr._is_subset(["db:read"], []) is True


# ─────────────────────────────────────────────────────────────────────────────
# Issue
# ─────────────────────────────────────────────────────────────────────────────

class TestIssue:
    def test_root_requires_human_delegator(self, dr):
        with pytest.raises(dr.DelegationError, match="root_delegator_must_be_human"):
            dr.issue_receipt(TENANT, "agt-rogue", "agt-victim", ["*"], 60)

    def test_root_receipt_has_depth_zero_and_self_principal(self, dr):
        r = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:*"], 3600)
        assert r.depth == 0
        assert r.human_principal_id == HUMAN
        assert r.parent_receipt_id is None

    def test_child_inherits_human_principal(self, dr):
        r1 = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:*"], 3600)
        r2 = dr.issue_receipt(TENANT, "agt-A", "agt-B", ["db:read"], 3600,
                              parent_receipt_id=r1.receipt_id)
        assert r2.human_principal_id == HUMAN
        assert r2.depth == 1

    def test_child_must_match_parent_delegatee(self, dr):
        r1 = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:*"], 3600)
        # agt-Z was never granted authority — it cannot delegate.
        with pytest.raises(dr.DelegationError, match="delegator_not_parent_delegatee"):
            dr.issue_receipt(TENANT, "agt-Z", "agt-B", ["db:read"], 3600,
                             parent_receipt_id=r1.receipt_id)

    def test_unknown_parent(self, dr):
        with pytest.raises(dr.DelegationError, match="parent_not_found"):
            dr.issue_receipt(TENANT, "agt-A", "agt-B", ["db:read"], 3600,
                             parent_receipt_id="rcpt:does-not-exist")

    def test_parent_cross_tenant_blocked(self, dr):
        r1 = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:*"], 3600)
        with pytest.raises(dr.DelegationError, match="parent_cross_tenant"):
            dr.issue_receipt("other-tenant", "agt-A", "agt-B", ["db:read"], 3600,
                             parent_receipt_id=r1.receipt_id)

    def test_child_cannot_outlive_parent(self, dr):
        # Parent expires in 60s, child asks for 3600s → clamped down.
        r1 = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:*"], 60)
        r2 = dr.issue_receipt(TENANT, "agt-A", "agt-B", ["db:read"], 3600,
                              parent_receipt_id=r1.receipt_id)
        # r2.expires_at must be ≤ r1.expires_at
        assert dr._parse_iso(r2.expires_at) <= dr._parse_iso(r1.expires_at)

    def test_invalid_scope_type(self, dr):
        with pytest.raises(dr.DelegationError, match="scope_must_be_list"):
            dr.issue_receipt(TENANT, HUMAN, "agt-A", "db:*", 3600)  # type: ignore[arg-type]

    def test_invalid_expiry(self, dr):
        with pytest.raises(dr.DelegationError, match="expires_in_seconds_must_be_positive"):
            dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:read"], 0)


# ─────────────────────────────────────────────────────────────────────────────
# Privilege escalation prevention — the gate's third clause
# ─────────────────────────────────────────────────────────────────────────────

class TestScopeEscalation:
    def test_b_cannot_issue_wider_than_its_own(self, dr):
        r1 = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:*"], 3600)
        r2 = dr.issue_receipt(TENANT, "agt-A", "agt-B", ["db:read"], 3600,
                              parent_receipt_id=r1.receipt_id)
        # B was only given db:read — it cannot pass db:write to C.
        with pytest.raises(dr.DelegationError, match="scope_exceeds_parent"):
            dr.issue_receipt(TENANT, "agt-B", "agt-C", ["db:write"], 3600,
                             parent_receipt_id=r2.receipt_id)

    def test_b_cannot_issue_wildcard(self, dr):
        r1 = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:read"], 3600)
        r2 = dr.issue_receipt(TENANT, "agt-A", "agt-B", ["db:read"], 3600,
                              parent_receipt_id=r1.receipt_id)
        with pytest.raises(dr.DelegationError, match="scope_exceeds_parent"):
            dr.issue_receipt(TENANT, "agt-B", "agt-C", ["*"], 3600,
                             parent_receipt_id=r2.receipt_id)

    def test_b_can_issue_equal_or_narrower(self, dr):
        r1 = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:*"], 3600)
        r2 = dr.issue_receipt(TENANT, "agt-A", "agt-B", ["db:read", "db:write"],
                              3600, parent_receipt_id=r1.receipt_id)
        # Equal:
        r3a = dr.issue_receipt(TENANT, "agt-B", "agt-C", ["db:read", "db:write"],
                               3600, parent_receipt_id=r2.receipt_id)
        # Narrower:
        r3b = dr.issue_receipt(TENANT, "agt-B", "agt-D", ["db:read"], 3600,
                               parent_receipt_id=r2.receipt_id)
        assert r3a.depth == 2
        assert r3b.depth == 2


# ─────────────────────────────────────────────────────────────────────────────
# Verification + tampering
# ─────────────────────────────────────────────────────────────────────────────

class TestVerify:
    def test_fresh_receipt_verifies(self, dr):
        r = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:*"], 3600)
        v = dr.verify_receipt(r.receipt_id)
        assert v.valid is True
        assert v.reason == "ok"

    def test_unknown_receipt(self, dr):
        v = dr.verify_receipt("rcpt:nonexistent")
        assert v.valid is False
        assert v.reason == "not_found"

    def test_signature_tamper_detected(self, dr, tmp_db):
        r = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:read"], 3600)
        # Mutate the stored scope so the signature no longer matches.
        import sqlite3
        conn = sqlite3.connect(tmp_db)
        conn.execute(
            "UPDATE delegation_receipts SET scope_json=? WHERE receipt_id=?",
            ('["*"]', r.receipt_id),
        )
        conn.commit()
        conn.close()
        v = dr.verify_receipt(r.receipt_id)
        assert v.valid is False
        assert v.reason == "signature_invalid"

    def test_expired_receipt_fails(self, dr, tmp_db):
        r = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:read"], 3600)
        # Backdate expires_at to an hour ago and re-sign so the only failure
        # path the test exercises is expiry, not tampering.
        import sqlite3
        from datetime import datetime, timezone
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        new_sig = dr._sign(dr._signing_payload(
            receipt_id=r.receipt_id,
            tenant_id=r.tenant_id,
            delegator_id=r.delegator_id,
            delegatee_id=r.delegatee_id,
            scope=r.scope,
            issued_at=r.issued_at,
            expires_at=past,
            parent_receipt_id=r.parent_receipt_id,
        ))
        conn = sqlite3.connect(tmp_db)
        conn.execute(
            "UPDATE delegation_receipts SET expires_at=?, signature=? WHERE receipt_id=?",
            (past, new_sig, r.receipt_id),
        )
        conn.commit()
        conn.close()
        v = dr.verify_receipt(r.receipt_id)
        assert v.valid is False
        assert v.reason == "expired"

    def test_cross_tenant_lookup_blocked(self, dr):
        r = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:read"], 3600)
        v = dr.verify_receipt(r.receipt_id, tenant_id="other-tenant")
        assert v.valid is False
        assert v.reason == "cross_tenant"


# ─────────────────────────────────────────────────────────────────────────────
# Chain traversal — the gate's first clause
# ─────────────────────────────────────────────────────────────────────────────

class TestChain:
    def test_three_hop_returns_root_to_leaf(self, dr):
        r1, r2, r3 = _three_hop_chain(dr)
        chain = dr.get_chain(r3.receipt_id)
        assert [c.receipt_id for c in chain] == [r1.receipt_id, r2.receipt_id, r3.receipt_id]
        assert [c.depth for c in chain] == [0, 1, 2]

    def test_each_hop_verifies(self, dr):
        r1, r2, r3 = _three_hop_chain(dr)
        for r in (r1, r2, r3):
            v = dr.verify_receipt(r.receipt_id)
            assert v.valid is True, f"{r.receipt_id} failed verification: {v.reason}"

    def test_chain_for_unknown_receipt_is_empty(self, dr):
        assert dr.get_chain("rcpt:bogus") == []

    def test_chain_cross_tenant_isolated(self, dr):
        r1, r2, r3 = _three_hop_chain(dr)
        assert dr.get_chain(r3.receipt_id, tenant_id="other-tenant") == []


# ─────────────────────────────────────────────────────────────────────────────
# Cascade revocation — the gate's second clause
# ─────────────────────────────────────────────────────────────────────────────

class TestCascadeRevoke:
    def test_cascade_revokes_all_descendants(self, dr):
        r1, r2, r3 = _three_hop_chain(dr)
        out = dr.revoke_receipt(r1.receipt_id, "admin", cascade=True)
        assert set(out["revoked_ids"]) == {r1.receipt_id, r2.receipt_id, r3.receipt_id}
        assert dr.verify_receipt(r1.receipt_id).reason == "revoked"
        assert dr.verify_receipt(r2.receipt_id).reason == "revoked"
        assert dr.verify_receipt(r3.receipt_id).reason == "revoked"

    def test_no_cascade_only_revokes_target(self, dr):
        r1, r2, r3 = _three_hop_chain(dr)
        dr.revoke_receipt(r2.receipt_id, "admin", cascade=False)
        # r2 revoked, r3 still verifies signature/expiry but its parent is
        # revoked — verify_receipt only checks the single receipt, so r3
        # still reads as ok. The chain report is what surfaces the parent
        # revocation (overall_valid=False).
        assert dr.verify_receipt(r1.receipt_id).valid is True
        assert dr.verify_receipt(r2.receipt_id).reason == "revoked"
        assert dr.verify_receipt(r3.receipt_id).valid is True

    def test_cascade_idempotent(self, dr):
        r1, _, _ = _three_hop_chain(dr)
        first = dr.revoke_receipt(r1.receipt_id, "admin", cascade=True)
        again = dr.revoke_receipt(r1.receipt_id, "admin", cascade=True)
        assert len(first["revoked_ids"]) == 3
        assert again["revoked_ids"] == []  # nothing new to revoke

    def test_cascade_does_not_revoke_siblings(self, dr):
        # human → A grants B and C separately
        r1 = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:*"], 3600)
        r2 = dr.issue_receipt(TENANT, "agt-A", "agt-B", ["db:read"], 3600,
                              parent_receipt_id=r1.receipt_id)
        r_sibling = dr.issue_receipt(TENANT, HUMAN, "agt-X", ["queue:*"], 3600)
        dr.revoke_receipt(r1.receipt_id, "admin", cascade=True)
        assert dr.verify_receipt(r1.receipt_id).reason == "revoked"
        assert dr.verify_receipt(r2.receipt_id).reason == "revoked"
        assert dr.verify_receipt(r_sibling.receipt_id).valid is True

    def test_revoke_unknown(self, dr):
        with pytest.raises(dr.DelegationError, match="not_found"):
            dr.revoke_receipt("rcpt:bogus", "admin")


# ─────────────────────────────────────────────────────────────────────────────
# Receipts-for-agent
# ─────────────────────────────────────────────────────────────────────────────

class TestReceiptsForAgent:
    def test_active_only_by_default(self, dr):
        r1 = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:read"], 3600)
        r2 = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["queue:write"], 3600)
        dr.revoke_receipt(r2.receipt_id, "admin", cascade=False)
        active = dr.get_receipts_for_agent(TENANT, "agt-A")
        ids = {r.receipt_id for r in active}
        assert ids == {r1.receipt_id}

    def test_include_revoked(self, dr):
        r1 = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:read"], 3600)
        dr.revoke_receipt(r1.receipt_id, "admin", cascade=False)
        all_ = dr.get_receipts_for_agent(TENANT, "agt-A", include_revoked=True)
        assert len(all_) == 1

    def test_tenant_isolation(self, dr):
        dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:read"], 3600)
        assert dr.get_receipts_for_agent("other-tenant", "agt-A") == []


# ─────────────────────────────────────────────────────────────────────────────
# Chain report (PDF-export shape)
# ─────────────────────────────────────────────────────────────────────────────

class TestChainReport:
    def test_report_per_hop_verification(self, dr):
        _, _, r3 = _three_hop_chain(dr)
        report = dr.export_chain_report(r3.receipt_id)
        assert report["found"] is True
        assert report["overall_valid"] is True
        assert report["depth"] == 2
        assert report["human_principal_id"] == HUMAN
        assert len(report["hops"]) == 3
        assert all(h["signature_valid"] for h in report["hops"])
        assert [h["depth"] for h in report["hops"]] == [0, 1, 2]

    def test_report_flags_revoked_hop(self, dr):
        r1, r2, r3 = _three_hop_chain(dr)
        dr.revoke_receipt(r2.receipt_id, "admin", cascade=False)
        report = dr.export_chain_report(r3.receipt_id)
        assert report["overall_valid"] is False
        assert "revoked" in report["overall_reason"]
        # Hop 1 (depth=1) should be flagged.
        revoked_hop = [h for h in report["hops"] if h["revoked"]]
        assert len(revoked_hop) == 1
        assert revoked_hop[0]["depth"] == 1

    def test_report_unknown_receipt(self, dr):
        report = dr.export_chain_report("rcpt:bogus")
        assert report["found"] is False
        assert report["overall_valid"] is False


# ─────────────────────────────────────────────────────────────────────────────
# Route-level integration
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def app_client(tmp_db):
    import importlib
    import modules.identity.delegation_receipt as drm
    importlib.reload(drm)
    drm.init_db()

    import api as app_module
    from fastapi.testclient import TestClient
    from modules.tenants.middleware import get_tenant
    from modules.tenants.models import Plan, TenantContext

    tenant = TenantContext(
        tenant_id="t-routes",
        tenant_name="Routes",
        plan=Plan.ENTERPRISE,
        api_key_id="k",
        role="owner",
    )
    # Override every known binding of get_tenant so the override matches even
    # after a prior test reloaded modules.tenants.middleware.
    import modules.product.commercial_tiers as _ct
    def _override():
        return tenant
    app_module.app.dependency_overrides[get_tenant] = _override
    app_module.app.dependency_overrides[_ct.get_tenant] = _override
    client = TestClient(app_module.app, raise_server_exceptions=False)
    yield client, drm
    app_module.app.dependency_overrides.clear()


class TestRoutes:
    def test_issue_get_verify_chain_revoke_report_flow(self, app_client):
        client, drm = app_client
        # Issue root.
        root = client.post("/api/delegation/receipt", json={
            "delegator_id": HUMAN,
            "delegatee_id": "agt-A",
            "scope": ["db:*"],
            "expires_in_seconds": 3600,
        })
        assert root.status_code == 200, root.text
        root_id = root.json()["receipt_id"]

        # Issue child.
        child = client.post("/api/delegation/receipt", json={
            "delegator_id": "agt-A",
            "delegatee_id": "agt-B",
            "scope": ["db:read"],
            "expires_in_seconds": 600,
            "parent_receipt_id": root_id,
        })
        assert child.status_code == 200, child.text
        child_id = child.json()["receipt_id"]

        # Get
        got = client.get(f"/api/delegation/receipt/{child_id}")
        assert got.status_code == 200
        assert got.json()["delegator_id"] == "agt-A"

        # Verify
        v = client.get(f"/api/delegation/receipt/{child_id}/verify").json()
        assert v["valid"] is True

        # Chain
        chain = client.get(f"/api/delegation/chain/{child_id}").json()
        assert chain["depth"] == 1
        assert len(chain["chain"]) == 2

        # Receipts for B
        rfa = client.get("/api/delegation/receipts/agt-B").json()
        assert rfa["count"] == 1

        # Report
        report = client.get(f"/api/delegation/chain/{child_id}/report").json()
        assert report["overall_valid"] is True

        # Revoke root with cascade
        revoke = client.post(
            f"/api/delegation/receipt/{root_id}/revoke",
            json={"revoked_by": "admin@x.com", "cascade": True},
        )
        assert revoke.status_code == 200, revoke.text
        assert set(revoke.json()["revoked_ids"]) == {root_id, child_id}

        # Verify child now revoked
        v_after = client.get(f"/api/delegation/receipt/{child_id}/verify").json()
        assert v_after["valid"] is False
        assert v_after["reason"] == "revoked"

    def test_scope_escalation_returns_403(self, app_client):
        client, _ = app_client
        root = client.post("/api/delegation/receipt", json={
            "delegator_id": HUMAN,
            "delegatee_id": "agt-A",
            "scope": ["db:read"],
            "expires_in_seconds": 600,
        }).json()
        resp = client.post("/api/delegation/receipt", json={
            "delegator_id": "agt-A",
            "delegatee_id": "agt-B",
            "scope": ["db:write"],         # escalation
            "expires_in_seconds": 600,
            "parent_receipt_id": root["receipt_id"],
        })
        assert resp.status_code == 403
        assert resp.json()["detail"]["error"] == "scope_exceeds_parent"

    def test_unknown_receipt_404(self, app_client):
        client, _ = app_client
        assert client.get("/api/delegation/receipt/rcpt:bogus").status_code == 404
        assert client.get("/api/delegation/chain/rcpt:bogus").status_code == 404
