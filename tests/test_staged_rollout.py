"""
Tests for modules/product/staged_rollout.py — per-tenant feature allowlists.

Coverage:
  - is_allowlisted false by default; true after grant; false after revoke.
  - grant_access enforces unknown_feature_key (typo guard) and
    already_active (no double-grants).
  - revoke_access is idempotent (returns {revoked: False} for missing grant).
  - History retained — list_grants(include_revoked=True) shows revoked entries.
  - require_feature integration: a community tenant with an allowlist
    grant passes the gate; without the grant it 403s as before.
  - require_feature degrades safely if staged_rollout is unavailable
    (the override is best-effort, never overrides denial).
"""

from __future__ import annotations

import os
import sys

import pytest
from fastapi import HTTPException

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture()
def tmp_db(tmp_path, monkeypatch):
    db = str(tmp_path / "sr.db")
    monkeypatch.setenv("DATA_DB_PATH", db)
    yield db


@pytest.fixture()
def sr(tmp_db):
    """Fresh staged_rollout against an isolated DB.

    Note: we deliberately do NOT reload commercial_tiers here. Reloading ct
    orphans api.py's already-captured get_tenant reference, which breaks
    dependency_overrides matching for any test that runs later in the
    same process and exercises a require_feature-gated route.
    """
    import importlib
    import modules.product.staged_rollout as m
    importlib.reload(m)
    m.init_db()
    return m


def _ctx(plan, tenant_id="t-test"):
    from modules.tenants.models import TenantContext
    return TenantContext(
        tenant_id=tenant_id, tenant_name=tenant_id,
        plan=plan, api_key_id="k", role="owner",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Module-level
# ─────────────────────────────────────────────────────────────────────────────

class TestAllowlistLifecycle:
    def test_default_not_allowlisted(self, sr):
        assert sr.is_allowlisted("t-1", "ent.blast_radius") is False

    def test_grant_then_check(self, sr):
        out = sr.grant_access("t-1", "ent.blast_radius",
                              granted_by="ops@x", reason="design partner")
        assert out.is_active() is True
        assert sr.is_allowlisted("t-1", "ent.blast_radius") is True

    def test_grant_unknown_feature_rejected(self, sr):
        with pytest.raises(sr.AllowlistError, match="unknown_feature_key"):
            sr.grant_access("t-1", "ent.totally-fake", "ops@x")

    def test_grant_already_active(self, sr):
        sr.grant_access("t-1", "ent.blast_radius", "ops@x")
        with pytest.raises(sr.AllowlistError, match="already_active"):
            sr.grant_access("t-1", "ent.blast_radius", "ops@x")

    def test_revoke_round_trip(self, sr):
        sr.grant_access("t-1", "ent.blast_radius", "ops@x")
        out = sr.revoke_access("t-1", "ent.blast_radius",
                               revoked_by="ops@x", reason="EOL")
        assert out["revoked"] is True
        assert sr.is_allowlisted("t-1", "ent.blast_radius") is False

    def test_revoke_idempotent(self, sr):
        out = sr.revoke_access("t-1", "ent.blast_radius", "ops@x")
        assert out["revoked"] is False

    def test_grant_again_after_revoke(self, sr):
        sr.grant_access("t-1", "ent.blast_radius", "ops@x")
        sr.revoke_access("t-1", "ent.blast_radius", "ops@x")
        # Re-granting should work (the partial-unique index only enforces
        # one *active* grant per tenant/feature).
        sr.grant_access("t-1", "ent.blast_radius", "ops@x", reason="re-extended")
        assert sr.is_allowlisted("t-1", "ent.blast_radius") is True

    def test_list_grants_include_revoked(self, sr):
        sr.grant_access("t-1", "ent.blast_radius", "ops@x")
        sr.revoke_access("t-1", "ent.blast_radius", "ops@x")
        sr.grant_access("t-1", "ent.behavioral_dna", "ops@x")
        active_only = sr.list_grants("t-1")
        with_history = sr.list_grants("t-1", include_revoked=True)
        assert len(active_only) == 1
        assert len(with_history) == 2

    def test_list_active_for_feature(self, sr):
        sr.grant_access("t-a", "ent.blast_radius", "ops")
        sr.grant_access("t-b", "ent.blast_radius", "ops")
        sr.grant_access("t-c", "ent.behavioral_dna", "ops")
        for_blast = sr.list_active_grants_for_feature("ent.blast_radius")
        assert {g.tenant_id for g in for_blast} == {"t-a", "t-b"}


# ─────────────────────────────────────────────────────────────────────────────
# require_feature integration
# ─────────────────────────────────────────────────────────────────────────────

class TestRequireFeatureIntegration:
    def test_community_blocked_without_grant(self, sr):
        from modules.tenants.models import Plan
        from modules.product.commercial_tiers import require_feature
        dep = require_feature("ent.blast_radius")
        with pytest.raises(HTTPException) as exc:
            dep(tenant=_ctx(Plan.FREE, "t-com"))
        assert exc.value.status_code == 403

    def test_community_passes_with_grant(self, sr):
        from modules.tenants.models import Plan
        from modules.product.commercial_tiers import require_feature
        sr.grant_access("t-com", "ent.blast_radius",
                        granted_by="ops@x", reason="design partner Q2")
        dep = require_feature("ent.blast_radius")
        result = dep(tenant=_ctx(Plan.FREE, "t-com"))
        assert result.tenant_id == "t-com"

    def test_grant_for_other_tenant_doesnt_help(self, sr):
        from modules.tenants.models import Plan
        from modules.product.commercial_tiers import require_feature
        sr.grant_access("t-other", "ent.blast_radius", "ops@x")
        dep = require_feature("ent.blast_radius")
        with pytest.raises(HTTPException) as exc:
            dep(tenant=_ctx(Plan.FREE, "t-com"))
        assert exc.value.status_code == 403

    def test_revoked_grant_no_longer_passes(self, sr):
        from modules.tenants.models import Plan
        from modules.product.commercial_tiers import require_feature
        sr.grant_access("t-com", "ent.blast_radius", "ops@x")
        sr.revoke_access("t-com", "ent.blast_radius", "ops@x")
        dep = require_feature("ent.blast_radius")
        with pytest.raises(HTTPException) as exc:
            dep(tenant=_ctx(Plan.FREE, "t-com"))
        assert exc.value.status_code == 403

    def test_enterprise_unaffected_by_allowlist(self, sr):
        """Tier-entitled tenants don't even consult the allowlist."""
        from modules.tenants.models import Plan
        from modules.product.commercial_tiers import require_feature
        dep = require_feature("ent.blast_radius")
        # No grant for this tenant — entitled by tier alone.
        result = dep(tenant=_ctx(Plan.ENTERPRISE, "t-ent"))
        assert result.tenant_id == "t-ent"

    def test_allowlist_module_failure_falls_through_to_403(self, sr, monkeypatch):
        """If staged_rollout itself blows up, require_feature must still
        produce the original 403 — fail-closed for the override."""
        from modules.tenants.models import Plan
        from modules.product.commercial_tiers import require_feature
        monkeypatch.setattr(sr, "is_allowlisted",
                            lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
        dep = require_feature("ent.blast_radius")
        with pytest.raises(HTTPException) as exc:
            dep(tenant=_ctx(Plan.FREE, "t-com"))
        assert exc.value.status_code == 403


# ─────────────────────────────────────────────────────────────────────────────
# Routes (admin)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def app_client(tmp_db, sr):
    import api as app_module
    from fastapi.testclient import TestClient
    from modules.tenants.middleware import get_tenant
    from modules.tenants.models import Plan, TenantContext
    from modules.security.rbac import Role, require_role

    admin = TenantContext(
        tenant_id="admin-t", tenant_name="Admin",
        plan=Plan.ENTERPRISE, api_key_id="k", role="owner",
    )

    def _override():
        return admin

    import modules.product.commercial_tiers as _ct
    import modules.security.rbac as _rbac
    app_module.app.dependency_overrides[get_tenant] = _override
    app_module.app.dependency_overrides[_ct.get_tenant] = _override
    # require_role(Role.OWNER) creates a fresh closure each call, so
    # overriding the closure object doesn't help. Override the shared
    # inner dependency that every closure depends on instead.
    app_module.app.dependency_overrides[_rbac._get_tenant_ctx] = _override
    yield TestClient(app_module.app, raise_server_exceptions=False), sr
    app_module.app.dependency_overrides.clear()


class TestRoutes:
    def test_grant_revoke_list_flow(self, app_client):
        client, _ = app_client
        # Grant
        ok = client.post("/api/admin/staged-rollout/grant", json={
            "tenant_id": "t-design",
            "feature_key": "ent.blast_radius",
            "granted_by": "founder@acme",
            "reason": "Q2 design partner",
        })
        assert ok.status_code == 200, ok.text
        # List
        listing = client.get("/api/admin/staged-rollout/t-design").json()
        assert listing["count"] == 1
        # Revoke
        rev = client.post("/api/admin/staged-rollout/revoke", json={
            "tenant_id": "t-design",
            "feature_key": "ent.blast_radius",
            "revoked_by": "founder@acme",
        })
        assert rev.status_code == 200
        # No more active grants.
        post_list = client.get("/api/admin/staged-rollout/t-design").json()
        assert post_list["count"] == 0

    def test_unknown_feature_404(self, app_client):
        client, _ = app_client
        resp = client.post("/api/admin/staged-rollout/grant", json={
            "tenant_id": "t", "feature_key": "ent.bogus",
            "granted_by": "ops",
        })
        assert resp.status_code == 404

    def test_double_grant_409(self, app_client):
        client, _ = app_client
        body = {"tenant_id": "t-x", "feature_key": "ent.blast_radius", "granted_by": "ops"}
        client.post("/api/admin/staged-rollout/grant", json=body)
        resp = client.post("/api/admin/staged-rollout/grant", json=body)
        assert resp.status_code == 409

    def test_revoke_unknown_404(self, app_client):
        client, _ = app_client
        resp = client.post("/api/admin/staged-rollout/revoke", json={
            "tenant_id": "t-no-grant", "feature_key": "ent.blast_radius",
            "revoked_by": "ops",
        })
        assert resp.status_code == 404

    def test_list_for_feature(self, app_client):
        client, _ = app_client
        for t in ("t-a", "t-b"):
            client.post("/api/admin/staged-rollout/grant", json={
                "tenant_id": t, "feature_key": "ent.behavioral_dna",
                "granted_by": "ops",
            })
        out = client.get("/api/admin/staged-rollout/feature/ent.behavioral_dna").json()
        assert out["count"] == 2
        assert {g["tenant_id"] for g in out["grants"]} == {"t-a", "t-b"}
