"""
Tests for modules/product/commercial_tiers.py — commercial-tier entitlement.

Coverage:
  - CommercialTier ordering + plan-to-tier mapping (incl. fallbacks)
  - is_entitled() boolean logic for every gate at every tier boundary
  - Unknown feature key rejection (typos must not grant access)
  - require_feature() raises HTTPException(403) with the structured detail
  - require_feature() returns the resolved TenantContext on success
  - get_feature() / list_features() / forbidden_payload() shape assertions
  - End-to-end: every Phase 5 route returns 403 for a community tenant and
    a non-403 (i.e. allowed by gate) for an enterprise tenant. Core scoring
    and UIS routes stay reachable for community tenants.
"""

from __future__ import annotations

import os
import sys

import pytest
from fastapi import HTTPException

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.product import commercial_tiers as ct
from modules.product.commercial_tiers import (
    COMMERCIAL_FEATURES,
    CommercialTier,
    forbidden_payload,
    get_feature,
    is_entitled,
    list_features,
    require_feature,
    tier_for_plan,
)
from modules.tenants.models import Plan, TenantContext


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

def _ctx(plan: Plan, tenant_id: str = "t-demo") -> TenantContext:
    return TenantContext(
        tenant_id=tenant_id,
        tenant_name=f"{tenant_id}-name",
        plan=plan,
        api_key_id="key-test",
        role="owner",
    )


PHASE5_GATES = [
    "ent.mcp_gateway",
    "ent.agent_discovery",
    "ent.enforcement_plane",
    "ent.behavioral_dna",
    "ent.blast_radius",
    "ent.intent_correlation",
    # Sprint FAT addition
    "ent.federation",
]


# ─────────────────────────────────────────────────────────────────────────────
# Tier ordering + plan mapping
# ─────────────────────────────────────────────────────────────────────────────

class TestTierOrdering:
    def test_all_six_phase5_gates_registered(self):
        assert set(COMMERCIAL_FEATURES) == set(PHASE5_GATES)

    def test_plan_free_maps_to_community(self):
        assert tier_for_plan(Plan.FREE) == CommercialTier.COMMUNITY

    def test_plan_starter_maps_to_community(self):
        assert tier_for_plan(Plan.STARTER) == CommercialTier.COMMUNITY

    def test_plan_pro_maps_to_pro(self):
        assert tier_for_plan(Plan.PRO) == CommercialTier.PRO

    def test_plan_enterprise_maps_to_enterprise(self):
        assert tier_for_plan(Plan.ENTERPRISE) == CommercialTier.ENTERPRISE

    def test_string_plan_accepted(self):
        assert tier_for_plan("pro") == CommercialTier.PRO
        assert tier_for_plan("ENTERPRISE") == CommercialTier.ENTERPRISE

    def test_unknown_plan_falls_back_to_community(self):
        assert tier_for_plan("not-a-real-plan") == CommercialTier.COMMUNITY

    def test_internal_rank_is_strictly_ascending(self):
        ranks = [
            ct._rank(CommercialTier.COMMUNITY),
            ct._rank(CommercialTier.PRO),
            ct._rank(CommercialTier.ENTERPRISE),
        ]
        assert ranks == sorted(ranks) and len(set(ranks)) == 3


# ─────────────────────────────────────────────────────────────────────────────
# is_entitled() — pure boolean logic
# ─────────────────────────────────────────────────────────────────────────────

class TestIsEntitled:
    def test_unknown_feature_returns_false(self):
        # Typos must not grant access.
        assert is_entitled(Plan.ENTERPRISE, "ent.does_not_exist") is False
        assert is_entitled(Plan.ENTERPRISE, "") is False

    def test_community_blocked_from_every_phase5_gate(self):
        for gate in PHASE5_GATES:
            assert is_entitled(Plan.FREE, gate) is False, gate
            assert is_entitled(Plan.STARTER, gate) is False, gate

    def test_enterprise_entitled_to_every_phase5_gate(self):
        for gate in PHASE5_GATES:
            assert is_entitled(Plan.ENTERPRISE, gate) is True, gate

    def test_pro_tier_boundary(self):
        # PRO crosses the pro-tier gates but not the enterprise-tier gates.
        for key, gate in COMMERCIAL_FEATURES.items():
            expected = gate.min_tier in (CommercialTier.COMMUNITY, CommercialTier.PRO)
            assert is_entitled(Plan.PRO, key) is expected, key


# ─────────────────────────────────────────────────────────────────────────────
# get_feature() / list_features() / forbidden_payload()
# ─────────────────────────────────────────────────────────────────────────────

class TestFeatureCatalog:
    def test_get_feature_returns_gate(self):
        gate = get_feature("ent.blast_radius")
        assert gate.key == "ent.blast_radius"
        assert gate.min_tier == CommercialTier.ENTERPRISE
        assert gate.name == "Blast Radius Simulator"

    def test_get_feature_unknown_raises(self):
        with pytest.raises(KeyError):
            get_feature("ent.bogus")

    def test_list_features_no_plan(self):
        rows = list_features()
        assert len(rows) == len(PHASE5_GATES)
        assert all("entitled" not in r for r in rows)

    def test_list_features_with_plan_marks_entitlement(self):
        rows = list_features(Plan.PRO)
        for row in rows:
            assert row["tenant_tier"] == "pro"
            gate = COMMERCIAL_FEATURES[row["key"]]
            expected = gate.min_tier in (CommercialTier.COMMUNITY, CommercialTier.PRO)
            assert row["entitled"] is expected, row

    def test_forbidden_payload_shape(self):
        gate = get_feature("ent.blast_radius")
        payload = forbidden_payload(
            tenant=_ctx(Plan.FREE, "t-1"),
            feature_key="ent.blast_radius",
            gate=gate,
        )
        # Stable shape — the dashboard reads these fields.
        assert payload["error"] == "feature_not_entitled"
        assert payload["feature"] == "ent.blast_radius"
        assert payload["feature_name"] == gate.name
        assert payload["tenant_id"] == "t-1"
        assert payload["tenant_tier"] == "community"
        assert payload["required_tier"] == "enterprise"
        assert "upgrade_url" in payload
        assert "community" in payload["message"]
        assert "enterprise" in payload["message"]


# ─────────────────────────────────────────────────────────────────────────────
# require_feature() — FastAPI dependency factory
# ─────────────────────────────────────────────────────────────────────────────

class TestRequireFeatureDependency:
    def test_unknown_feature_fails_at_factory_time(self):
        # Typos in a route decorator should fail at import, not request time.
        with pytest.raises(KeyError):
            require_feature("ent.totally-fake")

    def test_factory_name_includes_feature_key(self):
        dep = require_feature("ent.blast_radius")
        assert "ent.blast_radius" in dep.__name__

    def test_dependency_returns_tenant_when_entitled(self):
        dep = require_feature("ent.blast_radius")
        ent_tenant = _ctx(Plan.ENTERPRISE, "t-ent")
        # Call the inner function directly with an injected tenant.
        result = dep(tenant=ent_tenant)
        assert result is ent_tenant

    def test_dependency_pro_can_use_pro_gate(self):
        dep = require_feature("ent.behavioral_dna")        # min_tier=pro
        result = dep(tenant=_ctx(Plan.PRO, "t-pro"))
        assert isinstance(result, TenantContext)

    def test_dependency_pro_blocked_from_enterprise_gate(self):
        dep = require_feature("ent.blast_radius")          # min_tier=enterprise
        with pytest.raises(HTTPException) as exc:
            dep(tenant=_ctx(Plan.PRO, "t-pro"))
        assert exc.value.status_code == 403
        detail = exc.value.detail
        assert detail["error"] == "feature_not_entitled"
        assert detail["required_tier"] == "enterprise"
        assert detail["tenant_tier"] == "pro"

    def test_dependency_community_blocked_from_every_gate(self):
        community_tenant = _ctx(Plan.FREE, "t-com")
        for key in PHASE5_GATES:
            dep = require_feature(key)
            with pytest.raises(HTTPException) as exc:
                dep(tenant=community_tenant)
            assert exc.value.status_code == 403
            assert exc.value.detail["feature"] == key
            assert exc.value.detail["tenant_tier"] == "community"


# ─────────────────────────────────────────────────────────────────────────────
# End-to-end: Phase 5 routes through TestClient with dependency_overrides
# ─────────────────────────────────────────────────────────────────────────────

# Representative endpoint per gate. Mix of:
#   (a) routes added by the salvage commit (threat-sharing, delegation),
#   (b) the existing Phase 5 routes that PR-B wires with require_feature.
# Status codes other than 403 mean the gate is open — body errors (400/422)
# are fine, the gate did its job.
PHASE5_ROUTES: list[tuple[str, str, dict | None]] = [
    # Threat-sharing — ent.intent_correlation
    ("POST", "/api/threat-sharing/opt-in",              None),
    ("POST", "/api/threat-sharing/opt-out",             None),
    ("GET",  "/api/threat-sharing/status",              None),
    ("POST", "/api/threat-sharing/publish/custom:abc",  None),
    ("POST", "/api/threat-sharing/sync",                None),
    ("GET",  "/api/threat-sharing/network",             None),
    # Delegation — ent.enforcement_plane
    ("POST", "/api/delegation/receipt",                 {"delegator_id": "human:a", "delegatee_id": "agt-x", "scope": ["*"], "expires_in_seconds": 60}),
    ("GET",  "/api/delegation/receipt/rcpt:none",       None),
    ("GET",  "/api/delegation/receipt/rcpt:none/verify", None),
    ("GET",  "/api/delegation/chain/rcpt:none",         None),
    ("GET",  "/api/delegation/receipts/agt-x",          None),
    ("POST", "/api/delegation/receipt/rcpt:none/revoke", {"revoked_by": "x"}),
    ("GET",  "/api/delegation/chain/rcpt:none/report",  None),
    # Existing Phase 5 routes now gated by PR-B:
    # MCP gateway — ent.mcp_gateway
    ("POST", "/api/mcp/verify",                         {"manifest": {}, "expected_manifest_hash": "x"}),
    ("POST", "/api/mcp/inspect",                        {}),
    # Blast radius — ent.blast_radius
    ("POST", "/api/simulate/blast_radius",              {"agent_label": "agt-x"}),
    # Intent correlation — ent.intent_correlation
    ("GET",  "/api/intent/matches",                     None),
    # Policy guard — ent.enforcement_plane
    ("GET",  "/api/policy/guard/violations",            None),
    # Drift / behavioral DNA — ent.behavioral_dna
    ("GET",  "/api/drift/alerts",                       None),
    ("GET",  "/api/behavioral/alerts",                  None),
    # Cert dashboard — ent.enforcement_plane
    ("GET",  "/api/certs/fleet",                        None),
    # Discovery — ent.agent_discovery
    ("GET",  "/api/discovery/agents",                   None),
    # Enforcement plane — ent.enforcement_plane
    ("GET",  "/api/enforcement/policies",               None),
    # Policy advisor — ent.enforcement_plane
    ("GET",  "/api/policy/suggestions",                 None),
]

# Core (ungated) routes that must remain accessible for community tenants.
CORE_ROUTES: list[tuple[str, str]] = [
    ("GET", "/api/uis/spec"),
    ("GET", "/api/health"),
    ("GET", "/api/stats"),
]


def _client_with_tenant(plan: Plan):
    """
    TestClient that pins every request to a synthetic tenant on ``plan``.
    Routes built with ``require_feature(...)`` depend on ``get_tenant`` which
    we override here. Routes wrapped in ``require_role`` use a parallel
    helper, so override it as well.
    """
    from fastapi.testclient import TestClient

    import api as app_module
    from modules.security.rbac import Role, require_role
    from modules.tenants.middleware import get_tenant

    tenant = _ctx(plan, f"t-{plan.value}")

    def _get_tenant_override():
        return tenant

    # Build any factory-produced require_role(...) dependencies and swap them
    # too, so 401/403 from RBAC don't mask a missing tier check.
    role_dep = require_role(Role.ANALYST)

    app_module.app.dependency_overrides[get_tenant] = _get_tenant_override
    app_module.app.dependency_overrides[role_dep] = _get_tenant_override
    # Cover commercial_tiers' own captured get_tenant binding so module
    # reloads in other test fixtures cannot orphan our override.
    import modules.product.commercial_tiers as _ct
    app_module.app.dependency_overrides[_ct.get_tenant] = _get_tenant_override

    return TestClient(app_module.app, raise_server_exceptions=False), app_module


@pytest.fixture()
def community_client():
    client, app_module = _client_with_tenant(Plan.FREE)
    yield client
    app_module.app.dependency_overrides.clear()


@pytest.fixture()
def enterprise_client():
    client, app_module = _client_with_tenant(Plan.ENTERPRISE)
    yield client
    app_module.app.dependency_overrides.clear()


def _request(client, method: str, path: str, body: dict | None):
    if method == "GET":
        return client.get(path)
    if method == "DELETE":
        return client.delete(path)
    return client.request(method, path, json=body or {})


class TestPhase5RoutesGated:
    """Every Phase 5 route MUST 403 for a community tenant."""

    @pytest.mark.parametrize("method,path,body", PHASE5_ROUTES)
    def test_community_tenant_blocked(self, community_client, method, path, body):
        resp = _request(community_client, method, path, body)
        assert resp.status_code == 403, (
            f"{method} {path} returned {resp.status_code}, expected 403 "
            f"for community tenant. Body: {resp.text[:200]}"
        )
        detail = resp.json().get("detail")
        # FastAPI wraps the dict detail under "detail".
        assert isinstance(detail, dict), detail
        assert detail["error"] == "feature_not_entitled"
        assert detail["tenant_tier"] == "community"
        assert detail["feature"].startswith("ent.")


class TestPhase5RoutesEntitled:
    """Enterprise tenants get past the gate (any non-403 status is acceptable)."""

    @pytest.mark.parametrize("method,path,body", PHASE5_ROUTES)
    def test_enterprise_tenant_passes_gate(self, enterprise_client, method, path, body):
        resp = _request(enterprise_client, method, path, body)
        # 403 here would only ever come from the gate (RBAC is overridden).
        if resp.status_code == 403:
            detail = resp.json().get("detail")
            # Whitelist: route may legitimately 403 for non-tier reasons,
            # but never with our structured payload.
            assert not (isinstance(detail, dict) and detail.get("error") == "feature_not_entitled"), (
                f"{method} {path} returned a tier-403 for an enterprise tenant: {detail}"
            )


class TestCoreRoutesUngated:
    """Core scoring / health / UIS routes stay reachable for community tenants."""

    @pytest.mark.parametrize("method,path", CORE_ROUTES)
    def test_community_tenant_can_reach_core(self, community_client, method, path):
        resp = _request(community_client, method, path, None)
        # The gate must not engage; any non-403 (or a 403 whose detail is NOT
        # our structured payload) is acceptable.
        if resp.status_code == 403:
            detail = resp.json().get("detail")
            assert not (isinstance(detail, dict) and detail.get("error") == "feature_not_entitled"), (
                f"{method} {path} unexpectedly tier-gated for a community tenant"
            )


# ─────────────────────────────────────────────────────────────────────────────
# /api/product/entitlements — feeds the dashboard upsell modal
# ─────────────────────────────────────────────────────────────────────────────

class TestEntitlementsRoute:
    def test_community_tenant_sees_full_matrix(self, community_client):
        resp = community_client.get("/api/product/entitlements")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["tenant_tier"] == "community"
        assert body["upgrade_url"] == "/billing/upgrade"
        keys = {row["key"] for row in body["features"]}
        assert keys == set(PHASE5_GATES)
        # Every Phase 5 gate is locked for community.
        assert all(row["entitled"] is False for row in body["features"])

    def test_pro_tenant_partial_entitlement(self):
        # Build a fresh client at the pro tier — fixture would conflict.
        client, app_module = _client_with_tenant(Plan.PRO)
        try:
            resp = client.get("/api/product/entitlements")
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["tenant_tier"] == "pro"
            entitled = {row["key"] for row in body["features"] if row["entitled"]}
            assert entitled == {"ent.behavioral_dna", "ent.agent_discovery"}
        finally:
            app_module.app.dependency_overrides.clear()

    def test_enterprise_tenant_fully_entitled(self, enterprise_client):
        resp = enterprise_client.get("/api/product/entitlements")
        assert resp.status_code == 200
        body = resp.json()
        assert body["tenant_tier"] == "enterprise"
        assert all(row["entitled"] for row in body["features"])

    def test_route_itself_is_not_tier_gated(self, community_client):
        # Community must reach the route — otherwise the upsell modal can't
        # render the feature matrix at all.
        resp = community_client.get("/api/product/entitlements")
        assert resp.status_code != 403
