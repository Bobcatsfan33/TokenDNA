from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from fastapi import Depends, FastAPI
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient


def test_dev_mode_synthetic_tenant_role_is_explicit(monkeypatch):
    from modules.tenants import middleware

    monkeypatch.setattr(middleware, "DEV_MODE", True)
    monkeypatch.setattr(middleware, "_DEV_TENANT", replace(middleware._DEV_TENANT, role="owner"))

    ctx = asyncio.run(middleware.get_tenant(SimpleNamespace(), api_key=None, bearer=None))

    assert ctx.role == "owner"


def test_api_key_role_is_persisted_and_enforced(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "tenant-rbac.db"))

    from modules.security import rbac
    from modules.security.rbac import Role, require_role
    from modules.tenants import middleware, store

    monkeypatch.setattr(middleware, "DEV_MODE", False)
    monkeypatch.setattr(rbac, "_emit_audit", lambda *a, **kw: None)

    store.init_db()
    tenant, owner_key = store.create_tenant("Acme", plan=store.Plan.ENTERPRISE)
    analyst_record, analyst_key = store.create_api_key(
        tenant_id=tenant.id,
        name="soc",
        role="analyst",
    )

    assert analyst_record.role == "analyst"
    resolved_key, _resolved_tenant = store.lookup_by_key(analyst_key)
    assert resolved_key.role == "analyst"

    app = FastAPI()

    @app.get("/analyst")
    async def analyst_route(ctx=Depends(require_role(Role.ANALYST))):
        return {"role": ctx.role}

    @app.get("/owner")
    async def owner_route(ctx=Depends(require_role(Role.OWNER))):
        return {"role": ctx.role}

    client = TestClient(app)
    assert client.get("/analyst", headers={"X-API-Key": analyst_key}).json() == {"role": "analyst"}
    assert client.get("/owner", headers={"X-API-Key": analyst_key}).status_code == 403
    assert client.get("/owner", headers={"X-API-Key": owner_key}).json() == {"role": "owner"}


def test_tenant_context_defaults_to_readonly():
    from modules.tenants.models import Plan, TenantContext

    ctx = TenantContext(
        tenant_id="tenant-1",
        tenant_name="Acme",
        plan=Plan.ENTERPRISE,
        api_key_id="key-1",
    )

    assert ctx.role == "readonly"


def test_bearer_tenant_resolution_uses_verified_jwt(monkeypatch):
    import auth
    from modules.tenants import middleware
    from modules.tenants.models import Plan, Tenant

    monkeypatch.setattr(middleware, "DEV_MODE", False)
    seen: dict[str, str] = {}

    def fake_verify(token: str) -> dict:
        seen["token"] = token
        return {"org_id": "tenant-jwt", "roles": ["tokendna:admin"]}

    monkeypatch.setattr(auth, "_verify_jwt", fake_verify)
    monkeypatch.setattr(
        middleware.store,
        "get_tenant",
        lambda tenant_id: Tenant(
            id=tenant_id,
            name="JWT Tenant",
            plan=Plan.ENTERPRISE,
            is_active=True,
            created_at=__import__("datetime").datetime.utcnow(),
        ),
    )

    ctx = asyncio.run(
        middleware.get_tenant(
            SimpleNamespace(),
            api_key=None,
            bearer=HTTPAuthorizationCredentials(scheme="Bearer", credentials="signed.jwt"),
        )
    )

    assert seen["token"] == "signed.jwt"
    assert ctx.tenant_id == "tenant-jwt"
    assert ctx.role == "admin"


def test_bearer_tenant_resolution_requires_org_claim_in_production(monkeypatch):
    import auth
    from fastapi import HTTPException
    from modules.tenants import middleware

    monkeypatch.setattr(middleware, "DEV_MODE", False)
    monkeypatch.setenv("TOKENDNA_ENV", "production")
    monkeypatch.delenv("TOKENDNA_OIDC_ALLOW_SUB_TENANT_FALLBACK", raising=False)
    monkeypatch.setattr(auth, "_verify_jwt", lambda _token: {"sub": "user-only"})

    try:
        asyncio.run(
            middleware.get_tenant(
                SimpleNamespace(),
                api_key=None,
                bearer=HTTPAuthorizationCredentials(scheme="Bearer", credentials="signed.jwt"),
            )
        )
    except HTTPException as exc:
        assert exc.status_code == 401
        assert "tenant claim" in str(exc.detail)
    else:
        raise AssertionError("production JWT without tenant claim was accepted")


def test_oidc_group_role_map(monkeypatch):
    from modules.tenants.middleware import _role_from_claims

    monkeypatch.setenv(
        "TOKENDNA_OIDC_GROUP_ROLE_MAP_JSON",
        '{"Security Owners":"owner","SOC Analysts":"analyst"}',
    )

    assert _role_from_claims({"groups": ["SOC Analysts"]}) == "analyst"


def test_key_lifecycle_routes_emit_audit(monkeypatch):
    import api_routers.enterprise as api
    from modules.tenants.models import Plan, TenantContext

    tenant = TenantContext(
        tenant_id="tenant-1",
        tenant_name="Acme",
        plan=Plan.ENTERPRISE,
        api_key_id="actor-key",
        role="owner",
    )
    events: list[dict] = []

    monkeypatch.setattr(
        api.tenant_store,
        "create_api_key",
        lambda **_kw: (
            SimpleNamespace(id="key-new", key_prefix="tdna_abc", role="analyst"),
            "tdna_raw_secret",
        ),
    )
    monkeypatch.setattr(api.tenant_store, "revoke_api_key", lambda **_kw: None)

    def capture(event_type, outcome, **kwargs):
        events.append({"event_type": str(event_type), "outcome": str(outcome), **kwargs})

    monkeypatch.setattr(api, "log_event", capture)

    created = asyncio.run(
        api.create_key("tenant-1", {"name": "soc", "role": "analyst"}, tenant=tenant)
    )
    revoked = asyncio.run(api.revoke_key("tenant-1", "key-new", tenant=tenant))

    assert created["role"] == "analyst"
    assert revoked["status"] == "revoked"
    assert any("API_KEY_CREATED" in e["event_type"] for e in events)
    assert any("API_KEY_REVOKED" in e["event_type"] for e in events)
    assert all("tdna_raw_secret" not in str(e.get("detail", {})) for e in events)


def test_only_runtime_secure_endpoint_depends_on_bearer_verify_token():
    api_source = Path(__file__).resolve().parents[1].joinpath("api_routers/enterprise.py").read_text()

    assert api_source.count("Depends(verify_token)") == 1
    assert "async def secure(" in api_source
