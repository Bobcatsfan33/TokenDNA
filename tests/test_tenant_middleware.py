from __future__ import annotations

import os
import sys

import pytest
from fastapi.security import HTTPAuthorizationCredentials

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.mark.asyncio
async def test_bearer_api_key_resolves_tenant_for_scim(monkeypatch, tmp_path):
    from modules.tenants import middleware, store
    from modules.tenants.models import Plan

    monkeypatch.delenv("TOKENDNA_DB_BACKEND", raising=False)
    monkeypatch.delenv("TOKENDNA_PG_DSN", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("DATA_BACKEND", "sqlite")
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "tenants.db"))
    monkeypatch.setattr(middleware, "DEV_MODE", False)

    store.init_db()
    tenant, raw_key = store.create_tenant("Okta Sandbox", owner_email="owner@example.com", plan=Plan.ENTERPRISE)

    ctx = await middleware.get_tenant(
        request=None,  # type: ignore[arg-type]
        api_key=None,
        bearer=HTTPAuthorizationCredentials(scheme="Bearer", credentials=raw_key),
    )

    assert ctx.tenant_id == tenant.id
    assert ctx.tenant_name == "Okta Sandbox"
    assert ctx.plan is Plan.ENTERPRISE
    assert ctx.api_key_id != "jwt"
