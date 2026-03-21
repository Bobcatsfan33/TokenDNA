"""
TokenDNA — Tenant authentication middleware
Supports two auth paths (checked in order):
  1. X-API-Key header  → resolves tenant from key hash (primary, production)
  2. Bearer JWT        → resolves tenant from JWT sub claim (dev / OIDC flow)
DEV_MODE bypasses both and injects a synthetic dev tenant.
"""
from __future__ import annotations

import logging
import os

from fastapi import HTTPException, Request, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from .models import Plan, Tenant, TenantContext
from . import store

logger = logging.getLogger(__name__)

DEV_MODE = os.getenv("DEV_MODE", "false").lower() == "true"

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
_bearer         = HTTPBearer(auto_error=False)

# Synthetic tenant injected in DEV_MODE
_DEV_TENANT = TenantContext(
    tenant_id="dev-tenant",
    tenant_name="Local Dev",
    plan=Plan.ENTERPRISE,
    api_key_id="dev-key",
)


async def get_tenant(
    request: Request,
    api_key: str | None = Security(_api_key_header),
    bearer:  HTTPAuthorizationCredentials | None = Security(_bearer),
) -> TenantContext:
    """
    FastAPI dependency. Inject into any route that needs tenant isolation:
        tenant: TenantContext = Depends(get_tenant)
    """
    if DEV_MODE:
        return _DEV_TENANT

    # ── Path 1: API key ───────────────────────────────────────────────────────
    if api_key:
        result = store.lookup_by_key(api_key)
        if not result:
            raise HTTPException(status_code=401, detail="Invalid or revoked API key")
        key_record, tenant = result
        return TenantContext(
            tenant_id=tenant.id,
            tenant_name=tenant.name,
            plan=tenant.plan,
            api_key_id=key_record.id,
        )

    # ── Path 2: Bearer JWT (delegates to existing auth module) ────────────────
    if bearer:
        # Import here to avoid circular import
        from auth import _verify_jwt  # type: ignore
        try:
            payload = _verify_jwt(bearer.credentials)
        except Exception as exc:
            raise HTTPException(status_code=401, detail=f"JWT error: {exc}") from exc

        sub = payload.get("sub") or payload.get("client_id")
        if not sub:
            raise HTTPException(status_code=401, detail="JWT missing sub claim")

        # For JWT auth, the sub is treated as the tenant_id.
        # In a real OIDC flow you'd look up the org by the OIDC org_id claim.
        tenant = store.get_tenant(sub)
        if not tenant:
            raise HTTPException(status_code=403, detail="Tenant not found. Complete onboarding.")

        return TenantContext(
            tenant_id=tenant.id,
            tenant_name=tenant.name,
            plan=tenant.plan,
            api_key_id="jwt",
        )

    raise HTTPException(
        status_code=401,
        detail="Provide X-API-Key header or Authorization: Bearer <token>",
    )


def tenant_redis_prefix(tenant_id: str, key: str) -> str:
    """Namespace a Redis key under a tenant to prevent cross-tenant data leaks."""
    return f"t:{tenant_id}:{key}"
