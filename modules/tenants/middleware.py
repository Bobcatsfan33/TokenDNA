"""
TokenDNA — Tenant authentication middleware
Supports two auth paths (checked in order):
  1. X-API-Key header  → resolves tenant from key hash (primary, production)
  2. Bearer JWT        → resolves tenant from JWT sub claim (dev / OIDC flow)
DEV_MODE bypasses both and injects a synthetic dev tenant.
"""
from __future__ import annotations

import json
import logging
import os

from fastapi import HTTPException, Request, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from .models import Plan, Tenant, TenantContext
from . import store

logger = logging.getLogger(__name__)

DEV_MODE = os.getenv("DEV_MODE", "false").lower() == "true"

# DEV_MODE injects a synthetic tenant.  Default is ``acme`` so the seeded
# demo dashboard populates immediately without an extra env-var dance —
# ``demo_seed_v2.py`` writes Acme-side history under this tenant id.  Set
# ``DEV_TENANT_ID`` explicitly to point at a different tenant.
_DEV_TENANT_ID   = os.getenv("DEV_TENANT_ID", "acme")
_DEV_TENANT_NAME = os.getenv("DEV_TENANT_NAME", "Local Dev")
_ROLE_VALUES = {"owner", "admin", "analyst", "readonly"}
_DEV_TENANT_ROLE = os.getenv("DEV_TENANT_ROLE", "owner").strip().lower()
if _DEV_TENANT_ROLE not in _ROLE_VALUES:
    logger.warning("invalid DEV_TENANT_ROLE=%r; falling back to readonly", _DEV_TENANT_ROLE)
    _DEV_TENANT_ROLE = "readonly"

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
_bearer         = HTTPBearer(auto_error=False)

# Synthetic tenant injected in DEV_MODE
_DEV_TENANT = TenantContext(
    tenant_id=_DEV_TENANT_ID,
    tenant_name=_DEV_TENANT_NAME,
    plan=Plan.ENTERPRISE,
    api_key_id="dev-key",
    role=_DEV_TENANT_ROLE,
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

    # ── Path 1: API key ─────────────────────────────────────────────────────────
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
            role=key_record.role,
        )

    # ── Path 2: Bearer tenant API key or JWT ─────────────────────────────────
    if bearer:
        # SCIM providers such as Okta send provisioning credentials as
        # Authorization: Bearer <token>. Accept a tenant API key here before
        # falling through to JWT verification for OIDC/API callers. A genuine
        # JWT will never match a key hash, so this is safe; we swallow lookup
        # errors so a JWT bearer never 500s on the (optional) key probe.
        try:
            result = store.lookup_by_key(bearer.credentials)
        except Exception:
            logger.debug("bearer API-key lookup failed; falling through to JWT", exc_info=True)
            result = None
        if result:
            key_record, tenant = result
            return TenantContext(
                tenant_id=tenant.id,
                tenant_name=tenant.name,
                plan=tenant.plan,
                api_key_id=key_record.id,
                role=key_record.role,
            )

        # Import here to avoid circular import
        from auth import _verify_jwt  # type: ignore
        try:
            payload = _verify_jwt(bearer.credentials)
        except Exception as exc:
            raise HTTPException(status_code=401, detail=f"JWT error: {exc}") from exc

        tenant_id = _tenant_id_from_claims(payload)
        if not tenant_id:
            raise HTTPException(status_code=401, detail="JWT missing tenant claim")

        tenant = store.get_tenant(tenant_id)
        if not tenant:
            raise HTTPException(status_code=403, detail="Tenant not found. Complete onboarding.")

        return TenantContext(
            tenant_id=tenant.id,
            tenant_name=tenant.name,
            plan=tenant.plan,
            api_key_id="jwt",
            role=_role_from_claims(payload),
        )

    raise HTTPException(
        status_code=401,
        detail="Provide X-API-Key header or Authorization: Bearer <token>",
    )


def tenant_redis_prefix(tenant_id: str, key: str) -> str:
    """Namespace a Redis key under a tenant to prevent cross-tenant data leaks."""
    return f"t:{tenant_id}:{key}"


def _role_from_claims(payload: dict) -> str:
    role_claim = os.getenv("TOKENDNA_OIDC_ROLE_CLAIM", "tokendna_role,role").strip()
    raw = _first_claim(payload, role_claim)
    if not raw:
        normalized = _claim_set(payload, os.getenv("TOKENDNA_OIDC_GROUPS_CLAIM", "roles,groups"))
        mapped = _role_from_group_map(normalized)
        if mapped:
            return mapped
        for role in ("owner", "admin", "analyst", "readonly"):
            if role in normalized or f"tokendna:{role}" in normalized:
                return role
        return "readonly"
    value = str(raw).strip().lower()
    return value if value in _ROLE_VALUES else "readonly"


def _tenant_id_from_claims(payload: dict) -> str:
    claim_names = os.getenv(
        "TOKENDNA_OIDC_TENANT_CLAIM",
        "org_id,tenant_id,tid,organization",
    )
    tenant_id = _first_claim(payload, claim_names)
    if tenant_id:
        return str(tenant_id).strip()

    allow_sub_fallback = os.getenv("TOKENDNA_OIDC_ALLOW_SUB_TENANT_FALLBACK", "").strip().lower()
    production = (os.getenv("TOKENDNA_ENV") or os.getenv("ENVIRONMENT") or "").strip().lower() in {
        "production", "prod", "il4", "il5", "il6"
    }
    if allow_sub_fallback in {"1", "true", "yes"} or not production:
        fallback = payload.get("sub") or payload.get("client_id")
        return str(fallback).strip() if fallback else ""
    return ""


def _first_claim(payload: dict, claim_names: str) -> object | None:
    for name in [p.strip() for p in claim_names.split(",") if p.strip()]:
        if name in payload and payload[name] not in (None, ""):
            return payload[name]
    return None


def _claim_set(payload: dict, claim_names: str) -> set[str]:
    raw = _first_claim(payload, claim_names)
    if raw is None:
        return set()
    if isinstance(raw, str):
        values = [raw]
    else:
        try:
            values = list(raw)
        except TypeError:
            values = [raw]
    return {str(v).strip().lower() for v in values if str(v).strip()}


def _role_from_group_map(groups: set[str]) -> str:
    raw = os.getenv("TOKENDNA_OIDC_GROUP_ROLE_MAP_JSON", "").strip()
    if not raw:
        return ""
    try:
        mapping = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("invalid TOKENDNA_OIDC_GROUP_ROLE_MAP_JSON ignored")
        return ""
    if not isinstance(mapping, dict):
        return ""
    for group, role in mapping.items():
        normalized_role = str(role).strip().lower()
        if str(group).strip().lower() in groups and normalized_role in _ROLE_VALUES:
            return normalized_role
    return ""
