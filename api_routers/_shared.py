"""Shared helpers used by extracted domain routers (T-1).

Helpers that used to live as module-level functions in api.py and are referenced
by moved handlers land here so routers don't import api.py (which would create a
cycle: api.py imports api_routers).
"""
from __future__ import annotations

from fastapi import HTTPException


def _delegation_error_to_http(exc: Exception) -> HTTPException:
    """Translate DelegationError reason codes to structured 4xx responses."""
    code_map = {
        "scope_must_be_list_of_strings":      400,
        "expires_in_seconds_must_be_positive": 400,
        "root_delegator_must_be_human":       400,
        "parent_not_found":                   404,
        "parent_cross_tenant":                403,
        "parent_revoked":                     409,
        "parent_expired":                     409,
        "delegator_not_parent_delegatee":     403,
        "scope_exceeds_parent":               403,
        "not_found":                          404,
        "cross_tenant":                       403,
    }
    reason = str(exc)
    return HTTPException(
        status_code=code_map.get(reason, 400),
        detail={"error": reason, "message": reason.replace("_", " ")},
    )


# ── Rate-limit dependencies (moved from api.py) ───────────────────────────────
from fastapi import Depends, Request  # noqa: E402

from config import RATE_LIMIT_OPEN_PER_MINUTE, RATE_LIMIT_PER_MINUTE  # noqa: E402
from modules.identity.cache_redis import increment_rate  # noqa: E402
from modules.tenants.middleware import get_tenant  # noqa: E402
from modules.tenants.models import TenantContext  # noqa: E402


async def check_rate_limit(
    request: Request,
    tenant: TenantContext = Depends(get_tenant),
) -> None:
    ip = request.client.host if request.client else "unknown"
    key = f"rate:{ip}"
    count = increment_rate(key, window_seconds=60, tenant_id=tenant.tenant_id)
    if count > RATE_LIMIT_PER_MINUTE:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded ({RATE_LIMIT_PER_MINUTE} req/min)",
            headers={"Retry-After": "60"},
        )


async def check_rate_limit_open(request: Request) -> None:
    """Rate-limit dependency for open (unauthenticated) endpoints (IP-only, global)."""
    ip = request.client.host if request.client else "unknown"
    key = f"open_rate:{ip}"
    count = increment_rate(key, window_seconds=60, tenant_id="_open_")
    if count > RATE_LIMIT_OPEN_PER_MINUTE:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded ({RATE_LIMIT_OPEN_PER_MINUTE} req/min on open endpoint)",
            headers={"Retry-After": "60"},
        )
