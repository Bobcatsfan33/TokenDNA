"""
Aegis Security Platform — Role-Based Access Control
=====================================================
FedRAMP High / IL6 compliance: NIST 800-53 Rev5 AC-2, AC-3, AC-5, AC-6

Four roles enforcing least-privilege (AC-6):

  OWNER     — full control: tenants, keys, config, data, admin ops
  ADMIN     — tenant admin: manage keys, view all data, trigger scans
  ANALYST   — read-only security analyst: view findings, events, sessions
  READONLY  — dashboard viewer: stats and charts only, no raw data

Roles are stored on TenantContext (injected per-request by middleware).
Use the @require_role decorator on any FastAPI endpoint.
"""

from __future__ import annotations

import logging
from enum import IntEnum
from functools import wraps
from typing import Callable

from fastapi import Depends, HTTPException, status

logger = logging.getLogger("aegis.rbac")


# ── Role hierarchy (higher int = more privilege) ──────────────────────────────
class Role(IntEnum):
    READONLY = 10
    ANALYST  = 20
    ADMIN    = 30
    OWNER    = 40

    @classmethod
    def from_str(cls, s: str) -> "Role":
        mapping = {
            "readonly": cls.READONLY,
            "analyst":  cls.ANALYST,
            "admin":    cls.ADMIN,
            "owner":    cls.OWNER,
        }
        return mapping.get((s or "readonly").lower(), cls.READONLY)

    def __str__(self) -> str:
        return self.name.lower()


# ── Permission map ────────────────────────────────────────────────────────────
# Maps endpoint tags → minimum required Role
PERMISSION_MAP: dict[str, Role] = {
    # Dashboard / stats (all authenticated roles)
    "stats:read":          Role.READONLY,
    "events:read":         Role.READONLY,
    "health:read":         Role.READONLY,
    "threats:read":        Role.READONLY,

    # Session intelligence
    "sessions:read":       Role.ANALYST,
    "profile:read":        Role.ANALYST,

    # Cloud posture
    "findings:read":       Role.ANALYST,
    "scan:trigger":        Role.ADMIN,
    "remediation:apply":   Role.ADMIN,

    # Token management
    "token:revoke":        Role.ANALYST,
    "token:read":          Role.ANALYST,

    # Tenant management
    "tenant:read":         Role.ADMIN,
    "tenant:create":       Role.OWNER,
    "tenant:delete":       Role.OWNER,
    "apikey:create":       Role.ADMIN,
    "apikey:revoke":       Role.ADMIN,

    # System admin
    "audit:read":          Role.OWNER,
    "config:write":        Role.OWNER,
}


# ── FastAPI dependency factory ────────────────────────────────────────────────
def require_role(minimum_role: Role) -> Callable:
    """
    FastAPI dependency that enforces a minimum role.

    Usage:
        @app.get("/admin/tenants")
        async def list_tenants(
            tenant: TenantContext = Depends(require_role(Role.ADMIN))
        ):
            ...
    """
    def _checker(tenant=Depends(_get_tenant_ctx)):
        role = Role.from_str(getattr(tenant, "role", "readonly"))
        if role < minimum_role:
            logger.warning(
                "RBAC DENIED: tenant=%s role=%s required=%s",
                tenant.tenant_id, role, minimum_role,
            )
            _emit_audit(tenant, minimum_role, granted=False)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient privileges. Required: {minimum_role!s}, have: {role!s}",
            )
        _emit_audit(tenant, minimum_role, granted=True)
        return tenant

    return _checker


def _get_tenant_ctx():
    """Import lazily to avoid circular imports."""
    from modules.tenants.middleware import get_tenant
    return Depends(get_tenant)


def _emit_audit(tenant, required_role: Role, granted: bool) -> None:
    try:
        from modules.security.audit_log import AuditEventType, AuditOutcome, log_event
        log_event(
            AuditEventType.ACCESS_GRANTED if granted else AuditEventType.ACCESS_DENIED,
            AuditOutcome.SUCCESS if granted else AuditOutcome.FAILURE,
            tenant_id=tenant.tenant_id,
            subject=getattr(tenant, "owner_email", tenant.tenant_id),
            detail={"required_role": str(required_role), "granted": granted},
        )
    except Exception:
        pass


# ── Role assignment helpers ───────────────────────────────────────────────────
def check_permission(tenant_ctx, permission: str) -> bool:
    """
    Check a named permission against the tenant's role.

    Usage:
        if not check_permission(tenant, "scan:trigger"):
            raise HTTPException(403, "Scan trigger requires ADMIN role")
    """
    required = PERMISSION_MAP.get(permission, Role.OWNER)  # unknown = most restrictive
    role = Role.from_str(getattr(tenant_ctx, "role", "readonly"))
    return role >= required


def permission_required(permission: str) -> Callable:
    """
    Decorator version for non-FastAPI contexts.

    Usage:
        @permission_required("remediation:apply")
        def apply_fix(tenant_ctx, ...):
            ...
    """
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Look for a 'tenant' or 'tenant_ctx' kwarg
            tenant = kwargs.get("tenant") or kwargs.get("tenant_ctx")
            if tenant and not check_permission(tenant, permission):
                raise PermissionError(
                    f"Permission '{permission}' denied for role "
                    f"'{getattr(tenant, 'role', 'unknown')}'"
                )
            return fn(*args, **kwargs)
        return wrapper
    return decorator
