"""T-4: per-route OAuth scope authorization (AC-6 least privilege).

Closes the "basic RBAC" gap without waiting for full ABAC: per-route scopes,
enforced as a dependency stacked beside ``verify_token``. Roles answer "what
kind of user is this"; scopes answer "is this token allowed *this* operation".

Scope vocabulary: ``<domain>:<read|write|admin>``. Read from the JWT ``scp``
claim (Okta/Entra style, list or space string) or ``scope`` (RFC 8693,
space-delimited string).

Rollout is staged. With ``TOKENDNA_SCOPES_ENFORCE`` unset/false (default), a
missing scope is **log-only**: an ``access.denied`` AuditEvent is emitted (so
operators can see what *would* be denied for two weeks) and the request is
allowed. Flip ``TOKENDNA_SCOPES_ENFORCE=true`` to enforce — the same event is
emitted and a 403 is raised.

Usage in a router:

    from modules.auth.scopes import require_scopes
    router = APIRouter(dependencies=[Depends(require_scopes("policy:write"))])
"""
from __future__ import annotations

import logging
import os
from typing import Iterable

from fastapi import Depends, HTTPException

from auth import verify_token
from modules.security.audit_log import AuditEventType, AuditOutcome, log_event

logger = logging.getLogger(__name__)

_ENFORCE_ENV = "TOKENDNA_SCOPES_ENFORCE"


def enforcement_enabled() -> bool:
    """True when scopes are enforced (403); False = log-only rollout."""
    return os.getenv(_ENFORCE_ENV, "false").lower() in {"1", "true", "yes", "on"}


def held_scopes(claims: dict) -> set[str]:
    """Extract the scope set from a verified token's claims.

    Accepts ``scp`` (list or space-delimited string) or ``scope``
    (space-delimited string per RFC 6749/8693).
    """
    raw = claims.get("scp")
    if raw is None:
        raw = claims.get("scope", "")
    if isinstance(raw, str):
        return set(raw.split())
    if isinstance(raw, (list, tuple, set)):
        return {str(s) for s in raw}
    return set()


def _subject(claims: dict) -> str:
    return str(claims.get("sub") or claims.get("client_id") or "unknown")


def _tenant(claims: dict) -> str:
    for key in ("org_id", "tenant_id", "tid", "organization"):
        val = claims.get(key)
        if val:
            return str(val)
    return "_global_"


def require_scopes(*needed: str):
    """FastAPI dependency factory enforcing that the token holds every scope.

    Returns the verified claims on success so the handler can reuse them.
    """
    required = tuple(needed)

    async def dep(claims: dict = Depends(verify_token)) -> dict:
        # DEV_MODE / synthetic tokens carry no scopes; never block dev.
        if claims.get("dev_mode"):
            return claims

        held = held_scopes(claims)
        missing = [s for s in required if s not in held]
        if not missing:
            return claims

        enforced = enforcement_enabled()
        log_event(
            AuditEventType.ACCESS_DENIED,
            AuditOutcome.FAILURE if enforced else AuditOutcome.SUCCESS,
            tenant_id=_tenant(claims),
            subject=_subject(claims),
            resource=",".join(required),
            detail={
                "reason": "insufficient_scope",
                "required": list(required),
                "missing": missing,
                "held": sorted(held),
                "mode": "enforce" if enforced else "log_only",
            },
        )
        if enforced:
            raise HTTPException(
                status_code=403,
                detail={"error": "insufficient_scope", "missing": missing},
            )
        logger.info(
            "scope check (log-only): subject=%s missing=%s — allowing during rollout",
            _subject(claims), missing,
        )
        return claims

    return dep


def scopes_for_tier_feature(feature_key: str) -> tuple[str, ...]:
    """Best-effort scope hint derived from a commercial feature key.

    ``ent.enforcement_plane`` -> ``("enforcement:write",)`` etc. Used to keep
    scope names aligned with the existing tier gates during rollout.
    """
    domain = feature_key.split(".", 1)[-1]
    return (f"{domain}:write",)


def iter_scope_vocabulary(domains: Iterable[str]) -> list[str]:
    """Expand domains into the standard read/write/admin scope vocabulary."""
    out: list[str] = []
    for d in domains:
        out.extend([f"{d}:read", f"{d}:write", f"{d}:admin"])
    return out
