"""Real-time credential-rip kill switch router (Gap roadmap, Challenge D).

Exposes the Revocation Fan-out Bus: click a rogue agent -> rip its credentials
across every connected plane (TokenDNA decision, edge JWT, IdP OAuth, MCP,
sessions, data) with a per-plane receipt. Gated ANALYST+; cascade requires
OWNER/step-up (Sprint 5).
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException

from modules.identity import revocation_bus
from modules.identity import graph_revocation  # noqa: F401 — self-registers trust-graph connector
from modules.identity import idp_revocation  # noqa: F401 — self-registers IdP connectors
from modules.identity import mcp_revocation  # noqa: F401 — self-registers MCP connector
from modules.identity import passport_revocation  # noqa: F401 — self-registers passport connector
from modules.identity import session_revocation  # noqa: F401 — self-registers session connector
from modules.security.rbac import Role, require_role
from modules.tenants.models import TenantContext

router = APIRouter(prefix="/api/kill", tags=["kill-switch"])


def _actor(tenant: TenantContext) -> str:
    return str(getattr(tenant, "owner_email", "") or tenant.api_key_id or tenant.tenant_id)


@router.get("/{agent_id}/preview")
async def kill_preview(
    agent_id: str,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Pre-flight: which planes are connected and would be revoked. No effect."""
    receipt = revocation_bus.preview(tenant.tenant_id, agent_id)
    return receipt.as_dict()


@router.post("/{agent_id}")
async def kill_rip(
    agent_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Rip an agent's credentials across every connected plane.

    Body: {"reason": str (required), "planes": [str]?, "jtis": [str]?,
           "timeout_ms": int?}
    """
    reason = str(body.get("reason", "")).strip()
    if not reason:
        raise HTTPException(status_code=400, detail="'reason' is required to rip credentials")
    planes = body.get("planes")
    if planes is not None and not isinstance(planes, list):
        raise HTTPException(status_code=400, detail="'planes' must be a list of plane names")
    context = {"jtis": body.get("jtis") or []}
    receipt = revocation_bus.rip_credentials(
        tenant.tenant_id, agent_id,
        actor=_actor(tenant),
        reason=reason,
        planes=planes,
        context=context,
        timeout_ms=int(body.get("timeout_ms", revocation_bus.DEFAULT_PLANE_TIMEOUT_MS)),
    )
    return receipt.as_dict()


@router.post("/{agent_id}/cascade")
async def kill_cascade(
    agent_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.OWNER)),
):
    """Cascade rip: the agent + every agent/workload in its blast radius.

    OWNER-gated (step-up). Body must set {"confirm": true, "reason": str}.
    """
    reason = str(body.get("reason", "")).strip()
    if not reason:
        raise HTTPException(status_code=400, detail="'reason' is required for a cascade kill")
    if body.get("confirm") is not True:
        raise HTTPException(status_code=400, detail="cascade kill requires explicit {\"confirm\": true}")
    planes = body.get("planes")
    if planes is not None and not isinstance(planes, list):
        raise HTTPException(status_code=400, detail="'planes' must be a list of plane names")
    return revocation_bus.cascade_rip(
        tenant.tenant_id, agent_id,
        actor=_actor(tenant),
        reason=reason,
        planes=planes,
        context={"jtis": body.get("jtis") or []},
        max_hops=int(body.get("max_hops", 6)),
    )


@router.post("/{agent_id}/reverse")
async def kill_reverse(
    agent_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Restore reversible planes for an agent (irreversible planes reported)."""
    reason = str(body.get("reason", "")).strip()
    if not reason:
        raise HTTPException(status_code=400, detail="'reason' is required to reverse a rip")
    planes = body.get("planes")
    if planes is not None and not isinstance(planes, list):
        raise HTTPException(status_code=400, detail="'planes' must be a list of plane names")
    receipt = revocation_bus.reverse_rip(
        tenant.tenant_id, agent_id,
        actor=_actor(tenant),
        reason=reason,
        planes=planes,
    )
    return receipt.as_dict()
