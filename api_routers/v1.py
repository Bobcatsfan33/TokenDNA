"""The three flagship /v1 endpoints (P2.4).

Three questions, three endpoints, one code path. Every handler here is thin
orchestration over ``modules.identity.evaluate`` — no business logic lives in
this file, and none should be added to it.

    POST /v1/verify                     is this identity real and valid?
    POST /v1/authorize                  is it allowed to do this?
    GET  /v1/contain/{agent_id}         is it compromised, how far, and can I trace it?
    POST /v1/contain/{agent_id}/revoke  contain it — rip credentials across every plane

HTTP status carries the verdict so a caller that ignores the body still behaves
safely (fail-closed by default):

    ALLOW    200
    STEP_UP  202  — accepted, but step-up verification is required first
    BLOCK    403  — refused (401 on /v1/verify: the identity itself did not hold up)
    REVOKE   403  — refused, and the agent should be contained
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import JSONResponse

from modules.identity import evaluate as ev
from modules.identity import revocation_bus
from modules.identity import graph_revocation  # noqa: F401 — self-registers its connector
from modules.identity import idp_revocation  # noqa: F401
from modules.identity import mcp_revocation  # noqa: F401
from modules.identity import passport_revocation  # noqa: F401
from modules.identity import session_revocation  # noqa: F401
from modules.security.rbac import Role, require_role
from modules.tenants.models import TenantContext

router = APIRouter(prefix="/v1", tags=["v1"])

_STATUS = {ev.ALLOW: 200, ev.STEP_UP: 202, ev.BLOCK: 403, ev.REVOKE: 403}


def _respond(verdict: ev.Verdict, *, block_status: int = 403) -> JSONResponse:
    status = _STATUS.get(verdict.verdict, 403)
    if verdict.verdict in (ev.BLOCK, ev.REVOKE):
        status = block_status
    return JSONResponse(status_code=status, content=verdict.as_dict())


def _actor(tenant: TenantContext) -> str:
    return str(getattr(tenant, "owner_email", "") or tenant.api_key_id or tenant.tenant_id)


@router.post("/verify")
async def verify(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Is this a legitimate agent identity, and are its credentials valid?

    Body: {"agent_id": str (required), "passport": {...}?, "dpop_proof": str?,
           "dpop_method": str?, "dpop_uri": str?}

    A failed identity is a 401, not a 403: nothing was refused on policy grounds —
    the identity itself did not hold up.
    """
    agent_id = str(body.get("agent_id", "")).strip()
    if not agent_id:
        raise HTTPException(status_code=400, detail="'agent_id' is required")

    verdict = ev.evaluate("verify", ev.Subject(
        tenant_id=tenant.tenant_id,
        agent_id=agent_id,
        passport=body.get("passport"),
        dpop_proof=body.get("dpop_proof"),
        dpop_method=str(body.get("dpop_method", "POST")),
        dpop_uri=str(body.get("dpop_uri", "")),
    ))
    return _respond(verdict, block_status=401)


@router.post("/authorize")
async def authorize(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Is it allowed to do what it's doing, and go where it's going?

    Body: {"agent_id": str (required), "action": str (required),
           "resource": str (required), "destination": str?, "claims": {...}?}

    ``claims`` are the agent's verified token claims. When supplied, its scopes are
    evaluated too — honouring the log-only rollout switch, so enabling this cannot
    silently start denying traffic that used to flow.
    """
    agent_id = str(body.get("agent_id", "")).strip()
    action = str(body.get("action", "")).strip()
    resource = str(body.get("resource", "")).strip()
    missing = [k for k, v in (("agent_id", agent_id), ("action", action),
                              ("resource", resource)) if not v]
    if missing:
        raise HTTPException(status_code=400,
                            detail=f"missing required field(s): {', '.join(missing)}")

    verdict = ev.evaluate("authorize", ev.Subject(
        tenant_id=tenant.tenant_id,
        agent_id=agent_id,
        action=action,
        resource=resource,
        destination=str(body.get("destination", "")),
        claims=body.get("claims"),
    ))
    return _respond(verdict)


@router.get("/contain/{agent_id}")
async def contain(
    agent_id: str,
    window_hours: int = 24,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Has it been compromised — what is the blast radius, and can I trace it?

    Returns the verdict plus ``blast_radius.trace`` — the tamper-evident
    TraceReport (P2.2) — and ``blast_radius.trace_verification``, the result of
    re-deriving that chain, so a reader never takes the report's word for itself.
    """
    verdict = ev.evaluate("contain", ev.Subject(
        tenant_id=tenant.tenant_id, agent_id=agent_id, window_hours=window_hours,
    ))
    # CONTAIN is a diagnosis, not a refusal: a compromised agent must still return
    # its evidence to the operator who has to act on it. Always 200.
    return JSONResponse(status_code=200, content=verdict.as_dict())


@router.post("/contain/{agent_id}/revoke")
async def contain_revoke(
    agent_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Contain it: rip credentials across every connected plane, then re-diagnose.

    Body: {"reason": str (required), "planes": [str]?, "jtis": [str]?}

    Returns the kill receipt AND the post-containment verdict, so the caller can
    see that containment actually changed the agent's state rather than trusting
    that it did.
    """
    reason = str(body.get("reason", "")).strip()
    if not reason:
        raise HTTPException(status_code=400, detail="'reason' is required to revoke")
    planes = body.get("planes")
    if planes is not None and not isinstance(planes, list):
        raise HTTPException(status_code=400, detail="'planes' must be a list of plane names")

    receipt = revocation_bus.rip_credentials(
        tenant.tenant_id, agent_id,
        actor=_actor(tenant), reason=reason, planes=planes,
        context={"jtis": body.get("jtis") or []},
    )
    post = ev.evaluate("contain", ev.Subject(
        tenant_id=tenant.tenant_id, agent_id=agent_id,
    ))
    return {"receipt": receipt.as_dict(), "post_containment_verdict": post.as_dict()}
