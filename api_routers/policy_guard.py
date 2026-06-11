"""PolicyGuard domain router (T-1 decomposition, sprint 1 worked example).

Handlers MOVED VERBATIM from api.py — only the decorator changed from
``@app.<verb>("/api/policy/guard/...")`` to ``@router.<verb>("/...")`` with the
prefix stripped. Dependencies (auth + tier gate) are preserved exactly per
route, so the externally-visible behavior and route surface are unchanged
(verified by scripts/ci/openapi_route_guard.py).
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from modules.identity import policy_guard
from modules.product.commercial_tiers import require_feature
from modules.security.rbac import Role, require_role
from modules.tenants.models import TenantContext

router = APIRouter(prefix="/api/policy/guard", tags=["policy-guard"])


@router.post("/evaluate")
async def api_policy_guard_evaluate(
    body: dict,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """
    Evaluate a pending policy action against PolicyGuard constitutional rules.

    Returns disposition: allow | flag | block.
    BLOCK means the action must not proceed — a violation record is created
    and human approval is required via POST /api/policy/guard/violations/{id}/approve.

    Body fields:
      actor_id           str  required  agent/service attempting the action
      actor_type         str  required  "agent" | "service" | "human"
      action_type        str  required  "create" | "update" | "delete" | "activate" | "rollback"
      target_policy_id   str  required  policy being modified
      target_policy_name str  required  human-readable policy name
      scope_delta        list optional  permissions being added/removed
      metadata           dict optional  governed_agent, actor_scopes, delegated_scopes, etc.
    """
    policy_guard.init_db()
    try:
        action = policy_guard.PolicyAction(
            actor_id=str(body.get("actor_id", "")).strip(),
            actor_type=str(body.get("actor_type", "agent")).strip(),
            action_type=str(body.get("action_type", "")).strip(),
            target_policy_id=str(body.get("target_policy_id", "")).strip(),
            target_policy_name=str(body.get("target_policy_name", "")).strip(),
            tenant_id=tenant.tenant_id,
            scope_delta=body.get("scope_delta", []),
            metadata=body.get("metadata", {}),
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if not action.actor_id or not action.action_type or not action.target_policy_id:
        raise HTTPException(
            status_code=400,
            detail="actor_id, action_type, and target_policy_id are required",
        )

    result = policy_guard.evaluate(action)
    return {
        "request_id": result.request_id,
        "actor_id": result.actor_id,
        "target_policy_id": result.target_policy_id,
        "disposition": result.disposition.value,
        "rules_triggered": result.rules_triggered,
        "reasons": result.reasons,
        "violation_id": result.violation_id,
        "evaluated_at": result.evaluated_at,
        "proceed": result.disposition == policy_guard.Disposition.ALLOW,
    }


@router.get("/violations")
async def api_policy_guard_violations(
    status: Optional[str] = None,
    actor_id: Optional[str] = None,
    disposition: Optional[str] = None,
    limit: int = 50,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """
    List PolicyGuard violations for the current tenant.
    Default: open violations (requiring human review).
    BLOCK violations must be approved before the action can proceed.
    """
    policy_guard.init_db()
    violations = policy_guard.list_violations(
        tenant_id=tenant.tenant_id,
        status=status,
        actor_id=actor_id,
        disposition=disposition,
        limit=min(limit, 200),
    )
    return {
        "violations": [
            {
                "violation_id": v.violation_id,
                "actor_id": v.actor_id,
                "actor_type": v.actor_type,
                "action_type": v.action_type,
                "target_policy_id": v.target_policy_id,
                "target_policy_name": v.target_policy_name,
                "disposition": v.disposition.value,
                "rules_triggered": v.rules_triggered,
                "reasons": v.reasons,
                "status": v.status.value,
                "detected_at": v.detected_at,
                "resolved_at": v.resolved_at,
                "resolved_by": v.resolved_by,
                "resolution_note": v.resolution_note,
            }
            for v in violations
        ],
        "count": len(violations),
        "tenant_id": tenant.tenant_id,
    }


@router.get("/violations/{violation_id}")
async def api_policy_guard_get_violation(
    violation_id: str,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """Get a specific PolicyGuard violation by ID."""
    policy_guard.init_db()
    violation = policy_guard.get_violation(violation_id, tenant.tenant_id)
    if not violation:
        raise HTTPException(status_code=404, detail="Violation not found")
    return {
        "violation_id": violation.violation_id,
        "actor_id": violation.actor_id,
        "actor_type": violation.actor_type,
        "action_type": violation.action_type,
        "target_policy_id": violation.target_policy_id,
        "target_policy_name": violation.target_policy_name,
        "disposition": violation.disposition.value,
        "rules_triggered": violation.rules_triggered,
        "reasons": violation.reasons,
        "status": violation.status.value,
        "detected_at": violation.detected_at,
        "resolved_at": violation.resolved_at,
        "resolved_by": violation.resolved_by,
        "resolution_note": violation.resolution_note,
        "metadata": violation.metadata,
    }


@router.post("/violations/{violation_id}/approve",
    dependencies=[Depends(require_feature("ent.enforcement_plane"))],
)
async def api_policy_guard_approve(
    violation_id: str,
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """
    Human operator approves a blocked policy action.
    The action may now proceed; the violation audit record remains.

    Body fields:
      approved_by  str  required  operator identity
      note         str  optional  justification
    """
    policy_guard.init_db()
    approved_by = str(body.get("approved_by", "")).strip()
    if not approved_by:
        raise HTTPException(status_code=400, detail="approved_by is required")
    violation = policy_guard.approve_violation(
        violation_id=violation_id,
        tenant_id=tenant.tenant_id,
        approved_by=approved_by,
        note=str(body.get("note", "")),
    )
    if not violation:
        raise HTTPException(
            status_code=404,
            detail="Violation not found or not in open status",
        )
    return {
        "violation_id": violation.violation_id,
        "status": violation.status.value,
        "approved_by": violation.resolved_by,
        "resolved_at": violation.resolved_at,
        "proceed": True,
    }


@router.post("/violations/{violation_id}/reject",
    dependencies=[Depends(require_feature("ent.enforcement_plane"))],
)
async def api_policy_guard_reject(
    violation_id: str,
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """
    Human operator rejects a blocked policy action (must not proceed).

    Body fields:
      rejected_by  str  required  operator identity
      note         str  optional  justification
    """
    policy_guard.init_db()
    rejected_by = str(body.get("rejected_by", "")).strip()
    if not rejected_by:
        raise HTTPException(status_code=400, detail="rejected_by is required")
    violation = policy_guard.reject_violation(
        violation_id=violation_id,
        tenant_id=tenant.tenant_id,
        rejected_by=rejected_by,
        note=str(body.get("note", "")),
    )
    if not violation:
        raise HTTPException(
            status_code=404,
            detail="Violation not found or not in open status",
        )
    return {
        "violation_id": violation.violation_id,
        "status": violation.status.value,
        "rejected_by": violation.resolved_by,
        "resolved_at": violation.resolved_at,
        "proceed": False,
    }


@router.get("/stats")
async def api_policy_guard_stats(
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """Summary statistics for PolicyGuard violations in the current tenant."""
    policy_guard.init_db()
    return policy_guard.violation_stats(tenant.tenant_id)
