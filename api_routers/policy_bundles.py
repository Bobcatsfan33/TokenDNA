"""Policy bundles domain router (T-1 sprint 2).

Handlers MOVED VERBATIM from api.py — only the decorator changed
(@app.<verb>("/api/policy/bundles...") -> @router.<verb>("...")). Auth +
tier-gate dependencies preserved; route surface unchanged.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from modules.identity import policy_bundles
from modules.product import metering as feature_metering
from modules.product.feature_gates import PlanTier
from modules.security.rbac import Role, require_role
from modules.tenants.models import TenantContext

router = APIRouter(prefix="/api/policy/bundles", tags=["policy-bundles"])


@router.post("")
async def api_create_policy_bundle(
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    name = str(body.get("name", "edge-default")).strip() or "edge-default"
    version = str(body.get("version", "")).strip()
    if not version:
        raise HTTPException(status_code=400, detail="'version' is required")
    config = body.get("config")
    if not isinstance(config, dict):
        raise HTTPException(status_code=400, detail="'config' must be an object")
    cfg = dict(config)
    cfg.setdefault("created_by", tenant.api_key_id)
    bundle = policy_bundles.create_bundle(
        tenant_id=tenant.tenant_id,
        name=name,
        version=version,
        description=str(body.get("description", "")).strip(),
        config=cfg,
    )
    return {"tenant_id": tenant.tenant_id, "bundle": bundle}


@router.get("")
async def api_list_policy_bundles(
    name: str | None = None,
    status: str | None = None,
    limit: int = 50,
    cursor: str | None = None,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    page = policy_bundles.list_bundles_paginated(
        tenant_id=tenant.tenant_id,
        name=name,
        status=status,
        page_size=min(max(limit, 1), 200),
        cursor=cursor,
    )
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(page["items"]),
        "bundles": page["items"],
        "next_cursor": page["next_cursor"],
        "has_more": page["has_more"],
    }


@router.post("/{bundle_id}/activate")
async def api_activate_policy_bundle(
    bundle_id: str,
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.OWNER)),
):
    approval_actor_id = str(body.get("approval_actor_id", "")).strip() or None
    try:
        bundle = policy_bundles.activate_bundle_with_approval(
            tenant_id=tenant.tenant_id,
            bundle_id=bundle_id,
            actor_id=tenant.api_key_id,
            approval_actor_id=approval_actor_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if bundle is None:
        raise HTTPException(status_code=404, detail="Policy bundle not found")
    return {"tenant_id": tenant.tenant_id, "bundle": bundle}


@router.post("/{bundle_id}/review")
async def api_review_policy_bundle(
    bundle_id: str,
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    note = str(body.get("note", "")).strip()
    review = policy_bundles.review_bundle(
        tenant_id=tenant.tenant_id,
        bundle_id=bundle_id,
        actor_id=tenant.api_key_id,
        note=note,
    )
    if review is None:
        raise HTTPException(status_code=404, detail="Policy bundle not found")
    return {"tenant_id": tenant.tenant_id, "review": review}


@router.post("/{bundle_id}/approve")
async def api_approve_policy_bundle(
    bundle_id: str,
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.OWNER)),
):
    note = str(body.get("note", "")).strip()
    approval = policy_bundles.approve_bundle(
        tenant_id=tenant.tenant_id,
        bundle_id=bundle_id,
        actor_id=tenant.api_key_id,
        note=note,
    )
    if approval is None:
        raise HTTPException(status_code=404, detail="Policy bundle not found")
    return {"tenant_id": tenant.tenant_id, "approval": approval}


@router.get("/{bundle_id}/governance-log")
async def api_policy_bundle_governance_log(
    bundle_id: str,
    limit: int = 100,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    bundle = policy_bundles.get_bundle(tenant.tenant_id, bundle_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Policy bundle not found")
    rows = policy_bundles.list_governance_log(
        tenant_id=tenant.tenant_id,
        bundle_id=bundle_id,
        limit=min(max(limit, 1), 200),
    )
    return {"tenant_id": tenant.tenant_id, "count": len(rows), "events": rows}


@router.post("/{bundle_id}/rollback")
async def api_policy_bundle_rollback(
    bundle_id: str,
    tenant: TenantContext = Depends(require_role(Role.OWNER)),
):
    bundle = policy_bundles.get_bundle(tenant.tenant_id, bundle_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Policy bundle not found")
    try:
        rolled = policy_bundles.rollback_to_previous_active(
            tenant_id=tenant.tenant_id,
            name=str(bundle.get("name") or "edge-default"),
            actor_id=tenant.api_key_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if rolled is None:
        raise HTTPException(status_code=400, detail="No previous active bundle available")
    return {"tenant_id": tenant.tenant_id, "bundle": rolled}


@router.post("/simulate")
async def api_simulate_policy_bundle(
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    simulation = body.get("simulation")
    if not isinstance(simulation, dict):
        raise HTTPException(status_code=400, detail="'simulation' must be an object")
    bundle_id = str(body.get("bundle_id", "")).strip()
    bundle = None
    if bundle_id:
        bundle = policy_bundles.get_bundle(tenant.tenant_id, bundle_id)
    else:
        bundle_name = str(body.get("name", "edge-default")).strip() or "edge-default"
        bundle = policy_bundles.get_active_bundle(tenant.tenant_id, bundle_name)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Policy bundle not found")
    usage = feature_metering.record_usage(
        tenant_id=tenant.tenant_id,
        feature_key="policy.simulation.advanced",
        plan=PlanTier(str(tenant.plan.value) if hasattr(tenant.plan, "value") else str(tenant.plan)),
        amount=1,
        detail={"bundle_id": bundle.get("bundle_id"), "api": "/api/policy/bundles/simulate"},
    )
    if usage["usage"]["status"] == "blocked":
        raise HTTPException(status_code=402, detail="feature_usage_limit_exceeded:policy.simulation.advanced")
    result = policy_bundles.simulate_bundle(
        simulation=simulation,
        bundle_config=bundle.get("config", {}),
    )
    policy_bundles.record_simulation_result(
        tenant_id=tenant.tenant_id,
        bundle_id=bundle.get("bundle_id", ""),
        actor_id=tenant.api_key_id,
        simulation=result,
    )
    return {"tenant_id": tenant.tenant_id, "bundle": bundle, "simulation": result}


@router.post("/active/simulate")
async def api_simulate_active_policy_bundle(
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    simulation = body.get("simulation")
    if not isinstance(simulation, dict):
        raise HTTPException(status_code=400, detail="'simulation' must be an object")
    bundle_name = str(body.get("name", "edge-default")).strip() or "edge-default"
    bundle = policy_bundles.get_active_bundle(tenant.tenant_id, bundle_name)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Active policy bundle not found")
    usage = feature_metering.record_usage(
        tenant_id=tenant.tenant_id,
        feature_key="policy.simulation.advanced",
        plan=PlanTier(str(tenant.plan.value) if hasattr(tenant.plan, "value") else str(tenant.plan)),
        amount=1,
        detail={"bundle_id": bundle.get("bundle_id"), "api": "/api/policy/bundles/active/simulate"},
    )
    if usage["usage"]["status"] == "blocked":
        raise HTTPException(status_code=402, detail="feature_usage_limit_exceeded:policy.simulation.advanced")
    result = policy_bundles.simulate_bundle(
        simulation=simulation,
        bundle_config=bundle.get("config", {}),
    )
    policy_bundles.record_simulation_result(
        tenant_id=tenant.tenant_id,
        bundle_id=bundle.get("bundle_id", ""),
        actor_id=tenant.api_key_id,
        simulation=result,
    )
    return {"tenant_id": tenant.tenant_id, "bundle": bundle, "simulation": result}
