"""SIEM export router (Gap roadmap Epic 4.2 / B2).

Standardized per-MCP-call schema + ECS/Splunk/Sentinel exports. Gated
ent.mcp_gateway.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException

from modules.identity import siem_schema
from modules.product.commercial_tiers import require_feature
from modules.tenants.models import TenantContext

router = APIRouter(prefix="/api/siem", tags=["siem"])


@router.get("/schema")
async def schema(tenant: TenantContext = Depends(require_feature("ent.mcp_gateway"))):
    """The canonical per-MCP-call schema + supported SIEM targets."""
    return siem_schema.canonical_schema()


@router.post("/format")
async def fmt(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_feature("ent.mcp_gateway")),
):
    """Map a gateway enforcement record to a SIEM target format.

    Body: {"enforcement": {...}, "target": "ecs"|"splunk"|"sentinel"|"canonical"}
    """
    enforcement = body.get("enforcement")
    if not isinstance(enforcement, dict):
        raise HTTPException(status_code=400, detail="'enforcement' object is required")
    target = str(body.get("target", "ecs")).lower()
    try:
        event = siem_schema.normalize_mcp_call(enforcement)
        return siem_schema.export_event(event, target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/mcp-calls")
async def mcp_calls(
    target: str = "ecs",
    limit: int = 100,
    session_id: str | None = None,
    tenant: TenantContext = Depends(require_feature("ent.mcp_gateway")),
):
    """Recent MCP tool-call enforcements rendered for a SIEM target."""
    try:
        events = siem_schema.export_mcp_calls(
            tenant_id=tenant.tenant_id, target=target.lower(),
            limit=min(limit, 500), session_id=session_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"target": target.lower(), "events": events, "count": len(events)}
