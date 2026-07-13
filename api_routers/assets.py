"""AI Asset Management router (Gap roadmap Epic 3.1 / Challenge C1).

Scan an AI workflow -> inventory of Agents / Tools / MCP Servers /
Vulnerabilities, with scan history. Gated ent.agent_discovery (the inventory
tier); read endpoints require ANALYST.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException

from modules.identity import asset_inventory
from modules.product.commercial_tiers import require_feature
from modules.security.rbac import Role, require_role
from modules.tenants.models import TenantContext

router = APIRouter(prefix="/api/assets", tags=["asset-inventory"])


@router.post("/scan")
async def scan(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_feature("ent.agent_discovery")),
):
    """Scan an agent-workflow definition and persist the inventory.

    Body: {"definition": {...framework workflow...}, "source": str?}
    """
    definition = body.get("definition")
    if not isinstance(definition, dict):
        raise HTTPException(status_code=400, detail="'definition' object is required")
    return asset_inventory.scan_workflow(
        tenant_id=tenant.tenant_id,
        definition=definition,
        source=str(body.get("source", "upload")),
    )


@router.get("/scans")
async def scans(
    limit: int = 50,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """List scan history for the tenant (most recent first)."""
    rows = asset_inventory.list_scans(tenant_id=tenant.tenant_id, limit=min(limit, 200))
    return {"scans": rows, "count": len(rows)}


@router.get("/scans/{scan_id}")
async def scan_detail(
    scan_id: str,
    kind: str | None = None,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Full inventory for one scan; optional ?kind=agent|tool|mcp_server|vulnerability."""
    try:
        return asset_inventory.get_scan(tenant_id=tenant.tenant_id, scan_id=scan_id, kind=kind)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
