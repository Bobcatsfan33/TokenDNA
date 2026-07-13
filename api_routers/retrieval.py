"""Governed retrieval router (Gap roadmap Epic 3.3 / B3).

Manage per-agent allowed-source policies and evaluate retrieval requests.
Gated ent.enforcement_plane (governance primitive).
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException

from modules.identity import governed_retrieval as gr
from modules.product.commercial_tiers import require_feature
from modules.tenants.models import TenantContext


def _actor(tenant: TenantContext) -> str:
    return str(getattr(tenant, "owner_email", "") or tenant.api_key_id or tenant.tenant_id)


router = APIRouter(prefix="/api/retrieval", tags=["governed-retrieval"])


@router.post("/sources")
async def add_source(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """Allow an agent (or '*') to retrieve from sources matching a glob pattern.

    Body: {"agent_id": str, "pattern": str, "kind": str?}
    """
    agent_id = str(body.get("agent_id", "")).strip()
    pattern = str(body.get("pattern", "")).strip()
    if not agent_id or not pattern:
        raise HTTPException(status_code=400, detail="'agent_id' and 'pattern' are required")
    return gr.add_allowed_source(
        tenant_id=tenant.tenant_id, agent_id=agent_id, pattern=pattern,
        kind=str(body.get("kind", "any")), added_by=_actor(tenant),
    )


@router.get("/sources")
async def list_sources(
    agent_id: str | None = None,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    rows = gr.list_allowed_sources(tenant_id=tenant.tenant_id, agent_id=agent_id)
    return {"sources": rows, "count": len(rows)}


@router.delete("/sources/{source_id}")
async def delete_source(
    source_id: str,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    gr.remove_allowed_source(tenant_id=tenant.tenant_id, source_id=source_id)
    return {"removed": source_id}


@router.post("/check")
async def check(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """Evaluate (and audit) whether an agent may retrieve from a source.

    Body: {"agent_id": str, "source": str}
    """
    agent_id = str(body.get("agent_id", "")).strip()
    source = str(body.get("source", "")).strip()
    if not agent_id or not source:
        raise HTTPException(status_code=400, detail="'agent_id' and 'source' are required")
    return gr.check_retrieval(tenant_id=tenant.tenant_id, agent_id=agent_id, source=source)
