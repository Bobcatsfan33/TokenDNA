"""Campaign correlation router (Gap roadmap Epic 4.1 / A1).

Reassemble multi-session/agent/model attacks into campaigns. Gated
ent.intent_correlation (the correlation tier).
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException

from modules.identity import campaign_correlation as cc
from modules.identity import intent_correlation
from modules.product.commercial_tiers import require_feature
from modules.tenants.models import TenantContext

router = APIRouter(prefix="/api/campaigns", tags=["campaigns"])


@router.post("/build")
async def build(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_feature("ent.intent_correlation")),
):
    """Stitch signals into campaigns.

    Body: {"signals": [...]?, "window_seconds": int?, "min_signals": int?}
    If 'signals' omitted, sources recent intent matches for the tenant.
    """
    signals = body.get("signals")
    if signals is None:
        matches = intent_correlation.get_matches(tenant.tenant_id, limit=200)
        signals = cc.signals_from_intent_matches(matches)
    elif not isinstance(signals, list):
        raise HTTPException(status_code=400, detail="'signals' must be a list")
    campaigns = cc.build_campaigns(
        tenant_id=tenant.tenant_id,
        signals=signals,
        window_seconds=float(body.get("window_seconds", cc.DEFAULT_WINDOW_SECONDS)),
        min_signals=int(body.get("min_signals", 2)),
    )
    return {"campaigns": campaigns, "count": len(campaigns)}


@router.get("")
async def list_campaigns(
    limit: int = 50,
    tenant: TenantContext = Depends(require_feature("ent.intent_correlation")),
):
    rows = cc.list_campaigns(tenant_id=tenant.tenant_id, limit=min(limit, 200))
    return {"campaigns": rows, "count": len(rows)}


@router.get("/{campaign_id}")
async def get_campaign(
    campaign_id: str,
    tenant: TenantContext = Depends(require_feature("ent.intent_correlation")),
):
    try:
        return cc.get_campaign(tenant_id=tenant.tenant_id, campaign_id=campaign_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
