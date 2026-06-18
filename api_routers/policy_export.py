"""Policy export router (Gap roadmap Epic 3.2 / C4).

Emit guardrail configs (AWS Bedrock JSON + CLI, OpenAI, generic) from advisor
suggestions or a hand-authored policy spec. Gated ent.enforcement_plane.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException

from modules.identity import policy_advisor, policy_export
from modules.product.commercial_tiers import require_feature
from modules.tenants.models import TenantContext

router = APIRouter(prefix="/api/policy/export", tags=["policy-export"])


@router.get("/targets")
async def targets(tenant: TenantContext = Depends(require_feature("ent.enforcement_plane"))):
    """Supported export targets."""
    return {"targets": list(policy_export.SUPPORTED_TARGETS)}


@router.post("")
async def export(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """Export a guardrail config.

    Body: {"target": "bedrock"|"openai"|"generic", "name": str,
           "suggestion_ids": [str]?, "spec": {...}?}
    Either suggestion_ids (built from policy_advisor) or an explicit spec.
    """
    target = str(body.get("target", "bedrock")).lower()
    if target not in policy_export.SUPPORTED_TARGETS:
        raise HTTPException(status_code=400,
                            detail=f"unsupported target; supported: {policy_export.SUPPORTED_TARGETS}")
    name = str(body.get("name", "tokendna-guardrail"))

    if body.get("suggestion_ids"):
        suggestions = []
        for sid in body["suggestion_ids"]:
            s = policy_advisor.get_suggestion(sid, tenant.tenant_id)
            if s is not None:
                suggestions.append(s)
        if not suggestions:
            raise HTTPException(status_code=404, detail="no matching suggestions for tenant")
        spec = policy_export.spec_from_suggestions(name, suggestions)
    elif isinstance(body.get("spec"), dict):
        spec = policy_export.spec_from_dict({**body["spec"], "name": name})
    else:
        raise HTTPException(status_code=400, detail="provide 'suggestion_ids' or a 'spec' object")

    return policy_export.export_policy(spec, target)
