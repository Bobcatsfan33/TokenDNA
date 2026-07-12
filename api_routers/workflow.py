"""workflow domain router (T-1 decomposition).

Handlers MOVED VERBATIM from api.py (decorator-only change). Route surface
unchanged (scripts/ci/openapi_route_guard.py). Imports copied from api.py
(ruff ignores unused F401) so every handler resolves.
"""
from __future__ import annotations

from fastapi import APIRouter

import asyncio
import datetime
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
from fastapi import Body, Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from auth import verify_token
from config import DEV_MODE, OIDC_ISSUER, RATE_LIMIT_PER_MINUTE, RATE_LIMIT_OPEN_PER_MINUTE
from modules.identity import scoring
from modules.identity.alerts import handle_block, handle_revoke, handle_step_up
from modules.identity.cache_redis import (
    TenantRedis,
    get_baseline,
    get_event_counters,
    get_redis,
    increment_event_counter,
    increment_rate,
    is_token_revoked,
    push_baseline_history,
    revoke_token,
    set_baseline,
)
from modules.identity.scoring import RiskTier
from modules.identity.token_dna import generate_dna, migrate_dna
from modules.identity.uis import normalize_from_protocol, validate_uis_event
from modules.identity.uis_protocol import get_uis_spec, normalize_with_adapter
from modules.identity.attestation_store import create_attestation_record
from modules.identity.mcp_attestation import verify_mcp_server
from modules.identity.attestation_certificates import issue_certificate, revoke_certificate, verify_certificate
from modules.identity.certificate_status import build_crl, certificate_status_payload
from modules.identity.edge_enforcement import evaluate_runtime_enforcement
from modules.identity.trust_authority import list_key_configs
from modules.identity.attestation_drift import build_drift_event, DriftAssessment, assess_runtime_drift
from modules.identity import schema_registry
from modules.identity import trust_graph
from modules.identity import blast_radius
from modules.identity import policy_guard
from modules.identity import permission_drift
from modules.identity import intent_correlation
from modules.identity import policy_bundles
from modules.identity import agent_lifecycle
from modules.identity import mcp_inspector
from modules.identity import mcp_gateway
from modules.identity import agent_discovery
from modules.identity import enforcement_plane
from modules.identity import behavioral_dna
from modules.identity import compliance_engine
from modules.identity import cert_dashboard
from modules.identity import policy_advisor
from modules.identity import network_intel
from modules.identity import compliance
from modules.identity import attestation_store
from modules.identity import uis_store
from modules.identity import decision_audit
from modules.identity import trust_federation
from modules.identity import certificate_transparency as ct_log
from modules.identity import clickhouse_client
from modules.integrations.siem_taxii import build_taxii_bundle
from modules.integrations.idp_events import adapt_idp_event
from modules.integrations.sdk_wrappers import (
    build_adapter_normalize_request,
    build_attestation_request,
    sdk_create_attestation,
    sdk_normalize_event,
)
from modules.product import metering as feature_metering
from modules.product.commercial_tiers import (
    list_features as list_commercial_features,
    require_feature,
    tier_for_plan,
)
from modules.product.feature_gates import PlanTier, evaluate_feature_access, list_feature_matrix
from modules.storage import db_backend
from modules.identity.uis_narrative import enrich_event as uis_enrich_event
from modules.tenants import store as tenant_store
from modules.tenants.middleware import get_tenant
from modules.tenants.models import Plan, TenantContext
from modules.security.audit_log import AuditEventType, AuditOutcome, log_event
from modules.security.headers import RequestValidationMiddleware, SecurityHeadersMiddleware
from modules.security.rbac import Role, require_role
from modules.security.fips import fips, FIPSError
from modules.identity.hvip import HVIPEnforcer, HVIPRole, HVIPAction, HVIPError
from modules.identity import passport as passport_module
from modules.identity import verifier_reputation as reputation_module
from modules.identity import proof_of_control as poc_module
import hmac as _edge_hmac  # noqa: E402

router = APIRouter(prefix="", tags=["workflow"])


@router.post("/api/workflow/register")
async def api_workflow_register(
    body: dict,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """Register a canonical workflow. Body: {name, hops[], description?,
    created_by?}."""
    from modules.identity import workflow_attestation as wf  # noqa: PLC0415
    name = str(body.get("name") or "").strip()
    hops = body.get("hops")
    if not isinstance(hops, list):
        raise HTTPException(status_code=400, detail="'hops' must be a list")
    try:
        out = wf.register_workflow(
            tenant_id=tenant.tenant_id,
            name=name,
            hops=hops,
            description=str(body.get("description") or ""),
            created_by=body.get("created_by"),
        )
        return out.as_dict()
    except wf.WorkflowError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": str(exc)},
        ) from exc


@router.get("/api/workflow/{workflow_id}")
async def api_workflow_get(
    workflow_id: str,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    from modules.identity import workflow_attestation as wf  # noqa: PLC0415
    out = wf.get_workflow(workflow_id, tenant_id=tenant.tenant_id)
    if not out:
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    return out.as_dict()


@router.get("/api/workflow")
async def api_workflow_list(
    status: str = "active",
    limit: int = 100,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    from modules.identity import workflow_attestation as wf  # noqa: PLC0415
    items = wf.list_workflows(
        tenant.tenant_id,
        status=None if status == "all" else status,
        limit=limit,
    )
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(items),
        "workflows": [w.as_dict() for w in items],
    }


@router.post("/api/workflow/{workflow_id}/retire")
async def api_workflow_retire(
    workflow_id: str,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    from modules.identity import workflow_attestation as wf  # noqa: PLC0415
    if not wf.retire_workflow(workflow_id, tenant_id=tenant.tenant_id):
        raise HTTPException(
            status_code=404,
            detail={"error": "not_found_or_already_retired"},
        )
    return {"workflow_id": workflow_id, "status": "retired"}


@router.get("/api/workflow/{workflow_id}/replay")
async def api_workflow_replay(
    workflow_id: str,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """Re-derive signature, re-verify all linked delegation receipts,
    return a per-hop verification report."""
    from modules.identity import workflow_attestation as wf  # noqa: PLC0415
    return wf.replay_workflow(workflow_id, tenant_id=tenant.tenant_id).as_dict()


@router.post("/api/workflow/{workflow_id}/observe")
async def api_workflow_observe(
    workflow_id: str,
    body: dict,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """Record an observed run. Body: {hops[]}."""
    from modules.identity import workflow_attestation as wf  # noqa: PLC0415
    hops = body.get("hops")
    if not isinstance(hops, list):
        raise HTTPException(status_code=400, detail="'hops' must be a list")
    try:
        return wf.record_observation(
            workflow_id=workflow_id,
            observed_hops=hops,
            tenant_id=tenant.tenant_id,
        )
    except wf.WorkflowError as exc:
        reason = str(exc)
        if reason == "not_found_or_cross_tenant":
            raise HTTPException(status_code=404, detail={"error": reason}) from exc
        raise HTTPException(status_code=400, detail={"error": reason}) from exc


@router.get("/api/workflow/{workflow_id}/observations")
async def api_workflow_observations(
    workflow_id: str,
    drift_only: bool = False,
    limit: int = 50,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    from modules.identity import workflow_attestation as wf  # noqa: PLC0415
    items = wf.get_observations(
        workflow_id=workflow_id,
        drift_only=drift_only,
        limit=limit,
        tenant_id=tenant.tenant_id,
    )
    return {
        "workflow_id": workflow_id,
        "count": len(items),
        "observations": items,
    }


