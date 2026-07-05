"""enforcement domain router (T-1 decomposition).

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
from modules.identity.attestation import create_attestation_record
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

router = APIRouter(prefix="/api/enforcement", tags=["enforcement"])


@router.post("/policies",
    dependencies=[Depends(require_feature("ent.enforcement_plane"))],
)
async def api_ep_create_policy(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Create an enforcement policy."""
    enforcement_plane.init_db()
    name = str(body.get("name") or "")
    rules = body.get("rules") or []
    if not name:
        raise HTTPException(status_code=422, detail="name is required")
    if not isinstance(rules, list):
        raise HTTPException(status_code=422, detail="rules must be a list")
    try:
        return enforcement_plane.create_policy(
            tenant_id=tenant.tenant_id,
            name=name,
            rules=rules,
            mode=str(body.get("mode") or "shadow"),
            canary_pct=float(body.get("canary_pct") or 0.0),
            description=str(body.get("description") or ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/policies",
    dependencies=[Depends(require_feature("ent.enforcement_plane"))],
)
async def api_ep_list_policies(
    status: str | None = "active",
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    enforcement_plane.init_db()
    return {"policies": enforcement_plane.list_policies(tenant.tenant_id, status=status)}


@router.get("/policies/{policy_id}",
    dependencies=[Depends(require_feature("ent.enforcement_plane"))],
)
async def api_ep_get_policy(
    policy_id: str,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    enforcement_plane.init_db()
    try:
        return enforcement_plane.get_policy(policy_id, tenant.tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/policies/{policy_id}")
async def api_ep_update_policy(
    policy_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    enforcement_plane.init_db()
    try:
        return enforcement_plane.update_policy(
            policy_id, tenant.tenant_id,
            name=body.get("name"),
            description=body.get("description"),
            rules=body.get("rules"),
            mode=body.get("mode"),
            canary_pct=float(body["canary_pct"]) if "canary_pct" in body else None,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.delete("/policies/{policy_id}",
    dependencies=[Depends(require_feature("ent.enforcement_plane"))],
)
async def api_ep_deactivate_policy(
    policy_id: str,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    enforcement_plane.init_db()
    try:
        return enforcement_plane.deactivate_policy(policy_id, tenant.tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/evaluate",
    dependencies=[Depends(require_feature("ent.enforcement_plane"))],
)
async def api_ep_evaluate(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Evaluate a pending agent action against all policies."""
    enforcement_plane.init_db()
    agent_id = str(body.get("agent_id") or "")
    action_type = str(body.get("action_type") or "")
    if not agent_id or not action_type:
        raise HTTPException(status_code=422, detail="agent_id and action_type are required")
    return enforcement_plane.evaluate(
        tenant.tenant_id,
        agent_id,
        action_type,
        resource=str(body.get("resource") or ""),
        context=body.get("context") or {},
    )


@router.get("/decisions",
    dependencies=[Depends(require_feature("ent.enforcement_plane"))],
)
async def api_ep_decisions(
    agent_id: str | None = None,
    decision: str | None = None,
    limit: int = 100,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    enforcement_plane.init_db()
    return {"decisions": enforcement_plane.list_decisions(
        tenant.tenant_id, agent_id=agent_id, decision=decision, limit=min(limit, 500)
    )}


@router.get("/shadow/report",
    dependencies=[Depends(require_feature("ent.enforcement_plane"))],
)
async def api_ep_shadow_report(
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    enforcement_plane.init_db()
    return enforcement_plane.shadow_report(tenant.tenant_id)


@router.post("/killswitch/{agent_id}",
    dependencies=[Depends(require_feature("ent.enforcement_plane"))],
)
async def api_ep_kill_switch_activate(
    agent_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Activate kill switch for an agent."""
    enforcement_plane.init_db()
    activated_by = str(body.get("activated_by") or "")
    if not activated_by:
        raise HTTPException(status_code=422, detail="activated_by is required")
    try:
        return enforcement_plane.activate_kill_switch(
            tenant.tenant_id, agent_id, activated_by,
            reason=str(body.get("reason") or ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.delete("/killswitch/{agent_id}",
    dependencies=[Depends(require_feature("ent.enforcement_plane"))],
)
async def api_ep_kill_switch_deactivate(
    agent_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    enforcement_plane.init_db()
    deactivated_by = str(body.get("deactivated_by") or "")
    if not deactivated_by:
        raise HTTPException(status_code=422, detail="deactivated_by is required")
    try:
        return enforcement_plane.deactivate_kill_switch(tenant.tenant_id, agent_id, deactivated_by)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/killswitch",
    dependencies=[Depends(require_feature("ent.enforcement_plane"))],
)
async def api_ep_kill_switches_list(
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    enforcement_plane.init_db()
    return {"kill_switches": enforcement_plane.list_active_kill_switches(tenant.tenant_id)}


@router.get("/killswitch/{agent_id}",
    dependencies=[Depends(require_feature("ent.enforcement_plane"))],
)
async def api_ep_kill_switch_status(
    agent_id: str,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    enforcement_plane.init_db()
    return enforcement_plane.get_kill_switch_status(tenant.tenant_id, agent_id)


