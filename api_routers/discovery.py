"""discovery domain router (T-1 decomposition).

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

router = APIRouter(prefix="", tags=["discovery"])


@router.post("/api/discovery/agents/register",
    dependencies=[Depends(require_feature("ent.agent_discovery"))],
)
async def api_discovery_register(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Register an agent in the inventory."""
    agent_discovery.init_db()
    name = str(body.get("name") or "")
    provider = str(body.get("provider") or "")
    if not name or not provider:
        raise HTTPException(status_code=422, detail="name and provider are required")
    try:
        return agent_discovery.register_agent(
            tenant_id=tenant.tenant_id,
            name=name,
            provider=provider,
            model=str(body.get("model") or ""),
            endpoint_url=str(body.get("endpoint_url") or ""),
            tools=body.get("tools") or [],
            permissions=body.get("permissions") or {},
            owner_id=str(body.get("owner_id") or ""),
            external_id=str(body.get("external_id") or ""),
            metadata=body.get("metadata") or {},
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/api/discovery/agents",
    dependencies=[Depends(require_feature("ent.agent_discovery"))],
)
async def api_discovery_census(
    status: str | None = None,
    provider: str | None = None,
    discovery_method: str | None = None,
    owner_id: str | None = None,
    limit: int = 100,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Agent census — full inventory for this tenant."""
    agent_discovery.init_db()
    agents = agent_discovery.list_agents(
        tenant.tenant_id,
        status=status,
        provider=provider,
        discovery_method=discovery_method,
        owner_id=owner_id,
        limit=min(limit, 500),
    )
    summary = agent_discovery.census_summary(tenant.tenant_id)
    return {"summary": summary, "agents": agents}


@router.get("/api/discovery/agents/summary",
    dependencies=[Depends(require_feature("ent.agent_discovery"))],
)
async def api_discovery_summary(
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """High-level census summary only."""
    agent_discovery.init_db()
    return agent_discovery.census_summary(tenant.tenant_id)


@router.get("/api/discovery/agents/{agent_id}",
    dependencies=[Depends(require_feature("ent.agent_discovery"))],
)
async def api_discovery_get_agent(
    agent_id: str,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Single agent detail."""
    agent_discovery.init_db()
    try:
        return agent_discovery.get_agent(agent_id, tenant.tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/api/discovery/agents/{agent_id}")
async def api_discovery_update_agent(
    agent_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Update mutable agent fields."""
    agent_discovery.init_db()
    try:
        return agent_discovery.update_agent(
            agent_id,
            tenant.tenant_id,
            name=body.get("name"),
            model=body.get("model"),
            endpoint_url=body.get("endpoint_url"),
            tools=body.get("tools"),
            permissions=body.get("permissions"),
            owner_id=body.get("owner_id"),
            metadata=body.get("metadata"),
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/discovery/agents/{agent_id}/activity",
    dependencies=[Depends(require_feature("ent.agent_discovery"))],
)
async def api_discovery_record_activity(
    agent_id: str,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Record agent activity (heartbeat); auto-transitions provisioned → active."""
    agent_discovery.init_db()
    agent_discovery.record_activity(agent_id, tenant.tenant_id)
    try:
        return agent_discovery.get_agent(agent_id, tenant.tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/discovery/agents/{agent_id}/lifecycle",
    dependencies=[Depends(require_feature("ent.agent_discovery"))],
)
async def api_discovery_lifecycle_transition(
    agent_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Transition agent lifecycle state."""
    agent_discovery.init_db()
    to_status = str(body.get("to_status") or "")
    actor_id = str(body.get("actor_id") or "")
    if not to_status or not actor_id:
        raise HTTPException(status_code=422, detail="to_status and actor_id are required")
    try:
        return agent_discovery.transition_lifecycle(
            agent_id,
            tenant.tenant_id,
            to_status,
            actor_id,
            reason=str(body.get("reason") or ""),
            approved_by=body.get("approved_by"),
        )
    except (KeyError, ValueError) as exc:
        status_code = 404 if isinstance(exc, KeyError) else 422
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc


@router.get("/api/discovery/agents/{agent_id}/lifecycle",
    dependencies=[Depends(require_feature("ent.agent_discovery"))],
)
async def api_discovery_lifecycle_history(
    agent_id: str,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Lifecycle event history for an agent."""
    agent_discovery.init_db()
    return {"history": agent_discovery.get_lifecycle_history(agent_id, tenant.tenant_id)}


@router.post("/api/discovery/scan",
    dependencies=[Depends(require_feature("ent.agent_discovery"))],
)
async def api_discovery_scan(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Trigger a provider scan."""
    agent_discovery.init_db()
    provider = str(body.get("provider") or "")
    if not provider:
        raise HTTPException(status_code=422, detail="provider is required")
    credentials = body.get("credentials") or {}
    try:
        return agent_discovery.run_scan(tenant.tenant_id, provider, credentials)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/api/discovery/scans",
    dependencies=[Depends(require_feature("ent.agent_discovery"))],
)
async def api_discovery_list_scans(
    provider: str | None = None,
    limit: int = 50,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """List recent provider scans."""
    agent_discovery.init_db()
    return {"scans": agent_discovery.list_scans(tenant.tenant_id, provider=provider, limit=min(limit, 200))}


@router.get("/api/discovery/scans/{scan_id}",
    dependencies=[Depends(require_feature("ent.agent_discovery"))],
)
async def api_discovery_get_scan(
    scan_id: str,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Single scan result."""
    agent_discovery.init_db()
    try:
        return agent_discovery.get_scan(scan_id, tenant.tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/api/discovery/shadow",
    dependencies=[Depends(require_feature("ent.agent_discovery"))],
)
async def api_discovery_shadow_alerts(
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """List unacknowledged shadow agent alerts."""
    agent_discovery.init_db()
    return {"alerts": agent_discovery.list_shadow_alerts(tenant.tenant_id)}


@router.post("/api/discovery/shadow/{alert_id}/acknowledge",
    dependencies=[Depends(require_feature("ent.agent_discovery"))],
)
async def api_discovery_ack_shadow(
    alert_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Acknowledge a shadow agent alert."""
    agent_discovery.init_db()
    acknowledged_by = str(body.get("acknowledged_by") or tenant.tenant_id)
    try:
        return agent_discovery.acknowledge_shadow_alert(tenant.tenant_id, alert_id, acknowledged_by)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


