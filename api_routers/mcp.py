"""mcp domain router (T-1 decomposition).

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
from modules.identity import async_pipeline, geo_intel, ml_model, scoring, session_graph, threat_intel
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

router = APIRouter(prefix="", tags=["mcp"])


@router.post("/api/mcp/verify")
async def api_mcp_verify(
    body: dict,
    tenant: TenantContext = Depends(require_feature("ent.mcp_gateway")),
):
    manifest = body.get("manifest")
    expected_manifest_hash = str(body.get("expected_manifest_hash") or "").strip()
    if not isinstance(manifest, dict):
        raise HTTPException(status_code=400, detail="'manifest' must be an object")
    if not expected_manifest_hash:
        raise HTTPException(status_code=400, detail="'expected_manifest_hash' is required")

    result = verify_mcp_server(
        manifest=manifest,
        expected_manifest_hash=expected_manifest_hash,
        observed_capabilities=list(body.get("observed_capabilities") or []),
        authorized_agent_ids=(list(body["authorized_agent_ids"]) if "authorized_agent_ids" in body else None),
        connecting_agent_id=body.get("connecting_agent_id"),
    )
    return {"tenant_id": tenant.tenant_id, "verification": result.to_dict()}


@router.post("/api/mcp/inspect")
async def api_mcp_inspect(
    body: dict = Body(...),
    tenant: TenantContext = Depends(require_feature("ent.mcp_gateway")),
):
    """
    Inspect a pending MCP tool call before execution.

    Returns: allowed (bool), risk_score, recommendation (allow/flag/block),
    violations list, and any matching chain attack patterns.
    """
    mcp_inspector.init_db()
    tool_name = str(body.get("tool_name", "")).strip()
    if not tool_name:
        raise HTTPException(status_code=400, detail="'tool_name' is required")
    session_id = str(body.get("session_id", "")).strip()
    if not session_id:
        raise HTTPException(status_code=400, detail="'session_id' is required")
    return mcp_inspector.inspect_call(
        tenant_id=tenant.tenant_id,
        session_id=session_id,
        tool_name=tool_name,
        params=dict(body.get("params", {})),
        agent_id=body.get("agent_id"),
        declared_intent=body.get("declared_intent"),
    )


@router.post("/api/mcp/tools/register")
async def api_mcp_register_tool(
    body: dict = Body(...),
    tenant: TenantContext = Depends(require_feature("ent.mcp_gateway")),
):
    """Register or update a tool intent profile."""
    mcp_inspector.init_db()
    tool_name = str(body.get("tool_name", "")).strip()
    if not tool_name:
        raise HTTPException(status_code=400, detail="'tool_name' is required")
    access_mode = str(body.get("access_mode", "")).strip()
    if not access_mode:
        raise HTTPException(status_code=400, detail="'access_mode' is required")
    try:
        return mcp_inspector.register_tool(
            tenant_id=tenant.tenant_id,
            tool_name=tool_name,
            access_mode=access_mode,
            description=str(body.get("description", "")),
            allowed_params=list(body.get("allowed_params", [])),
            forbidden_params=list(body.get("forbidden_params", [])),
            param_constraints=dict(body.get("param_constraints", {})),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/mcp/tools")
async def api_mcp_list_tools(
    tenant: TenantContext = Depends(require_feature("ent.mcp_gateway")),
):
    """List all tool intent profiles available to this tenant."""
    mcp_inspector.init_db()
    return {"tools": mcp_inspector.list_tools(tenant_id=tenant.tenant_id)}


@router.get("/api/mcp/tools/{tool_name}")
async def api_mcp_get_tool(
    tool_name: str,
    tenant: TenantContext = Depends(require_feature("ent.mcp_gateway")),
):
    """Return a single tool intent profile."""
    mcp_inspector.init_db()
    profile = mcp_inspector.get_tool(tenant_id=tenant.tenant_id, tool_name=tool_name)
    if not profile:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_name}' not found")
    return profile


@router.get("/api/mcp/violations")
async def api_mcp_violations(
    resolved: bool | None = None,
    limit: int = 200,
    tenant: TenantContext = Depends(require_feature("ent.mcp_gateway")),
):
    """Return MCP violations for this tenant."""
    mcp_inspector.init_db()
    violations = mcp_inspector.list_violations(
        tenant_id=tenant.tenant_id,
        resolved=resolved,
        limit=limit,
    )
    return {"violations": violations, "count": len(violations)}


@router.post("/api/mcp/violations/{violation_id}/resolve")
async def api_mcp_resolve_violation(
    violation_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_feature("ent.mcp_gateway")),
):
    """Mark a violation as resolved."""
    mcp_inspector.init_db()
    resolved_by = str(body.get("resolved_by", "")).strip()
    if not resolved_by:
        raise HTTPException(status_code=400, detail="'resolved_by' is required")
    try:
        return mcp_inspector.resolve_violation(
            tenant_id=tenant.tenant_id,
            violation_id=violation_id,
            resolved_by=resolved_by,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/api/mcp/chain/{session_id}")
async def api_mcp_chain(
    session_id: str,
    limit: int = 200,
    tenant: TenantContext = Depends(require_feature("ent.mcp_gateway")),
):
    """Return the full tool-call chain for a session."""
    mcp_inspector.init_db()
    chain = mcp_inspector.get_chain(
        tenant_id=tenant.tenant_id,
        session_id=session_id,
        limit=limit,
    )
    return {"session_id": session_id, "chain": chain, "count": len(chain)}


@router.post("/api/mcp/gateway/session/open",
    dependencies=[Depends(require_feature("ent.mcp_gateway"))],
)
async def api_gw_open_session(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Open a gateway-managed MCP session."""
    mcp_gateway.init_db()
    agent_id = str(body.get("agent_id") or "")
    server_id = str(body.get("server_id") or "")
    if not agent_id or not server_id:
        raise HTTPException(status_code=422, detail="agent_id and server_id are required")
    return mcp_gateway.open_session(
        tenant_id=tenant.tenant_id,
        agent_id=agent_id,
        server_id=server_id,
        mode=str(body.get("mode") or "audit"),
        passport_id=body.get("passport_id"),
    )


@router.post("/api/mcp/gateway/session/close/{session_id}",
    dependencies=[Depends(require_feature("ent.mcp_gateway"))],
)
async def api_gw_close_session(
    session_id: str,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Close an open gateway session."""
    mcp_gateway.init_db()
    try:
        return mcp_gateway.close_session(session_id, tenant.tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/api/mcp/gateway/sessions",
    dependencies=[Depends(require_feature("ent.mcp_gateway"))],
)
async def api_gw_list_sessions(
    status: str | None = None,
    agent_id: str | None = None,
    limit: int = 100,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """List gateway sessions for this tenant."""
    mcp_gateway.init_db()
    return {"sessions": mcp_gateway.list_sessions(tenant.tenant_id, status=status, agent_id=agent_id, limit=min(limit, 500))}


@router.get("/api/mcp/gateway/sessions/{session_id}",
    dependencies=[Depends(require_feature("ent.mcp_gateway"))],
)
async def api_gw_get_session(
    session_id: str,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Get a single gateway session."""
    mcp_gateway.init_db()
    try:
        return mcp_gateway.get_session(session_id, tenant.tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/mcp/gateway/enforce",
    dependencies=[Depends(require_feature("ent.mcp_gateway"))],
)
async def api_gw_enforce(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Gateway enforcement point — evaluate a pending tool call."""
    mcp_gateway.init_db()
    session_id = str(body.get("session_id") or "")
    tool_name = str(body.get("tool_name") or "")
    if not session_id or not tool_name:
        raise HTTPException(status_code=422, detail="session_id and tool_name are required")
    params = body.get("params") or {}
    if not isinstance(params, dict):
        params = {}
    try:
        return mcp_gateway.enforce(
            session_id,
            tenant.tenant_id,
            tool_name,
            params,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/api/mcp/gateway/enforcements",
    dependencies=[Depends(require_feature("ent.mcp_gateway"))],
)
async def api_gw_list_enforcements(
    session_id: str | None = None,
    outcome: str | None = None,
    limit: int = 100,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Enforcement log for this tenant."""
    mcp_gateway.init_db()
    return {"enforcements": mcp_gateway.list_enforcements(tenant.tenant_id, session_id=session_id, outcome=outcome, limit=min(limit, 500))}


@router.post("/api/mcp/gateway/session/{session_id}/bind",
    dependencies=[Depends(require_feature("ent.mcp_gateway"))],
)
async def api_gw_bind_passport(
    session_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Bind a TokenDNA Passport to a gateway session."""
    mcp_gateway.init_db()
    passport_id = str(body.get("passport_id") or "")
    if not passport_id:
        raise HTTPException(status_code=422, detail="passport_id is required")
    try:
        return mcp_gateway.bind_passport(session_id, tenant.tenant_id, passport_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/mcp/fingerprint/register",
    dependencies=[Depends(require_feature("ent.mcp_gateway"))],
)
async def api_gw_register_manifest(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Register or update a server's tool manifest for fingerprinting."""
    mcp_gateway.init_db()
    server_id = str(body.get("server_id") or "")
    tools = body.get("tools") or []
    if not server_id:
        raise HTTPException(status_code=422, detail="server_id is required")
    if not isinstance(tools, list):
        raise HTTPException(status_code=422, detail="tools must be a list")
    return mcp_gateway.register_manifest(tenant.tenant_id, server_id, tools)


@router.get("/api/mcp/fingerprint/alerts",
    dependencies=[Depends(require_feature("ent.mcp_gateway"))],
)
async def api_gw_fp_alerts(
    server_id: str | None = None,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """List unresolved tool manifest drift alerts."""
    mcp_gateway.init_db()
    return {"alerts": mcp_gateway.list_fingerprint_alerts(tenant.tenant_id, server_id=server_id)}


@router.get("/api/mcp/fingerprint/{server_id}",
    dependencies=[Depends(require_feature("ent.mcp_gateway"))],
)
async def api_gw_get_fingerprint(
    server_id: str,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Current fingerprint snapshot for a server."""
    mcp_gateway.init_db()
    return mcp_gateway.get_fingerprint(tenant.tenant_id, server_id)


@router.post("/api/mcp/fingerprint/alerts/{alert_id}/resolve",
    dependencies=[Depends(require_feature("ent.mcp_gateway"))],
)
async def api_gw_resolve_fp_alert(
    alert_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Resolve a tool manifest drift alert."""
    mcp_gateway.init_db()
    resolved_by = str(body.get("resolved_by") or tenant.tenant_id)
    try:
        return mcp_gateway.resolve_fingerprint_alert(tenant.tenant_id, alert_id, resolved_by)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/api/mcp/anomaly/baseline/{agent_id}",
    dependencies=[Depends(require_feature("ent.mcp_gateway"))],
)
async def api_gw_anomaly_baseline(
    agent_id: str,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Learned tool-call baseline for an agent."""
    mcp_gateway.init_db()
    return {"agent_id": agent_id, "baseline": mcp_gateway.get_anomaly_baseline(tenant.tenant_id, agent_id)}


@router.get("/api/mcp/anomaly/alerts",
    dependencies=[Depends(require_feature("ent.mcp_gateway"))],
)
async def api_gw_anomaly_alerts(
    agent_id: str | None = None,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Unacknowledged anomaly alerts."""
    mcp_gateway.init_db()
    return {"alerts": mcp_gateway.list_anomaly_alerts(tenant.tenant_id, agent_id=agent_id)}


@router.post("/api/mcp/anomaly/alerts/{alert_id}/acknowledge",
    dependencies=[Depends(require_feature("ent.mcp_gateway"))],
)
async def api_gw_ack_anomaly(
    alert_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Acknowledge an anomaly alert."""
    mcp_gateway.init_db()
    acknowledged_by = str(body.get("acknowledged_by") or tenant.tenant_id)
    try:
        return mcp_gateway.acknowledge_anomaly_alert(tenant.tenant_id, alert_id, acknowledged_by)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


