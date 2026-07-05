"""passport domain router (T-1 decomposition).

Handlers MOVED VERBATIM from api.py (decorator-only change). Route surface
unchanged (scripts/ci/openapi_route_guard.py). Imports copied from api.py
(ruff ignores unused F401) so every handler resolves.
"""
from __future__ import annotations

from fastapi import APIRouter

from api_routers._shared import check_rate_limit_open

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

router = APIRouter(prefix="", tags=["passport"])


@router.post("/api/passport/request")
async def api_passport_request(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(get_tenant),
):
    """
    Submit a passport issuance request.
    Creates the passport in PENDING state; operator must approve.
    """
    agent_id = str(body.get("agent_id", "")).strip()
    owner_org = str(body.get("owner_org", "")).strip()
    display_name = str(body.get("display_name", "")).strip()
    agent_dna_fingerprint = str(body.get("agent_dna_fingerprint", "")).strip()
    permissions = body.get("permissions") or []
    resource_patterns = body.get("resource_patterns") or []
    requested_by = str(body.get("requested_by", "api")).strip()

    if not all([agent_id, owner_org, display_name, agent_dna_fingerprint]):
        raise HTTPException(
            status_code=400,
            detail="agent_id, owner_org, display_name, agent_dna_fingerprint are required",
        )
    if not permissions:
        raise HTTPException(status_code=400, detail="permissions list is required")

    try:
        p = passport_module.request_passport(
            tenant_id=tenant.tenant_id,
            agent_id=agent_id,
            owner_org=owner_org,
            display_name=display_name,
            agent_dna_fingerprint=agent_dna_fingerprint,
            permissions=permissions,
            resource_patterns=resource_patterns,
            requested_by=requested_by,
            model_fingerprint=body.get("model_fingerprint"),
            delegation_depth=int(body.get("delegation_depth", 0)),
            custom_claims=body.get("custom_claims"),
            validity_days=body.get("validity_days"),
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {"passport": p.to_dict()}


@router.post("/api/passport/{passport_id}/approve")
async def api_passport_approve(
    passport_id: str,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Approve a PENDING passport (ADMIN role required)."""
    try:
        p = passport_module.approve_passport(passport_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"passport": p.to_dict()}


@router.post("/api/passport/{passport_id}/issue")
async def api_passport_issue(
    passport_id: str,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Issue (sign) an APPROVED passport (ADMIN role required)."""
    try:
        p = passport_module.issue_passport(passport_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"passport": p.to_dict()}


@router.post("/api/passport/{passport_id}/revoke")
async def api_passport_revoke(
    passport_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Revoke an ISSUED or APPROVED passport (ADMIN role required)."""
    reason = str(body.get("reason", "operator_revoked")).strip()
    try:
        p = passport_module.revoke_passport(passport_id, reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"passport": p.to_dict()}


@router.post("/api/passport/verify", dependencies=[Depends(check_rate_limit_open)])
async def api_passport_verify(
    request: Request,
    body: dict = Body(default={}),
):
    """
    Verify a passport bundle. Open endpoint — no auth required.
    Third-party integrators call this to validate a passport presented by an agent.
    Rate-limited by IP (RATE_LIMIT_OPEN_PER_MINUTE, default 30/min).
    """
    result = passport_module.verify_passport(body)
    status_code = 200 if result["valid"] else 401
    from fastapi.responses import JSONResponse  # noqa: PLC0415
    return JSONResponse(content=result, status_code=status_code)


@router.get("/api/passport/{passport_id}")
async def api_passport_get(
    passport_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    """Retrieve a passport by ID."""
    p = passport_module.get_passport(passport_id)
    if p is None:
        raise HTTPException(status_code=404, detail="Passport not found")
    return {"passport": p.to_dict()}


@router.get("/api/passport/{passport_id}/status", dependencies=[Depends(check_rate_limit_open)])
async def api_passport_status_check(
    passport_id: str,
    request: Request,
):
    """
    Revocation check endpoint (public). Returns minimal status.
    Used as the revocation_url target in issued passports.
    Rate-limited by IP (RATE_LIMIT_OPEN_PER_MINUTE, default 30/min).
    """
    p = passport_module.get_passport(passport_id)
    if p is None:
        raise HTTPException(status_code=404, detail="Passport not found")
    return {
        "passport_id": passport_id,
        "status": p.status.value,
        "revoked_at": p.revoked_at,
        "revocation_reason": p.revocation_reason,
        "not_after": p.not_after,
    }


@router.get("/api/passports")
async def api_passports_list(
    agent_id: str | None = None,
    status: str | None = None,
    limit: int = 50,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """List passports for this tenant (ANALYST+ required)."""
    passports = passport_module.list_passports(
        tenant_id=tenant.tenant_id,
        agent_id=agent_id,
        status=status,
        limit=min(limit, 200),
    )
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(passports),
        "passports": [p.to_dict() for p in passports],
    }


@router.post("/api/passport/{passport_id}/evidence")
async def api_passport_submit_evidence(
    passport_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(get_tenant),
):
    """Attach an evidence bundle to a pending passport."""
    evidence_type = str(body.get("evidence_type", "manual")).strip()
    evidence_ref = str(body.get("evidence_ref", "")).strip()
    if not evidence_ref:
        raise HTTPException(status_code=400, detail="evidence_ref is required")
    submitted_by = str(body.get("submitted_by", "api")).strip()

    try:
        ev = passport_module.submit_evidence(
            passport_id=passport_id,
            tenant_id=tenant.tenant_id,
            submitted_by=submitted_by,
            evidence_type=evidence_type,
            evidence_ref=evidence_ref,
            notes=body.get("notes"),
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {"evidence": ev.__dict__}


@router.get("/api/passport/{passport_id}/evidence")
async def api_passport_list_evidence(
    passport_id: str,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """List evidence bundles for a passport (ANALYST+ required)."""
    evidence = passport_module.list_evidence(passport_id)
    return {
        "passport_id": passport_id,
        "count": len(evidence),
        "evidence": [e.__dict__ for e in evidence],
    }


@router.get("/api/passport/integrations/playbooks")
async def api_passport_playbooks_list():
    """List available cross-vendor integration playbooks."""
    return {"playbooks": passport_module.list_integration_playbooks()}


@router.get("/api/passport/integrations/playbook/{vendor}")
async def api_passport_playbook_detail(vendor: str):
    """Return detailed integration playbook for a specific vendor."""
    try:
        playbook = passport_module.get_integration_playbook(vendor)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"playbook": playbook}


