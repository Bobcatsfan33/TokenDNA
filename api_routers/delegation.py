"""delegation domain router (T-1 decomposition).

Handlers MOVED VERBATIM from api.py (decorator-only change). Route surface
unchanged (scripts/ci/openapi_route_guard.py). Imports copied from api.py
(ruff ignores unused F401) so every handler resolves.
"""
from __future__ import annotations

from fastapi import APIRouter

from api_routers._shared import _delegation_error_to_http

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

router = APIRouter(prefix="", tags=["delegation"])


@router.post("/api/delegation/receipt")
async def api_delegation_issue(
    body: dict,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """Issue a signed delegation receipt."""
    from modules.identity import delegation_receipt  # noqa: PLC0415
    delegator_id = str(body.get("delegator_id") or "").strip()
    delegatee_id = str(body.get("delegatee_id") or "").strip()
    scope = body.get("scope")
    expires_in = body.get("expires_in_seconds")
    parent = body.get("parent_receipt_id")
    ceiling = body.get("ceiling")
    if not delegator_id or not delegatee_id:
        raise HTTPException(status_code=400,
                            detail="'delegator_id' and 'delegatee_id' are required")
    if not isinstance(scope, list):
        raise HTTPException(status_code=400, detail="'scope' must be a list")
    try:
        expires_in = int(expires_in)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400,
                            detail="'expires_in_seconds' must be an integer") from None
    try:
        receipt = delegation_receipt.issue_receipt(
            tenant_id=tenant.tenant_id,
            delegator_id=delegator_id,
            delegatee_id=delegatee_id,
            scope=scope,
            expires_in_seconds=expires_in,
            parent_receipt_id=parent or None,
            ceiling=ceiling if isinstance(ceiling, dict) else None,
        )
        return receipt.as_dict()
    except delegation_receipt.DelegationError as exc:
        raise _delegation_error_to_http(exc) from exc


@router.get("/api/delegation/receipt/{receipt_id}")
async def api_delegation_get(
    receipt_id: str,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    from modules.identity import delegation_receipt  # noqa: PLC0415
    receipt = delegation_receipt.get_receipt(receipt_id, tenant_id=tenant.tenant_id)
    if not receipt:
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    return receipt.as_dict()


@router.get("/api/delegation/receipt/{receipt_id}/verify")
async def api_delegation_verify(
    receipt_id: str,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    from modules.identity import delegation_receipt  # noqa: PLC0415
    return delegation_receipt.verify_receipt(
        receipt_id, tenant_id=tenant.tenant_id
    ).as_dict()


@router.get("/api/delegation/chain/{receipt_id}")
async def api_delegation_chain(
    receipt_id: str,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    from modules.identity import delegation_receipt  # noqa: PLC0415
    chain = delegation_receipt.get_chain(receipt_id, tenant_id=tenant.tenant_id)
    if not chain:
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    return {
        "receipt_id": receipt_id,
        "depth": chain[-1].depth,
        "human_principal_id": chain[-1].human_principal_id,
        "chain": [r.as_dict() for r in chain],
    }


@router.get("/api/delegation/receipts/{agent_id}")
async def api_delegation_receipts_for_agent(
    agent_id: str,
    include_revoked: bool = False,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    from modules.identity import delegation_receipt  # noqa: PLC0415
    receipts = delegation_receipt.get_receipts_for_agent(
        tenant_id=tenant.tenant_id,
        agent_id=agent_id,
        include_revoked=include_revoked,
    )
    return {
        "tenant_id": tenant.tenant_id,
        "agent_id": agent_id,
        "count": len(receipts),
        "receipts": [r.as_dict() for r in receipts],
    }


@router.post("/api/delegation/receipt/{receipt_id}/revoke")
async def api_delegation_revoke(
    receipt_id: str,
    body: dict,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    from modules.identity import delegation_receipt  # noqa: PLC0415
    revoked_by = str(body.get("revoked_by") or "").strip()
    if not revoked_by:
        raise HTTPException(status_code=400, detail="'revoked_by' is required")
    cascade = bool(body.get("cascade", True))
    try:
        return delegation_receipt.revoke_receipt(
            receipt_id=receipt_id,
            revoked_by=revoked_by,
            cascade=cascade,
            tenant_id=tenant.tenant_id,
        )
    except delegation_receipt.DelegationError as exc:
        raise _delegation_error_to_http(exc) from exc


@router.get("/api/delegation/chain/{receipt_id}/report")
async def api_delegation_chain_report(
    receipt_id: str,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    from modules.identity import delegation_receipt  # noqa: PLC0415
    report = delegation_receipt.export_chain_report(receipt_id, tenant_id=tenant.tenant_id)
    if not report.get("found"):
        raise HTTPException(status_code=404, detail=report)
    return report


