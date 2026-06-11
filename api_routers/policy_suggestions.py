"""policy-suggestions domain router (T-1 decomposition).

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

router = APIRouter(prefix="/api/policy/suggestions", tags=["policy-suggestions"])


@router.post("/analyze")
async def api_policy_suggestions_analyze(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """
    Run gap analysis over the lookback window and generate policy suggestions.

    Analyzes policy_guard violations and denied decisions, clusters failure
    patterns, and produces candidate policy amendments for operator review.

    Body params (all optional):
      lookback_hours: int  — analysis window (default 24)
      min_confidence: float — minimum confidence threshold (default 0.0)
      source_types: list[str] — limit to specific sources
    """
    policy_advisor.init_db()
    lookback_hours = int(body.get("lookback_hours", 24))
    min_confidence = float(body.get("min_confidence", 0.0))
    source_types = body.get("source_types") or None
    if source_types is not None and not isinstance(source_types, list):
        raise HTTPException(status_code=400, detail="'source_types' must be a list")
    return policy_advisor.analyze_and_generate(
        tenant_id=tenant.tenant_id,
        lookback_hours=max(1, min(lookback_hours, 8760)),
        min_confidence=min_confidence,
        source_types=source_types,
    )


@router.get("")
async def api_list_policy_suggestions(
    status: str | None = None,
    amendment_type: str | None = None,
    min_confidence: float = 0.0,
    limit: int = 50,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """
    List policy suggestions for this tenant.

    Query params:
      status: pending | approved | rejected | applied | superseded
      amendment_type: tighten_scope | add_restriction | revoke_permission |
                      add_monitoring | rate_limit | require_approval
      min_confidence: float (0.0-1.0)
      limit: int (max 200)
    """
    policy_advisor.init_db()
    suggestions = policy_advisor.list_suggestions(
        tenant_id=tenant.tenant_id,
        status=status,
        amendment_type=amendment_type,
        min_confidence=min_confidence,
        limit=min(limit, 200),
    )
    return {
        "suggestions": [
            {
                "suggestion_id": s.suggestion_id,
                "source_type": s.source_type.value,
                "gap_description": s.gap_description,
                "amendment_type": s.amendment_type.value,
                "amendment": s.amendment,
                "confidence": s.confidence,
                "status": s.status.value,
                "evidence_count": len(s.evidence_ids),
                "evidence_ids": s.evidence_ids,
                "created_at": s.created_at,
                "reviewed_at": s.reviewed_at,
                "reviewed_by": s.reviewed_by,
                "review_note": s.review_note,
                "regression_tested": s.regression_tested,
                "regression_passed": s.regression_passed,
            }
            for s in suggestions
        ],
        "count": len(suggestions),
    }


@router.get("/stats")
async def api_policy_suggestion_stats(
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """Summary statistics for this tenant's policy suggestions."""
    policy_advisor.init_db()
    return policy_advisor.suggestion_stats(tenant_id=tenant.tenant_id)


@router.get("/{suggestion_id}")
async def api_get_policy_suggestion(
    suggestion_id: str,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """Get a single policy suggestion by ID."""
    policy_advisor.init_db()
    s = policy_advisor.get_suggestion(
        suggestion_id=suggestion_id,
        tenant_id=tenant.tenant_id,
    )
    if not s:
        raise HTTPException(status_code=404, detail="Suggestion not found")
    return {
        "suggestion_id": s.suggestion_id,
        "tenant_id": s.tenant_id,
        "source_type": s.source_type.value,
        "gap_description": s.gap_description,
        "amendment_type": s.amendment_type.value,
        "amendment": s.amendment,
        "confidence": s.confidence,
        "status": s.status.value,
        "evidence_ids": s.evidence_ids,
        "created_at": s.created_at,
        "reviewed_at": s.reviewed_at,
        "reviewed_by": s.reviewed_by,
        "review_note": s.review_note,
        "regression_tested": s.regression_tested,
        "regression_passed": s.regression_passed,
        "regression_result": s.regression_result,
        "metadata": s.metadata,
    }


@router.post("/{suggestion_id}/approve")
async def api_approve_policy_suggestion(
    suggestion_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """
    Operator approves a pending policy suggestion.

    Runs regression gate by default; set run_regression=false to skip.
    On regression failure, the suggestion remains pending with failure details attached.

    Body params:
      approved_by: str (required)
      note: str (optional)
      run_regression: bool (default true)
    """
    policy_advisor.init_db()
    approved_by = str(body.get("approved_by", "")).strip()
    if not approved_by:
        raise HTTPException(status_code=400, detail="'approved_by' is required")
    note = str(body.get("note", ""))
    run_regression = bool(body.get("run_regression", True))
    s = policy_advisor.approve_suggestion(
        suggestion_id=suggestion_id,
        tenant_id=tenant.tenant_id,
        approved_by=approved_by,
        note=note,
        run_regression=run_regression,
    )
    if not s:
        raise HTTPException(
            status_code=404,
            detail="Suggestion not found or not in 'pending' status",
        )
    return {
        "suggestion_id": s.suggestion_id,
        "status": s.status.value,
        "regression_tested": s.regression_tested,
        "regression_passed": s.regression_passed,
        "regression_result": s.regression_result,
        "reviewed_by": s.reviewed_by,
        "reviewed_at": s.reviewed_at,
        "review_note": s.review_note,
    }


@router.post("/{suggestion_id}/reject")
async def api_reject_policy_suggestion(
    suggestion_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """
    Operator rejects a pending policy suggestion.

    Body params:
      rejected_by: str (required)
      note: str (optional)
    """
    policy_advisor.init_db()
    rejected_by = str(body.get("rejected_by", "")).strip()
    if not rejected_by:
        raise HTTPException(status_code=400, detail="'rejected_by' is required")
    note = str(body.get("note", ""))
    s = policy_advisor.reject_suggestion(
        suggestion_id=suggestion_id,
        tenant_id=tenant.tenant_id,
        rejected_by=rejected_by,
        note=note,
    )
    if not s:
        raise HTTPException(
            status_code=404,
            detail="Suggestion not found or not in 'pending' status",
        )
    return {
        "suggestion_id": s.suggestion_id,
        "status": s.status.value,
        "rejected_by": s.reviewed_by,
        "reviewed_at": s.reviewed_at,
        "review_note": s.review_note,
    }


@router.post("/auto-tighten")
async def api_policy_auto_tighten(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """
    Bounded auto-tightening: automatically approve high-confidence suggestions
    within operator-defined confidence interval.

    Body params:
      confidence_threshold: float (default 0.85)
      max_amendments_per_run: int (default 5, max 20)
    """
    policy_advisor.init_db()
    confidence_threshold = float(body.get("confidence_threshold", 0.85))
    max_amendments = min(int(body.get("max_amendments_per_run", 5)), 20)
    if not (0.0 <= confidence_threshold <= 1.0):
        raise HTTPException(
            status_code=400, detail="'confidence_threshold' must be between 0.0 and 1.0"
        )
    return policy_advisor.bounded_auto_tighten(
        tenant_id=tenant.tenant_id,
        confidence_threshold=confidence_threshold,
        max_amendments_per_run=max_amendments,
    )


