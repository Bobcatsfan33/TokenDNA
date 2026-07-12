"""verifier domain router (T-1 decomposition).

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

router = APIRouter(prefix="", tags=["verifier"])


@router.post("/api/verifier/{verifier_id}/challenge")
async def api_issue_challenge(
    verifier_id: str,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """
    Issue a cryptographic challenge to a verifier.
    ADMIN role required. The challenge nonce is returned for delivery.
    """
    try:
        challenge = reputation_module.issue_challenge(
            verifier_id=verifier_id,
            tenant_id=tenant.tenant_id,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return {"challenge": challenge.to_dict()}


@router.post("/api/verifier/challenge/{challenge_id}/respond", dependencies=[Depends(check_rate_limit_open)])
async def api_resolve_challenge(
    challenge_id: str,
    request: Request,
    body: dict = Body(default={}),
):
    """Submit a verifier's response to a challenge. Open endpoint. Rate-limited by IP."""
    submitted = str(body.get("response", "")).strip()
    if not submitted:
        raise HTTPException(status_code=400, detail="'response' field is required")
    try:
        challenge = reputation_module.resolve_challenge(challenge_id, submitted)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    # If verifier proved key control, record it in the proof-of-control registry
    if challenge.outcome.value == "correct":
        try:
            from modules.identity import proof_of_control as _poc  # noqa: PLC0415
            _poc.init_db()
            _poc.record_proof(
                verifier_id=challenge.verifier_id,
                tenant_id=challenge.tenant_id,
            )
        except Exception:  # noqa: BLE001
            pass  # proof recording is best-effort; do not fail the response
    return {
        "challenge_id": challenge.challenge_id,
        "outcome": challenge.outcome.value,
        "response_ms": challenge.response_ms,
    }


@router.get("/api/verifier/{verifier_id}/reputation")
async def api_verifier_reputation(
    verifier_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    """Get current reputation score for a verifier."""
    rep = reputation_module.get_reputation(
        verifier_id=verifier_id,
        tenant_id=tenant.tenant_id,
    )
    history = reputation_module.get_challenge_history(
        verifier_id=verifier_id,
        tenant_id=tenant.tenant_id,
        limit=20,
    )
    return {
        "reputation": rep.to_dict(),
        "recent_challenges": history,
    }


@router.get("/api/verifier/reputation/leaderboard")
async def api_reputation_leaderboard(
    limit: int = 20,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Reputation leaderboard: verifiers ranked by effective reputation score."""
    board = reputation_module.get_leaderboard(
        tenant_id=tenant.tenant_id,
        limit=min(limit, 100),
    )
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(board),
        "leaderboard": board,
    }


@router.get("/api/verifier/reputation/anomalies")
async def api_reputation_anomalies(
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Return verifiers with anomalous reputation signals."""
    anomalies = reputation_module.get_reputation_anomalies(
        tenant_id=tenant.tenant_id,
    )
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(anomalies),
        "anomalies": anomalies,
    }


@router.post("/api/verifier/reputation/quorum")
async def api_reputation_quorum(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(get_tenant),
):
    """
    Evaluate a reputation-weighted quorum from a set of verifier attestations.
    Supersedes /api/federation/quorum with live reputation scores.
    """
    attestations = body.get("attestations") or []
    if not isinstance(attestations, list):
        raise HTTPException(status_code=400, detail="'attestations' must be a list")
    min_weight = float(body.get("min_weight", 0.6))
    min_verifiers = int(body.get("min_verifiers", 1))
    min_reputation = float(body.get("min_reputation", 0.3))

    verdict = reputation_module.evaluate_reputation_weighted_quorum(
        attestations=attestations,
        tenant_id=tenant.tenant_id,
        min_weight=min_weight,
        min_verifiers=min_verifiers,
        min_reputation=min_reputation,
    )
    return {
        "quorum": {
            "met": verdict.met,
            "effective_action": verdict.effective_action,
            "confidence": verdict.confidence,
            "total_reputation_weight": verdict.total_reputation_weight,
            "passing_weight": verdict.passing_weight,
            "required_weight": verdict.required_weight,
            "participating_verifiers": verdict.participating_verifiers,
            "verdicts": verdict.verdicts,
        }
    }


@router.post("/api/verifier/reputation/expire-challenges")
async def api_expire_pending_challenges(
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Expire all pending challenges past their timeout window."""
    count = reputation_module.expire_pending_challenges(tenant_id=tenant.tenant_id)
    return {"expired": count}


@router.post("/api/verifier/reputation/sync-scores")
async def api_sync_static_scores(
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Push current reputation scores back to trust_federation_verifiers.trust_score."""
    count = reputation_module.sync_static_scores(tenant_id=tenant.tenant_id)
    return {"synced": count}


@router.get("/api/verifier/{verifier_id}/challenges")
async def api_verifier_challenge_history(
    verifier_id: str,
    limit: int = 50,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Full challenge history for a specific verifier."""
    history = reputation_module.get_challenge_history(
        verifier_id=verifier_id,
        tenant_id=tenant.tenant_id,
        limit=min(limit, 200),
    )
    return {
        "verifier_id": verifier_id,
        "count": len(history),
        "challenges": history,
    }


@router.get("/api/verifier/reputation/due-for-challenge")
async def api_due_for_challenge(
    max_age_hours: int = 24,
    limit: int = 50,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Return verifiers that haven't been challenged recently."""
    verifier_ids = reputation_module.get_verifiers_due_for_challenge(
        tenant_id=tenant.tenant_id,
        max_age_hours=max_age_hours,
        limit=min(limit, 200),
    )
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(verifier_ids),
        "verifier_ids": verifier_ids,
    }


