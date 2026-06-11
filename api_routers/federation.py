"""federation domain router (T-1 decomposition).

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

router = APIRouter(prefix="", tags=["federation"])


@router.post("/api/federation/verifiers")
async def api_upsert_federation_verifier(
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    name = str(body.get("name", "")).strip()
    issuer = str(body.get("issuer", "")).strip()
    if not name or not issuer:
        raise HTTPException(status_code=400, detail="'name' and 'issuer' are required")
    verifier = trust_federation.upsert_verifier(
        tenant_id=tenant.tenant_id,
        verifier_id=(str(body.get("verifier_id", "")).strip() or None),
        name=name,
        trust_score=float(body.get("trust_score", 0.7)),
        issuer=issuer,
        jwks_uri=(str(body.get("jwks_uri", "")).strip() or None),
        metadata=(body.get("metadata") if isinstance(body.get("metadata"), dict) else {}),
        status=str(body.get("status", "active")).strip().lower(),
    )
    return {"tenant_id": tenant.tenant_id, "verifier": verifier}


@router.post("/api/federation/verifiers/{verifier_id}/revoke")
async def api_revoke_federation_verifier(
    verifier_id: str,
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.OWNER)),
):
    reason = str(body.get("reason", "")).strip() or "manual_revoke"
    verifier = trust_federation.revoke_verifier(
        tenant_id=tenant.tenant_id,
        verifier_id=verifier_id,
        actor=tenant.api_key_id,
        reason=reason,
    )
    if verifier is None:
        raise HTTPException(status_code=404, detail="Verifier not found")
    return {"tenant_id": tenant.tenant_id, "verifier": verifier}


@router.post("/api/federation/verifiers/{verifier_id}/rotate")
async def api_rotate_federation_verifier_key(
    verifier_id: str,
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.OWNER)),
):
    key_version = str(body.get("key_version", "")).strip()
    if not key_version:
        raise HTTPException(status_code=400, detail="'key_version' is required")
    verifier = trust_federation.rotate_verifier_key(
        tenant_id=tenant.tenant_id,
        verifier_id=verifier_id,
        actor=tenant.api_key_id,
        key_version=key_version,
        key_expires_at=(str(body.get("key_expires_at", "")).strip() or None),
    )
    if verifier is None:
        raise HTTPException(status_code=404, detail="Verifier not found")
    return {"tenant_id": tenant.tenant_id, "verifier": verifier}


@router.get("/api/federation/verifiers/{verifier_id}/lifecycle")
async def api_get_federation_verifier_lifecycle(
    verifier_id: str,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    lifecycle = trust_federation.verifier_lifecycle_status(
        tenant_id=tenant.tenant_id,
        verifier_id=verifier_id,
    )
    if lifecycle is None:
        raise HTTPException(status_code=404, detail="Verifier not found")
    return {"tenant_id": tenant.tenant_id, "lifecycle": lifecycle}


@router.get("/api/federation/verifiers")
async def api_list_federation_verifiers(
    status: str | None = None,
    limit: int = 100,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    verifiers = trust_federation.list_verifiers(
        tenant_id=tenant.tenant_id,
        status=status,
        limit=min(max(limit, 1), 200),
    )
    return {"tenant_id": tenant.tenant_id, "count": len(verifiers), "verifiers": verifiers}


@router.post("/api/federation/attestations")
async def api_issue_federation_attestation(
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    verifier_id = str(body.get("verifier_id", "")).strip()
    target_type = str(body.get("target_type", "")).strip()
    target_id = str(body.get("target_id", "")).strip()
    verdict = str(body.get("verdict", "allow")).strip().lower()
    if not verifier_id or not target_type or not target_id:
        raise HTTPException(status_code=400, detail="'verifier_id', 'target_type', and 'target_id' are required")
    attestation = trust_federation.issue_federation_attestation(
        tenant_id=tenant.tenant_id,
        verifier_id=verifier_id,
        target_type=target_type,
        target_id=target_id,
        verdict=verdict,
        confidence=float(body.get("confidence", 0.7)),
        expires_at=(str(body.get("expires_at", "")).strip() or None),
        metadata=(body.get("metadata") if isinstance(body.get("metadata"), dict) else {}),
        key_id=(str(body.get("key_id", "")).strip() or None),
        algorithm=str(body.get("algorithm", "HS256")).strip().upper(),
    )
    verification = trust_federation.verify_attestation_signature(attestation)
    return {"tenant_id": tenant.tenant_id, "attestation": attestation, "verification": verification}


@router.get("/api/federation/attestations")
async def api_list_federation_attestations(
    target_type: str | None = None,
    target_id: str | None = None,
    verifier_id: str | None = None,
    limit: int = 100,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    rows = trust_federation.list_federation_attestations(
        tenant_id=tenant.tenant_id,
        target_type=target_type,
        target_id=target_id,
        verifier_id=verifier_id,
        limit=min(max(limit, 1), 200),
    )
    return {"tenant_id": tenant.tenant_id, "count": len(rows), "attestations": rows}


@router.post("/api/federation/quorum/evaluate")
async def api_evaluate_federation_quorum(
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    target_type = str(body.get("target_type", "")).strip()
    target_id = str(body.get("target_id", "")).strip()
    if not target_type or not target_id:
        raise HTTPException(status_code=400, detail="'target_type' and 'target_id' are required")
    result = trust_federation.evaluate_federation_quorum(
        tenant_id=tenant.tenant_id,
        target_type=target_type,
        target_id=target_id,
        min_verifiers=max(1, int(body.get("min_verifiers", 2))),
        min_trust_score=max(0.0, min(float(body.get("min_trust_score", 0.6)), 1.0)),
        min_confidence=max(0.0, min(float(body.get("min_confidence", 0.6)), 1.0)),
    )
    return {"tenant_id": tenant.tenant_id, "quorum": result}


@router.get("/api/federation/verifiers/{verifier_id}/proof-status")
async def api_proof_status(
    verifier_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    """
    Get the current proof-of-control status for a verifier.

    Returns: proof_interval_hours, last_proof_at, next_proof_due,
             status (current | overdue | expired | never_proved),
             consecutive_misses.
    """
    poc_module.init_db()
    record = poc_module.get_proof_status(verifier_id, tenant.tenant_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Verifier not registered in proof-of-control registry. "
                   "POST to /proof-interval to register.",
        )
    return {
        "verifier_id": record.verifier_id,
        "tenant_id": record.tenant_id,
        "interval_hours": record.interval_hours,
        "last_proof_at": record.last_proof_at,
        "next_proof_due": record.next_proof_due,
        "status": record.status.value,
        "consecutive_misses": record.consecutive_misses,
        "updated_at": record.updated_at,
    }


@router.post("/api/federation/verifiers/{verifier_id}/proof-interval")
async def api_set_proof_interval(
    verifier_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """
    Register or update the proof-of-control interval for a verifier.
    Creates the entry if it doesn't exist (idempotent).

    Body:
      interval_hours: int (1–168, default 24)
    """
    poc_module.init_db()
    interval_hours = int(body.get("interval_hours", poc_module._DEFAULT_INTERVAL_HOURS))
    record = poc_module.set_proof_interval(
        verifier_id=verifier_id,
        tenant_id=tenant.tenant_id,
        interval_hours=interval_hours,
    )
    return {
        "verifier_id": record.verifier_id,
        "interval_hours": record.interval_hours,
        "status": record.status.value,
        "next_proof_due": record.next_proof_due,
    }


@router.post("/api/federation/verifiers/proof-sweep")
async def api_proof_sweep(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """
    Run the proof-of-control sweep for this tenant.

    Demotes verifiers past their proof interval to 'unverified' in
    trust_federation and updates proof status. Optionally issues new
    challenges to OVERDUE verifiers.

    Body:
      auto_issue_challenges: bool (default true)
    """
    poc_module.init_db()
    auto_issue = bool(body.get("auto_issue_challenges", True))
    result = poc_module.sweep_expired_proofs(
        tenant_id=tenant.tenant_id,
        auto_issue_challenges=auto_issue,
    )
    return {
        "swept_at": result.swept_at,
        "total_checked": result.total_checked,
        "newly_overdue": result.newly_overdue,
        "newly_expired": result.newly_expired,
        "demoted_in_federation": result.demoted_in_federation,
        "demoted_ids": result.demoted_ids,
        "promoted_ids": result.promoted_ids,
        "challenges_issued": result.challenges_issued,
    }


@router.post("/api/federation/verifiers/proof-renew-all")
async def api_proof_renew_all(
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """
    Batch-issue proof-of-control challenges to all OVERDUE and NEVER_PROVED
    verifiers. Does not demote — use proof-sweep for demotion.
    """
    poc_module.init_db()
    result = poc_module.renew_all_overdue(tenant_id=tenant.tenant_id)
    return result


@router.get("/api/federation/verifiers/proof-registry")
async def api_proof_registry(
    status: str | None = None,
    limit: int = 100,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """
    List all registered verifiers and their proof-of-control status.

    Query params:
      status: current | overdue | expired | never_proved (optional filter)
      limit: max results (default 100, max 500)
    """
    poc_module.init_db()
    records = poc_module.list_proof_registry(
        tenant_id=tenant.tenant_id,
        status=status,
        limit=min(limit, 500),
    )
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(records),
        "registry": [
            {
                "verifier_id": r.verifier_id,
                "interval_hours": r.interval_hours,
                "last_proof_at": r.last_proof_at,
                "next_proof_due": r.next_proof_due,
                "status": r.status.value,
                "consecutive_misses": r.consecutive_misses,
            }
            for r in records
        ],
    }


@router.get("/api/federation/verifiers/proof-stats")
async def api_proof_stats(
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Summary statistics for proof-of-control status across all verifiers."""
    poc_module.init_db()
    return poc_module.proof_stats(tenant_id=tenant.tenant_id)


