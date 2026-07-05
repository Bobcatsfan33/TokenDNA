"""intel domain router (T-1 decomposition).

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

router = APIRouter(prefix="", tags=["intel"])


@router.get("/api/intel/feed")
async def api_network_intel_feed(
    limit: int = 100,
    min_tenant_count: int = 2,
    min_confidence: float = 0.6,
    tenant: TenantContext = Depends(get_tenant),
):
    rows = network_intel.get_feed(
        limit=min(max(limit, 1), 500),
        min_tenant_count=max(min_tenant_count, 1),
        min_confidence=max(min(min_confidence, 1.0), 0.0),
    )
    return {"tenant_id": tenant.tenant_id, "count": len(rows), "feed": rows}


@router.post("/api/intel/record")
async def api_network_intel_record(
    body: dict,
    tenant: TenantContext = Depends(get_tenant),
):
    signal_type = str(body.get("signal_type", "")).strip()
    raw_value = str(body.get("raw_value", "")).strip()
    if not signal_type:
        raise HTTPException(status_code=400, detail="'signal_type' is required")
    if not raw_value:
        raise HTTPException(status_code=400, detail="'raw_value' is required")

    metadata = body.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise HTTPException(status_code=400, detail="'metadata' must be an object when provided")

    record = network_intel.record_signal(
        tenant_id=tenant.tenant_id,
        signal_type=signal_type,
        raw_value=raw_value,
        severity=str(body.get("severity") or "medium"),
        confidence=float(body.get("confidence", 0.5)),
        metadata=metadata,
    )
    return {"tenant_id": tenant.tenant_id, "signal": record}


@router.post("/api/intel/rules")
async def api_network_intel_upsert_rule(
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    signal_type = str(body.get("signal_type", "")).strip()
    raw_value = str(body.get("raw_value", "")).strip()
    mode = str(body.get("mode", "")).strip().lower()
    if not signal_type:
        raise HTTPException(status_code=400, detail="'signal_type' is required")
    if not raw_value:
        raise HTTPException(status_code=400, detail="'raw_value' is required")
    if mode not in {"suppress", "allow"}:
        raise HTTPException(status_code=400, detail="'mode' must be suppress or allow")
    usage = feature_metering.record_usage(
        tenant_id=tenant.tenant_id,
        feature_key="intel.cross_tenant_controls",
        plan=PlanTier(str(tenant.plan.value) if hasattr(tenant.plan, "value") else str(tenant.plan)),
        amount=1,
        detail={"mode": mode, "api": "/api/intel/rules"},
    )
    if usage["usage"]["status"] == "blocked":
        raise HTTPException(status_code=402, detail="feature_usage_limit_exceeded:intel.cross_tenant_controls")
    rule = network_intel.upsert_suppression_rule(
        signal_type=signal_type,
        raw_value=raw_value,
        mode=mode,
        reason=str(body.get("reason", "")),
        expires_at=(str(body.get("expires_at", "")).strip() or None),
    )
    return {"rule": rule}


@router.get("/api/intel/rules")
async def api_network_intel_list_rules(
    mode: str | None = None,
    limit: int = 100,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    _ = tenant
    if mode is not None:
        mode = mode.strip().lower()
        if mode not in {"suppress", "allow"}:
            raise HTTPException(status_code=400, detail="'mode' must be suppress or allow")
    rules = network_intel.list_suppression_rules(mode=mode, limit=min(max(limit, 1), 500))
    return {"count": len(rules), "rules": rules}


@router.post("/api/intel/decay")
async def api_network_intel_decay(
    body: dict,
    _tenant: TenantContext = Depends(require_role(Role.OWNER)),
):
    older_than_days = body.get("older_than_days")
    if older_than_days is not None:
        try:
            older_than_days = int(older_than_days)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="'older_than_days' must be an integer") from exc
    result = network_intel.apply_decay(older_than_days=older_than_days)
    return {"result": result}


@router.post("/api/intel/assess")
async def api_network_intel_assess(
    body: dict,
    tenant: TenantContext = Depends(get_tenant),
):
    candidates = body.get("candidates")
    if not isinstance(candidates, list):
        raise HTTPException(status_code=400, detail="'candidates' must be an array")
    normalized: list[dict[str, str]] = []
    for item in candidates:
        if not isinstance(item, dict):
            continue
        signal_type = str(item.get("signal_type", "")).strip()
        raw_value = str(item.get("raw_value", "")).strip()
        if not signal_type or not raw_value:
            continue
        normalized.append({"signal_type": signal_type, "raw_value": raw_value})

    assessment = network_intel.assess_runtime_penalty(normalized)
    suppression_status = [
        {
            "signal_type": candidate["signal_type"],
            "status": network_intel.is_suppressed(candidate["signal_type"], candidate["raw_value"]),
        }
        for candidate in normalized
    ]
    return {"tenant_id": tenant.tenant_id, "assessment": assessment, "suppression_status": suppression_status}


@router.get("/api/intel/feed/taxii")
async def api_network_intel_feed_taxii(
    limit: int = 100,
    min_tenant_count: int = 2,
    min_confidence: float = 0.6,
    _tenant: TenantContext = Depends(get_tenant),
):
    rows = network_intel.get_feed(
        limit=min(max(limit, 1), 500),
        min_tenant_count=max(min_tenant_count, 1),
        min_confidence=max(min(min_confidence, 1.0), 0.0),
    )
    return {"taxii_bundle": build_taxii_bundle(rows)}


