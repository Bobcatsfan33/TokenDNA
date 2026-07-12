"""product domain router (T-1 decomposition).

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

router = APIRouter(prefix="", tags=["product"])


@router.get("/api/product/features")
async def api_product_feature_matrix(
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    tenant_plan = getattr(tenant, "plan", Plan.FREE)
    plan_value = str(tenant_plan.value if hasattr(tenant_plan, "value") else tenant_plan).lower()
    plan_tier = PlanTier(plan_value) if plan_value in {p.value for p in PlanTier} else PlanTier.FREE
    return {
        "tenant_id": tenant.tenant_id,
        "plan": plan_tier.value,
        "features": list_feature_matrix(plan_tier),
    }


@router.post("/api/product/features/evaluate")
async def api_evaluate_product_feature(
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    feature = str(body.get("feature", "")).strip()
    if not feature:
        raise HTTPException(status_code=400, detail="'feature' is required")
    tenant_plan = getattr(tenant, "plan", Plan.FREE)
    plan_value = str(tenant_plan.value if hasattr(tenant_plan, "value") else tenant_plan).lower()
    plan_tier = PlanTier(plan_value) if plan_value in {p.value for p in PlanTier} else PlanTier.FREE
    result = evaluate_feature_access(
        feature_name=feature,
        plan=plan_tier,
        identity_fields=(body.get("identity_fields") if isinstance(body.get("identity_fields"), dict) else {}),
    )
    return {"tenant_id": tenant.tenant_id, "plan": plan_tier.value, "result": result}


@router.get("/api/product/usage")
async def api_product_usage(
    month: str | None = None,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    statement = feature_metering.build_usage_statement(
        tenant_id=tenant.tenant_id,
        month_bucket=month,
    )
    return {"tenant_id": tenant.tenant_id, "statement": statement}


@router.get("/api/product/usage/exports")
async def api_product_usage_exports(
    month: str | None = None,
    limit: int = 50,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    exports = feature_metering.list_billing_exports(
        tenant_id=tenant.tenant_id,
        month_bucket=(month or None),
        limit=min(max(limit, 1), 200),
    )
    return {"tenant_id": tenant.tenant_id, "count": len(exports), "exports": exports}


@router.post("/api/product/usage/export")
async def api_product_usage_export(
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    export_format = str(body.get("format", "json")).strip().lower()
    if export_format not in {"json", "csv"}:
        raise HTTPException(status_code=400, detail="'format' must be json or csv")
    export = feature_metering.export_billing_statement(
        tenant_id=tenant.tenant_id,
        month_bucket=(str(body.get("month", "")).strip() or None),
        export_format=export_format,
        key_id=(str(body.get("key_id", "")).strip() or None),
        algorithm=str(body.get("algorithm", "HS256")).strip().upper(),
    )
    verification = feature_metering.verify_billing_export_signature(export)
    return {"tenant_id": tenant.tenant_id, "export": export, "verification": verification}


@router.post("/api/product/usage/evaluate")
async def api_product_usage_evaluate(
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    feature = str(body.get("feature", "")).strip()
    if not feature:
        raise HTTPException(status_code=400, detail="'feature' is required")
    amount = int(body.get("amount", 1))
    plan = PlanTier(str(tenant.plan.value) if hasattr(tenant.plan, "value") else str(tenant.plan))
    assessment = feature_metering.evaluate_usage(
        tenant_id=tenant.tenant_id,
        feature_key=feature,
        plan=plan,
        amount=max(1, amount),
        month_bucket=(str(body.get("month", "")).strip() or None),
    )
    return {"tenant_id": tenant.tenant_id, "assessment": assessment}


@router.get("/api/product/entitlements")
async def api_product_entitlements(
    tenant: TenantContext = Depends(get_tenant),
):
    """Return the commercial-tier feature matrix for the current tenant."""
    return {
        "tenant_id": tenant.tenant_id,
        "tenant_tier": tier_for_plan(tenant.plan).value,
        "features": list_commercial_features(tenant.plan),
        "upgrade_url": "/billing/upgrade",
    }


