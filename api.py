"""
TokenDNA Identity Backbone -- FastAPI v2.5.0

Endpoints
─────────
GET  /                          health check (unauthenticated)
GET  /dashboard                 admin dashboard SPA (unauthenticated)

GET  /api/stats                 KPI counters for current tenant
GET  /api/events                recent session events for current tenant
GET  /api/events/hourly         hourly volume for past 24h (chart data)
GET  /api/threats               threat signal breakdown for past 24h
GET  /api/health                detailed system health

GET  /secure                    main token integrity check
GET  /profile/{uid}             inspect user adaptive profile
DELETE /profile/{uid}           reset user profile
POST /revoke                    manually revoke token by jti

POST /admin/tenants             create tenant  (returns raw API key, show once)
GET  /admin/tenants             list all tenants
GET  /admin/tenants/{id}/keys   list API keys for a tenant
POST /admin/tenants/{id}/keys   rotate / add API key
DELETE /admin/tenants/{id}/keys/{kid}  revoke a key

POST /onboarding/aws/external-id   generate ExternalId for CloudFormation
POST /onboarding/aws/test          test IAM role + quick posture scan

POST /api/uis/normalize            normalize a protocol event into UIS v1.0
POST /api/agent/attest             generate 4D agent attestation record
POST /api/mcp/verify               verify MCP server integrity/capabilities
"""
from __future__ import annotations

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

# alias used in /api/oss/sdk/attest route
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)
from api_routers._shared import APP_VERSION  # noqa: E402

def _plan_tier_from_tenant(tenant: TenantContext) -> PlanTier:
    plan_value = str(
        getattr(tenant, "plan", Plan.FREE).value if hasattr(tenant.plan, "value") else tenant.plan
    ).lower()
    if plan_value in {p.value for p in PlanTier}:
        return PlanTier(plan_value)
    return PlanTier.FREE


def _record_decision_audit(
    *,
    tenant: TenantContext,
    request_id: str,
    source_endpoint: str,
    actor_subject: str,
    evaluation_input: dict,
    enforcement: dict,
    policy_bundle: dict | None = None,
) -> dict:
    return decision_audit.record_decision(
        tenant_id=tenant.tenant_id,
        request_id=request_id,
        source_endpoint=source_endpoint,
        actor_subject=actor_subject,
        evaluation_input=evaluation_input,
        enforcement_result=enforcement,
        policy_bundle=policy_bundle,
    )


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await _startup_checks()
    yield


app = FastAPI(
    title="TokenDNA Identity Backbone",
    description="Zero-trust identity exchange, UIS normalization, and agent supply-chain attestation",
    version=APP_VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

# Security middleware (order matters — validation runs first, then headers)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestValidationMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "X-API-Key", "X-Correlation-ID", "Content-Type"],
    allow_credentials=False,  # explicit — never wildcard credentials
)

# T-1 decomposition registry: mount every extracted domain router. No-op while
# api_routers.ALL_ROUTERS is empty; routers are added one sprint at a time and
# their handlers are removed from this file (enforced by the monolith ratchet).
from api_routers import mount_all as _mount_routers  # noqa: E402
_mount_routers(app)


# Prometheus latency / count middleware. Records every served request,
# falls back to a no-op when prometheus_client is not installed.
@app.middleware("http")
async def _metrics_middleware(request, call_next):
    from time import perf_counter
    from modules.observability.metrics import record_http_request

    start = perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        # Use the matched route template when available so cardinality stays
        # bounded; otherwise fall back to the raw path.
        route = getattr(getattr(request, "scope", {}).get("route", None), "path", None) or request.url.path
        record_http_request(request.method, route, status, perf_counter() - start)


async def _startup_checks() -> None:
    # Federal-profile fail-closed crypto gate (T-3, SC-13): refuse to start when
    # REQUIRE_FIPS=true but the validated OpenSSL provider is not active.
    from modules.security.fips import assert_fips_mode
    assert_fips_mode()

    if DEV_MODE:
        logger.warning("DEV_MODE=true — JWT auth disabled. Not for production.")
    if not OIDC_ISSUER and not DEV_MODE:
        logger.warning("OIDC_ISSUER not set — authenticated endpoints will 401.")

    # Production HMAC secret gate — fail fast if any required secret is missing
    # or set to a published dev default. No-op in non-prod.
    from modules.security.secret_gate import assert_production_secrets, is_production
    assert_production_secrets()
    if is_production():
        logger.info("Production secret gate passed ✓")

    # Observability — opt-in via env vars; no-ops when packages missing.
    try:
        from modules.observability.tracing import init_tracing
        from modules.observability.error_reporting import init_error_reporting
        init_tracing(app)
        init_error_reporting()
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("observability init partial failure: %s", exc)

    # FIPS 140-2 enforcement (SC-13)
    il_env = os.getenv("ENVIRONMENT", "dev").lower()
    fips_active = fips.is_active()
    if not fips_active:
        if il_env in {"il5", "il6"}:
            logger.critical("FIPS 140-2 not active in IL5/IL6 environment — FATAL")
            raise RuntimeError("FIPS 140-2 required but not active in IL5/IL6 environment")
        else:
            logger.warning("FIPS 140-2 not active (environment=%s) — acceptable for non-IL5", il_env)
    else:
        logger.info("FIPS 140-2 active ✓ (environment=%s)", il_env)

    from modules.storage.migrations import apply_migrations

    migration_report = apply_migrations()
    logger.info(
        "Storage migrations ready (head=%s current=%s applied_now=%s)",
        migration_report.get("head"),
        migration_report.get("current"),
        migration_report.get("applied_now"),
    )

    from modules.identity.cache_redis import is_available as redis_ok
    logger.info("Redis: %s", "connected" if redis_ok() else "UNREACHABLE")
    logger.info("ClickHouse: %s", "connected" if clickhouse_client.is_available() else "UNREACHABLE")

    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, threat_intel._ensure_tor_list)

    # Emit startup audit event (AU-2: application startup)
    log_event(AuditEventType.STARTUP, AuditOutcome.SUCCESS,
              detail={"version": APP_VERSION, "dev_mode": DEV_MODE})


# ── Rate limiting dependency ──────────────────────────────────────────────────

from api_routers._shared import check_rate_limit, check_rate_limit_open  # noqa: E402
# ── Health / dashboard (unauthenticated) ─────────────────────────────────────

@app.get("/")
async def health():
    from modules.identity.cache_redis import is_available as redis_ok
    return {
        "service":    "TokenDNA",
        "version":    APP_VERSION,
        "redis":      redis_ok(),
        "clickhouse": clickhouse_client.is_available(),
        "dev_mode":   DEV_MODE,
    }


@app.get("/healthz")
async def healthz():
    """Kubernetes liveness probe — process is up and serving."""
    return {"status": "ok"}


@app.get("/readyz")
async def readyz():
    """Kubernetes readiness probe — refuse traffic if a dependency is down."""
    from modules.identity.cache_redis import is_available as redis_ok
    redis_state = redis_ok()
    ch_state = clickhouse_client.is_available()
    ready = redis_state and ch_state
    body = {
        "status": "ready" if ready else "degraded",
        "redis": redis_state,
        "clickhouse": ch_state,
        "dev_mode": DEV_MODE,
    }
    if not ready:
        return JSONResponse(status_code=503, content=body)
    return body


@app.get("/metrics")
async def metrics_endpoint():
    """Prometheus exposition endpoint."""
    from fastapi.responses import Response
    from modules.observability.metrics import render_metrics
    body, content_type = render_metrics()
    return Response(content=body, media_type=content_type)


# ── Enterprise SAML SSO (alpha) ───────────────────────────────────────────────


# ── SCIM 2.0 (alpha) ──────────────────────────────────────────────────────────


# ── Dashboard data API (tenant-scoped, real data) ────────────────────────────

# ── Consolidation endpoints: UIS + Agent Attestation + MCP Verification ──────

# ── Main integrity check ──────────────────────────────────────────────────────

# ── Profile endpoints ─────────────────────────────────────────────────────────

# ── Manual revocation ─────────────────────────────────────────────────────────

# ── Tenant management (admin) ─────────────────────────────────────────────────

# ── AWS onboarding ────────────────────────────────────────────────────────────

# ── Session Intelligence (/api/sessions) ──────────────────────────────────────

# ── Cloud Posture Findings (/api/cloud-findings) ───────────────────────────────

# ── Audit Log endpoint (OWNER only) ────────────────────────────────────────────

# ── Trust Graph endpoints ──────────────────────────────────────────────────────

# ── Blast Radius Simulator endpoints ──────────────────────────────────────────

# ── Intent Correlation endpoints ───────────────────────────────────────────────

# ── ZTIX Exchange endpoints ───────────────────────────────────────────────────

# ── Permission Drift Tracker (Sprint 5-2) ─────────────────────────────────

# ── Sprint 5-3: Ghost Agent Offboarding Enforcement ───────────────────────────

# ── Sprint 5-4: MCP Intent-Aware Inspection ───────────────────────────────────

# ── Sprint 6-1: Agent Attestation Certificate Lifecycle Dashboard ─────────────

# ==========================================================================
# Policy Advisor — Adaptive Policy Suggestion Engine (Sprint 6-2)
# ==========================================================================


# ==========================================================================
# Agent Identity Passport (Sprint 3-1) — restored 2026-04-21
# ==========================================================================

from modules.identity import passport as passport_module


# ==========================================================================
# Verifier Reputation Network (Sprint 3-2) — restored 2026-04-21
# ==========================================================================

from modules.identity import verifier_reputation as reputation_module


# ==========================================================================
# ZTIX Continuous Proof-of-Control (Expansion #2) — Sprint 7-B
# ==========================================================================

from modules.identity import proof_of_control as poc_module


# ── Phase 5-1: MCP Security Gateway ──────────────────────────────────────────


# ── Phase 5-2: Agent Discovery & Inventory ────────────────────────────────────


# ── Phase 5-3: Enforcement Plane ─────────────────────────────────────────────


# ── Phase 5-3: Behavioral DNA ─────────────────────────────────────────────────


# ── Phase 5-4: Compliance Engine ─────────────────────────────────────────────


# ── Commercial Tier Entitlements ──────────────────────────────────────────────
# Ungated — community tenants need to see what they're locked out of.

# ── Threat Sharing Network ────────────────────────────────────────────────────
# Cross-tenant threat-intel sharing built on top of intent_correlation.
# Gated behind ent.intent_correlation since the network is an extension of
# that feature.

# ── Delegation Receipts ───────────────────────────────────────────────────────
# Cryptographic paper trail for agent delegation chains. Gated behind
# ent.enforcement_plane — receipts are an authorization-enforcement primitive.

# ── Threat Sharing Flywheel ───────────────────────────────────────────────────
# Network-effect loops on top of /api/threat-sharing: hit recording, catalog
# scoring, industry digest, auto-subscribe.

# ── Workflow Attestation ──────────────────────────────────────────────────────
# Multi-hop signed DAG with replay + drift detection. Gated behind
# ent.enforcement_plane — workflow attestation is the chain-of-custody
# layer above per-receipt delegation.

# ── Compliance Posture & Incident Reconstruction ──────────────────────────────
# Auditor-facing surfaces. compliance.py owns the framework definitions;
# this is the operator's "prove our posture as of now" deliverable.

# ── Honeypot Mesh / Active Deception ──────────────────────────────────────────
# Active counterpart to deception_mesh: emit attestation-valid decoys,
# harvest attacker TTPs. Gated behind ent.enforcement_plane.

# ── Staged Rollout / Allowlist Admin ──────────────────────────────────────────
# Per-tenant feature allowlists for design-partner / beta / staged-rollout
# scenarios. Admin-only. require_feature() consults this transparently;
# tier-based entitlement remains the default.

# ── Edge enforcement parity (Cloudflare Worker snapshot endpoints) ────────────
#
# Pulled by edge/index.js scheduled() handler every 60s and cached in KV so
# the request-path edge checks (cert revocation + drift score gating) are
# O(1) and never block on the backend.  Authenticates via a shared
# X-Edge-Sync-Token header (set as a Cloudflare Worker secret).


