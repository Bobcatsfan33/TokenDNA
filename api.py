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
APP_VERSION = "2.5.0"

_DASHBOARD_PATH = Path(__file__).parent / "dashboard" / "index.html"


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


def _tenant_subject(tenant: TenantContext) -> str:
    return str(getattr(tenant, "owner_email", "") or tenant.api_key_id or tenant.tenant_id)

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


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    if not _DASHBOARD_PATH.exists():
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return FileResponse(_DASHBOARD_PATH)


# ── Enterprise SAML SSO (alpha) ───────────────────────────────────────────────


@app.get("/saml/metadata", response_class=Response)
async def saml_metadata():
    from modules.auth.saml import generate_metadata
    return Response(content=generate_metadata(), media_type="application/xml")


@app.get("/saml/login")
async def saml_login(relay_state: str | None = None):
    from modules.auth.saml import build_authn_request, SAMLError
    try:
        req = build_authn_request(relay_state=relay_state)
    except SAMLError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return {
        "request_id": req.request_id,
        "redirect_url": req.redirect_url,
        "relay_state": req.relay_state,
    }


@app.post("/saml/acs")
async def saml_acs(request: Request):
    from modules.auth.saml import parse_assertion, SAMLError
    form = await request.form()
    saml_response = form.get("SAMLResponse")
    if not saml_response:
        raise HTTPException(status_code=400, detail="SAMLResponse missing")
    try:
        assertion = parse_assertion(str(saml_response))
    except SAMLError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    return {
        "name_id": assertion.name_id,
        "attributes": assertion.attributes,
        "issuer": assertion.issuer,
        "session_index": assertion.session_index,
    }


# ── SCIM 2.0 (alpha) ──────────────────────────────────────────────────────────


def _scim_response(body: dict, status: int = 200):
    return JSONResponse(
        content=body,
        status_code=status,
        media_type="application/scim+json",
    )


def _scim_handle(coro):  # decorator-like wrapper
    """Translate SCIMError into a SCIM-formatted JSON response."""
    from functools import wraps
    from modules.auth.scim import SCIMError

    @wraps(coro)
    async def wrapper(*args, **kwargs):
        try:
            return await coro(*args, **kwargs)
        except SCIMError as exc:
            return _scim_response(exc.to_response(), status=exc.status)

    return wrapper


@app.get("/scim/v2/ServiceProviderConfig")
async def scim_spc():
    from modules.auth.scim import service_provider_config
    return _scim_response(service_provider_config())


@app.get("/scim/v2/ResourceTypes")
async def scim_resource_types():
    from modules.auth.scim import resource_types
    return _scim_response(resource_types())


@app.post("/scim/v2/Users")
@_scim_handle
async def scim_create_user(request: Request, tenant: TenantContext = Depends(get_tenant)):
    from modules.auth.scim import create_user
    payload = await request.json()
    body = create_user(payload, tenant_id=tenant.tenant_id)
    return _scim_response(body, status=201)


@app.get("/scim/v2/Users/{user_id}")
@_scim_handle
async def scim_get_user(user_id: str, tenant: TenantContext = Depends(get_tenant)):
    from modules.auth.scim import get_user
    return _scim_response(get_user(user_id, tenant_id=tenant.tenant_id))


@app.put("/scim/v2/Users/{user_id}")
@_scim_handle
async def scim_replace_user(user_id: str, request: Request, tenant: TenantContext = Depends(get_tenant)):
    from modules.auth.scim import replace_user
    payload = await request.json()
    return _scim_response(replace_user(user_id, payload, tenant_id=tenant.tenant_id))


@app.patch("/scim/v2/Users/{user_id}")
@_scim_handle
async def scim_patch_user(user_id: str, request: Request, tenant: TenantContext = Depends(get_tenant)):
    from modules.auth.scim import patch_user
    payload = await request.json()
    return _scim_response(patch_user(user_id, payload, tenant_id=tenant.tenant_id))


@app.delete("/scim/v2/Users/{user_id}")
@_scim_handle
async def scim_delete_user(user_id: str, tenant: TenantContext = Depends(get_tenant)):
    from modules.auth.scim import delete_user
    delete_user(user_id, tenant_id=tenant.tenant_id)
    return Response(status_code=204)


@app.get("/scim/v2/Users")
@_scim_handle
async def scim_list_users(
    startIndex: int = 1,
    count: int = 100,
    filter: str | None = None,
    tenant: TenantContext = Depends(get_tenant),
):
    from modules.auth.scim import list_users
    return _scim_response(
        list_users(
            tenant_id=tenant.tenant_id,
            start_index=startIndex,
            count=count,
            filter_expr=filter,
        )
    )


@app.post("/scim/v2/Groups")
@_scim_handle
async def scim_create_group(request: Request, tenant: TenantContext = Depends(get_tenant)):
    from modules.auth.scim import create_group
    payload = await request.json()
    return _scim_response(create_group(payload, tenant_id=tenant.tenant_id), status=201)


@app.get("/scim/v2/Groups/{group_id}")
@_scim_handle
async def scim_get_group(group_id: str, tenant: TenantContext = Depends(get_tenant)):
    from modules.auth.scim import get_group
    return _scim_response(get_group(group_id, tenant_id=tenant.tenant_id))


@app.get("/scim/v2/Groups")
@_scim_handle
async def scim_list_groups(
    filter: str | None = None,
    tenant: TenantContext = Depends(get_tenant),
):
    from modules.auth.scim import list_groups
    return _scim_response(list_groups(tenant_id=tenant.tenant_id, filter_expr=filter))


@app.patch("/scim/v2/Groups/{group_id}")
@_scim_handle
async def scim_patch_group(group_id: str, request: Request, tenant: TenantContext = Depends(get_tenant)):
    from modules.auth.scim import patch_group
    payload = await request.json()
    return _scim_response(patch_group(group_id, payload, tenant_id=tenant.tenant_id))


@app.delete("/scim/v2/Groups/{group_id}")
@_scim_handle
async def scim_delete_group(group_id: str, tenant: TenantContext = Depends(get_tenant)):
    from modules.auth.scim import delete_group
    delete_group(group_id, tenant_id=tenant.tenant_id)
    return Response(status_code=204)


# ── Dashboard data API (tenant-scoped, real data) ────────────────────────────

@app.get("/api/stats")
async def api_stats(tenant: TenantContext = Depends(get_tenant)):
    """KPI counters for the current tenant — served from Redis (no ClickHouse)."""
    counters = get_event_counters(tenant.tenant_id, days=1)
    total    = counters["total"] or 1   # avoid div-by-zero
    allow    = counters["allow"]
    return {
        "tenant_id":   tenant.tenant_id,
        "tenant_name": tenant.tenant_name,
        "today": {
            **counters,
            "allow_rate_pct": round(allow / total * 100, 1),
        },
    }


@app.get("/api/events")
async def api_events(
    limit: int = 50,
    tenant: TenantContext = Depends(get_tenant),
):
    """Recent session events for the current tenant, newest first."""
    events = clickhouse_client.query_recent_events(tenant.tenant_id, limit=min(limit, 200))
    return {"tenant_id": tenant.tenant_id, "events": events, "count": len(events)}


@app.get("/api/events/hourly")
async def api_events_hourly(
    hours: int = 24,
    tenant: TenantContext = Depends(get_tenant),
):
    """Hourly event volume for the past N hours. Powers the area chart."""
    rows = clickhouse_client.query_hourly_volume(tenant.tenant_id, hours=min(hours, 168))
    return {"tenant_id": tenant.tenant_id, "rows": rows}


@app.get("/api/threats")
async def api_threats(tenant: TenantContext = Depends(get_tenant)):
    """Threat signal breakdown for the past 24 hours."""
    breakdown = clickhouse_client.query_threat_breakdown(tenant.tenant_id)
    return {"tenant_id": tenant.tenant_id, "breakdown": breakdown}


@app.get("/api/health")
async def api_health_detail(_tenant: TenantContext = Depends(get_tenant)):
    """Detailed system health for the health panel."""
    from modules.identity.cache_redis import is_available as redis_ok
    from modules.identity.threat_intel import _tor_exits, _tor_last_refresh
    import time as _time
    tor_age = int(_time.time() - _tor_last_refresh) if _tor_last_refresh else None
    return {
        "redis":       {"ok": redis_ok()},
        "clickhouse":  {"ok": clickhouse_client.is_available()},
        "tor_list":    {"ok": len(_tor_exits) > 0, "count": len(_tor_exits), "age_seconds": tor_age},
        "dev_mode":    DEV_MODE,
        "version":     APP_VERSION,
        "fips_active": fips.is_active(),
        "il_environment": os.getenv("ENVIRONMENT", "dev"),
    }


@app.get("/api/operator/status")
async def api_operator_status(
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    from modules.identity.cache_redis import is_available as redis_ok
    from modules.storage.migrations import migration_status

    dependencies = {
        "sqlite": {"ok": True},
        "redis": {"ok": redis_ok()},
        "clickhouse": {"ok": clickhouse_client.is_available()},
        "storage_backend": db_backend.get_backend_config().__dict__,
    }
    try:
        migrations = migration_status()
    except Exception as exc:  # noqa: BLE001
        migrations = {
            "up_to_date": False,
            "pending": [],
            "error": str(exc),
        }
    slo = {
        "edge_decision_ms": {
            "target": float(os.getenv("EDGE_DECISION_SLO_MS", "5")),
        },
        "rate_limit_per_minute": {
            "target": RATE_LIMIT_PER_MINUTE,
        },
    }
    posture = {
        "fips_active": fips.is_active(),
        "environment": os.getenv("ENVIRONMENT", "dev"),
        "dev_mode": DEV_MODE,
    }
    return {
        "tenant_id": tenant.tenant_id,
        "version": APP_VERSION,
        "dependencies": dependencies,
        "migrations": migrations,
        "slo": slo,
        "posture": posture,
    }


# ── Consolidation endpoints: UIS + Agent Attestation + MCP Verification ──────

@app.get("/api/threat-intel/feed")
async def api_threat_intel_feed(
    limit: int = 50,
    cursor: str | None = None,
    min_tenant_count: int = 2,
    min_confidence: float = 0.6,
    tenant: TenantContext = Depends(get_tenant),
):
    """Cursor-paginated threat-intel feed.  ?limit=N (default 50, max 200)
    + ?cursor=<opaque>; response includes ``next_cursor`` (null when
    exhausted)."""
    from modules.storage.pagination import paginate_offset  # noqa: PLC0415
    page = paginate_offset(
        lambda offset, lim: network_intel.get_feed(
            limit=lim, offset=offset,
            min_tenant_count=max(min_tenant_count, 1),
            min_confidence=max(min(min_confidence, 1.0), 0.0),
        ),
        cursor=cursor,
        limit=limit,
    )
    return page.as_response("signals", extra={"tenant_id": tenant.tenant_id})


@app.get("/api/schema/uis.json")
async def api_schema_uis_json(
    response: Response,
    _tenant: TenantContext = Depends(get_tenant),
):
    # Serve the canonical JSON Schema artifact via the validator's cache.
    # Same source of truth that ``validate_uis_event`` uses at runtime.
    from modules.identity.uis_validator import (  # noqa: PLC0415
        schema_dict, schema_version,
    )
    response.headers["X-UIS-Schema-Version"] = schema_version()
    response.headers["Content-Type"] = "application/json"
    return schema_dict()


@app.get("/api/schema/attestation.json")
async def api_schema_attestation_json(
    _tenant: TenantContext = Depends(get_tenant),
):
    return schema_registry.build_attestation_schema_artifact()


@app.get("/api/attestation/spec")
async def api_attestation_protocol_spec(
    _tenant: TenantContext = Depends(get_tenant),
):
    return {
        "version": "1.0",
        "record_dimensions": {
            "who": ["agent_id", "created_by", "owner_org"],
            "what": ["soul_hash", "directive_hashes", "model_fingerprint", "mcp_manifest_hash"],
            "how": ["auth_method", "dpop_bound", "mtls_bound", "behavior_confidence"],
            "why": ["declared_purpose", "scope", "delegation_chain", "policy_trace_id"],
        },
        "certificate_fields": [
            "certificate_id", "tenant_id", "attestation_id", "issuer", "subject",
            "issued_at", "expires_at", "signature_alg", "ca_key_id",
            "status", "revoked_at", "revocation_reason", "claims", "signature",
        ],
        "transparency_log": {
            "actions": ["issued", "revoked"],
            "integrity_fields": ["previous_entry_hash", "entry_hash", "merkle_root"],
        },
    }


@app.post("/api/abac/evaluate")
async def api_abac_evaluate(
    body: dict,
    tenant: TenantContext = Depends(get_tenant),
):
    uis_event = body.get("uis_event")
    if not isinstance(uis_event, dict):
        raise HTTPException(status_code=400, detail="'uis_event' must be an object")

    attestation = body.get("attestation")
    if attestation is not None and not isinstance(attestation, dict):
        raise HTTPException(status_code=400, detail="'attestation' must be an object when provided")

    drift = body.get("drift")
    if drift is not None and not isinstance(drift, dict):
        raise HTTPException(status_code=400, detail="'drift' must be an object when provided")

    required_scope = body.get("required_scope")
    if required_scope is not None and not isinstance(required_scope, list):
        raise HTTPException(status_code=400, detail="'required_scope' must be an array when provided")

    certificate_verified = body.get("certificate_verified")
    if certificate_verified is not None and not isinstance(certificate_verified, bool):
        raise HTTPException(status_code=400, detail="'certificate_verified' must be a boolean when provided")

    certificate = body.get("certificate")
    if certificate is not None and not isinstance(certificate, dict):
        raise HTTPException(status_code=400, detail="'certificate' must be an object when provided")
    certificate_id = str(body.get("certificate_id", "")).strip()
    if not certificate_id and isinstance(certificate, dict):
        certificate_id = str(certificate.get("certificate_id", "")).strip()

    request_headers = body.get("request_headers") or {}
    if not isinstance(request_headers, dict):
        raise HTTPException(status_code=400, detail="'request_headers' must be an object when provided")
    observed_scope = body.get("observed_scope")
    if observed_scope is None:
        observed_scope = required_scope or []
    if not isinstance(observed_scope, list):
        raise HTTPException(status_code=400, detail="'observed_scope' must be an array when provided")

    if certificate_verified is not None:
        # Keep backward-compat override path for callers passing pre-verified status.
        cert_for_eval = certificate
    else:
        cert_for_eval = certificate

    enforcement = evaluate_runtime_enforcement(
        uis_event=uis_event,
        attestation=attestation,
        certificate=cert_for_eval,
        certificate_id=certificate_id,
        request_headers={str(k).lower(): str(v) for k, v in request_headers.items()},
        observed_scope=[str(v) for v in observed_scope],
        required_scope=[str(v) for v in (required_scope or [])],
    )

    # Optional backward-compatible override.
    if certificate_verified is not None and enforcement["decision"].get("action") != "block":
        enforcement["decision"]["policy_trace"]["inputs"]["certificate_verified_override"] = certificate_verified
        if certificate_verified is False:
            enforcement["decision"]["action"] = "block"
            enforcement["decision"]["reasons"] = list(enforcement["decision"].get("reasons", [])) + [
                "certificate_verification_failed"
            ]

    request_id = str(body.get("request_id") or str(uuid.uuid4()))
    audit_record = decision_audit.record_decision(
        tenant_id=tenant.tenant_id,
        request_id=request_id,
        source_endpoint="/api/abac/evaluate",
        actor_subject=str(body.get("actor_subject") or "api-client"),
        evaluation_input={
            "uis_event": uis_event,
            "attestation": attestation,
            "certificate": cert_for_eval,
            "certificate_id": certificate_id,
            "request_headers": {str(k).lower(): str(v) for k, v in request_headers.items()},
            "observed_scope": [str(v) for v in observed_scope],
            "required_scope": [str(v) for v in (required_scope or [])],
        },
        enforcement_result=enforcement,
    )
    return {"tenant_id": tenant.tenant_id, "request_id": request_id, "audit_id": audit_record.get("audit_id"), **enforcement}


@app.get("/api/decision-audit")
async def api_list_decision_audits(
    limit: int = 50,
    cursor: str | None = None,
    source_endpoint: str | None = None,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    page = decision_audit.list_decisions_paginated(
        tenant_id=tenant.tenant_id,
        page_size=min(max(limit, 1), 200),
        cursor=cursor,
        source_endpoint=source_endpoint,
    )
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(page["items"]),
        "audits": page["items"],
        "next_cursor": page["next_cursor"],
        "has_more": page["has_more"],
    }


@app.get("/api/decision-audit/{audit_id}")
async def api_get_decision_audit(
    audit_id: str,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    record = decision_audit.get_decision(tenant_id=tenant.tenant_id, audit_id=audit_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Decision audit not found")
    return {"tenant_id": tenant.tenant_id, "audit": record}


@app.post("/api/decision-audit/{audit_id}/replay")
async def api_replay_decision_audit(
    audit_id: str,
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    record = decision_audit.get_decision(tenant_id=tenant.tenant_id, audit_id=audit_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Decision audit not found")

    policy_bundle_config = None
    bundle_id = str(body.get("bundle_id", "")).strip()
    if bundle_id:
        bundle = policy_bundles.get_bundle(tenant.tenant_id, bundle_id)
        if bundle is None:
            raise HTTPException(status_code=404, detail="Policy bundle not found")
        policy_bundle_config = bundle.get("config") or {}
    else:
        config = body.get("policy_bundle_config")
        if config is not None and not isinstance(config, dict):
            raise HTTPException(status_code=400, detail="'policy_bundle_config' must be an object when provided")
        policy_bundle_config = config or {}

    replay = decision_audit.replay_decision(record=record, policy_bundle_config=policy_bundle_config)
    return {"tenant_id": tenant.tenant_id, "replay": replay}


@app.post("/api/integrations/idp/normalize")
async def api_integrations_idp_normalize(
    body: dict,
    request: Request,
    tenant: TenantContext = Depends(get_tenant),
):
    provider = str(body.get("provider", "")).strip().lower()
    event = body.get("event")
    if not provider:
        raise HTTPException(status_code=400, detail="'provider' is required")
    if not isinstance(event, dict):
        raise HTTPException(status_code=400, detail="'event' must be an object")

    adapted_claims = adapt_idp_event(provider, event)
    normalized_event = normalize_with_adapter(
        protocol="oidc",
        tenant_id=tenant.tenant_id,
        tenant_name=tenant.tenant_name,
        payload=adapted_claims,
        request_context={
            "request_id": str(uuid.uuid4()),
            "ip": request.client.host if request.client else "",
            "user_agent": request.headers.get("user-agent", ""),
            "integration_provider": provider,
        },
        risk_context=body.get("risk_context") if isinstance(body.get("risk_context"), dict) else {},
    )
    uis_store.insert_event(tenant_id=tenant.tenant_id, event=normalized_event)
    return {"tenant_id": tenant.tenant_id, "provider": provider, "uis_event": normalized_event}


@app.get("/api/integrations/catalog")
async def api_integrations_catalog(
    _tenant: TenantContext = Depends(get_tenant),
):
    return {
        "siem_soar": [
            {
                "name": "STIX/TAXII feed",
                "endpoint": "/api/intel/feed/taxii",
                "description": "Consume TokenDNA anonymized threat intel as STIX bundle",
            },
            {
                "name": "UIS event ingestion",
                "endpoint": "/api/uis/adapters/normalize",
                "description": "Normalize protocol/provider payloads into UIS",
            },
        ],
        "idp": [
            {
                "name": "Okta/Entra event adapter",
                "endpoint": "/api/integrations/idp/normalize",
                "description": "Translate IdP event formats into UIS-normalized identity events",
            }
        ],
        "agent_security": [
            {
                "name": "Attestation + trust authority",
                "endpoints": [
                    "/api/agent/attest",
                    "/api/agent/certificates/issue",
                    "/api/agent/certificates/verify",
                    "/api/agent/certificates/revoke",
                    "/api/agent/certificates/transparency-log",
                ],
            },
            {
                "name": "Runtime enforcement",
                "endpoints": ["/secure", "/api/abac/evaluate", "/api/agent/drift/assess"],
            },
        ],
    }


# ── Main integrity check ──────────────────────────────────────────────────────

@app.get("/secure")
async def secure(
    request: Request,
    user: dict = Depends(verify_token),
    tenant: TenantContext = Depends(get_tenant),
    _rate: None = Depends(check_rate_limit),
):
    request_id = str(uuid.uuid4())
    user_id    = user.get("sub", "unknown")
    jti        = user.get("jti", "")
    tid        = tenant.tenant_id

    # ── 1. Check revocation (tenant-scoped) ───────────────────────────────────
    if jti and is_token_revoked(jti, tenant_id=tid):
        raise HTTPException(status_code=401, detail="Token has been revoked")

    # ── 2. Extract signals ────────────────────────────────────────────────────
    ua  = request.headers.get("user-agent", "")
    ip  = request.client.host if request.client else ""
    r   = get_redis()
    tr  = TenantRedis(r, tid)    # tenant-namespaced Redis wrapper

    geo     = geo_intel.lookup(ip, redis_client=r)
    current = generate_dna(ua, ip, geo.country, geo.asn)
    threat  = threat_intel.enrich(ip, asn=geo.asn, isp=geo.isp, redis_client=r)
    session_context = {
        "request_id": request_id,
        "session_id": request.headers.get("x-session-id", ""),
        "ip": ip,
        "country": geo.country,
        "asn": geo.asn,
        "device_fingerprint": current.get("device", ""),
        "dna_fingerprint": current.get("device", ""),
        "user_agent": ua,
    }

    # ── 3. Baseline establishment ─────────────────────────────────────────────
    baseline = get_baseline(user_id, tenant_id=tid)
    if baseline is None:
        set_baseline(user_id, current, tenant_id=tid)
        ml_model.update_profile(user_id, current, redis=tr)
        session_graph.add_event(user_id, current, geo, redis=tr)
        increment_event_counter("allow", tenant_id=tid)
        baseline_event = normalize_from_protocol(
            protocol="oidc",
            tenant_id=tenant.tenant_id,
            tenant_name=tenant.tenant_name,
            subject=user_id,
            claims=user,
            request_context=session_context,
            risk_context={"risk_score": 100, "risk_tier": "allow", "indicators": []},
        )
        uis_store.insert_event(tenant_id=tenant.tenant_id, event=baseline_event)
        return {"status": "baseline_set", "request_id": request_id}

    # ── 4. Score ──────────────────────────────────────────────────────────────
    ml_score     = ml_model.score(user_id, current, redis=tr)
    graph_result = session_graph.detect_anomalies(user_id, current, geo, redis=tr)
    network_signal_candidates = [
        {"signal_type": "ip_hash", "raw_value": current.get("ip", "")},
        {"signal_type": "device_hash", "raw_value": current.get("device", "")},
        {"signal_type": "asn", "raw_value": current.get("asn", "")},
    ]
    network_assessment = network_intel.assess_runtime_penalty(network_signal_candidates)
    breakdown = scoring.compute(
        ml_score,
        threat,
        graph_result,
        network_penalty=network_assessment.get("penalty", 0),
        network_reasons=network_assessment.get("reasons", []),
    )

    uis_event = normalize_from_protocol(
        protocol="oidc",
        tenant_id=tenant.tenant_id,
        tenant_name=tenant.tenant_name,
        subject=user_id,
        claims=user,
        request_context=session_context,
        risk_context={
            "risk_score": breakdown.final_score,
            "risk_tier": breakdown.tier.value,
            "impossible_travel": graph_result.impossible_travel,
            "velocity_anomaly": graph_result.branching,
            "indicators": list(getattr(threat, "flags", [])),
        },
    )
    uis_store.insert_event(tenant_id=tenant.tenant_id, event=uis_event)
    # Record high-confidence malicious indicators to bootstrap network effects.
    if breakdown.tier in {RiskTier.BLOCK, RiskTier.REVOKE}:
        if current.get("ip"):
            network_intel.record_signal(
                tenant_id=tid,
                signal_type="ip_hash",
                raw_value=current["ip"],
                severity="high" if breakdown.tier == RiskTier.BLOCK else "critical",
                confidence=0.7 if breakdown.tier == RiskTier.BLOCK else 0.9,
                metadata={"tier": breakdown.tier.value, "reasons": breakdown.reasons},
            )
        if current.get("device"):
            network_intel.record_signal(
                tenant_id=tid,
                signal_type="device_hash",
                raw_value=current["device"],
                severity="high" if breakdown.tier == RiskTier.BLOCK else "critical",
                confidence=0.65 if breakdown.tier == RiskTier.BLOCK else 0.85,
                metadata={"tier": breakdown.tier.value, "reasons": breakdown.reasons},
            )

    # Optional agent policy hook for machine identities.
    agent_id = request.headers.get("x-agent-id")
    dpop_present = bool(request.headers.get("dpop"))
    mtls_present = bool(request.headers.get("x-mtls-subject"))
    if agent_id:
        observed_scope = (
            user.get("scope", [])
            if isinstance(user.get("scope"), list)
            else str(user.get("scope", "")).split()
        )
        latest_attestation = attestation_store.get_latest_attestation_for_agent(
            tenant_id=tid, agent_id=agent_id
        )

        if latest_attestation is None:
            # Bootstrap first attestation snapshot when agent has no baseline yet.
            bootstrap_attestation = create_attestation_record(
                agent_id=agent_id,
                owner_org=tenant.tenant_name,
                created_by=user_id,
                soul_hash=request.headers.get("x-agent-soul-hash", ""),
                directive_hashes=[h.strip() for h in request.headers.get("x-agent-directive-hashes", "").split(",") if h.strip()],
                model_fingerprint=request.headers.get("x-agent-model-fingerprint", ""),
                mcp_manifest_hash=request.headers.get("x-agent-mcp-manifest-hash", ""),
                auth_method="token",
                dpop_bound=dpop_present,
                mtls_bound=mtls_present,
                behavior_confidence=max(min(breakdown.final_score / 100.0, 1.0), 0.0),
                declared_purpose=request.headers.get("x-agent-purpose", "runtime_access"),
                scope=observed_scope,
                delegation_chain=[v for v in request.headers.get("x-agent-delegation-chain", "").split(",") if v],
                policy_trace_id=request_id,
                runtime_context={
                    "tenant_id": tid,
                    "ip": ip,
                    "country": geo.country,
                    "asn": geo.asn,
                    "user_agent": ua,
                },
                behavior_features={
                    "risk_tier": breakdown.tier.value,
                    "risk_score": breakdown.final_score,
                    "threat_flags": list(getattr(threat, "flags", [])),
                },
            )
            attestation_store.insert_attestation(tenant_id=tid, record=bootstrap_attestation.to_dict())
        else:
            certificate_id = request.headers.get("x-agent-certificate-id", "")
            cert = (
                attestation_store.get_certificate(tenant_id=tid, certificate_id=certificate_id)
                if certificate_id
                else None
            )
            enforcement = evaluate_runtime_enforcement(
                uis_event=uis_event,
                attestation=latest_attestation,
                certificate=cert,
                certificate_id=certificate_id,
                request_headers={k.lower(): str(v) for k, v in request.headers.items()},
                observed_scope=[str(v) for v in observed_scope],
                required_scope=[],
            )
            try:
                min_verifiers = max(1, int(request.headers.get("x-federation-min-verifiers", "2")))
            except Exception:
                min_verifiers = 2
            try:
                min_trust_score = max(
                    0.0,
                    min(float(request.headers.get("x-federation-min-trust-score", "0.6")), 1.0),
                )
            except Exception:
                min_trust_score = 0.6
            try:
                min_confidence = max(
                    0.0,
                    min(float(request.headers.get("x-federation-min-confidence", "0.6")), 1.0),
                )
            except Exception:
                min_confidence = 0.6
            federation_quorum = trust_federation.evaluate_federation_quorum(
                tenant_id=tid,
                target_type="agent",
                target_id=agent_id,
                min_verifiers=min_verifiers,
                min_trust_score=min_trust_score,
                min_confidence=min_confidence,
            )
            enforcement["federation_quorum"] = federation_quorum
            if not federation_quorum.get("quorum", {}).get("met", False):
                decision = enforcement.get("decision") or {}
                if decision.get("action") == "allow":
                    decision["action"] = "step_up"
                decision["reasons"] = list(decision.get("reasons", [])) + ["federation_quorum_not_met"]
                enforcement["decision"] = decision
            elif federation_quorum.get("effective_action") == "block":
                decision = enforcement.get("decision") or {}
                decision["action"] = "block"
                decision["reasons"] = list(decision.get("reasons", [])) + ["federation_quorum_block"]
                enforcement["decision"] = decision
            decision_audit.record_decision(
                tenant_id=tid,
                request_id=request_id,
                source_endpoint="/secure",
                actor_subject=user_id,
                evaluation_input={
                    "uis_event": uis_event,
                    "attestation": latest_attestation,
                    "certificate": cert,
                    "certificate_id": certificate_id,
                    "request_headers": {k.lower(): str(v) for k, v in request.headers.items()},
                    "observed_scope": [str(v) for v in observed_scope],
                    "required_scope": [],
                },
                enforcement_result=enforcement,
            )
            decision = enforcement["decision"]
            drift_dict = enforcement.get("drift")

            if certificate_id:
                if cert is None:
                    raise HTTPException(status_code=401, detail="Agent certificate not found")
                if cert.get("attestation_id") != latest_attestation.get("attestation_id"):
                    raise HTTPException(status_code=401, detail="Agent certificate does not match latest attestation baseline")
                if enforcement.get("authn_failure"):
                    cert_status = enforcement.get("certificate_status") or {}
                    raise HTTPException(
                        status_code=401,
                        detail=f"Invalid agent certificate: {cert_status.get('reason', 'invalid')}",
                    )

            if drift_dict and float(drift_dict.get("score", 0.0)) > 0:
                drift_event = build_drift_event(
                    tenant_id=tid,
                    agent_id=agent_id,
                    attestation_id=latest_attestation.get("attestation_id"),
                    certificate_id=certificate_id or None,
                    assessment=DriftAssessment(
                        score=float(drift_dict.get("score", 0.0)),
                        severity=str(drift_dict.get("severity", "none")),
                        reasons=[str(v) for v in drift_dict.get("reasons", [])],
                    ),
                    request_id=request_id,
                )
                attestation_store.insert_drift_event(tenant_id=tid, event=drift_event)

                log_event(
                    AuditEventType.THREAT_STEP_UP if decision.get("action") == "step_up" else AuditEventType.THREAT_BLOCK,
                    AuditOutcome.FAILURE if decision.get("action") == "block" else AuditOutcome.UNKNOWN,
                    tenant_id=tid,
                    subject=user_id,
                    source_ip=ip or "0.0.0.0",
                    resource="/secure",
                    detail={
                        "agent_id": agent_id,
                        "drift_score": float(drift_dict.get("score", 0.0)),
                        "drift_reasons": [str(v) for v in drift_dict.get("reasons", [])],
                        "severity": str(drift_dict.get("severity", "none")),
                        "timing_ms": enforcement.get("timing", {}),
                    },
                    correlation_id=request_id,
                )

            if decision.get("action") == "block":
                raise HTTPException(
                    status_code=403,
                    detail={
                        "status": "blocked",
                        "message": "Agent attestation policy blocked request",
                        "decision": decision,
                        "drift": drift_dict,
                        "timing_ms": enforcement.get("timing", {}),
                    },
                )
            if decision.get("action") == "step_up":
                return Response(
                    content=(
                        '{"status":"step_up","reason":"agent_policy","score":'
                        + str(breakdown.final_score)
                        + ',"timing_ms":'
                        + __import__("json").dumps(enforcement.get("timing", {}), separators=(",", ":"))
                        + "}"
                    ),
                    status_code=202,
                    media_type="application/json",
                )

    # ── 5. Update profile and graph ───────────────────────────────────────────
    ml_model.update_profile(user_id, current, redis=tr)
    session_graph.add_event(user_id, current, geo, redis=tr)

    # ── 5a. UIS Narrative Enrichment (v1.1) ────────────────────────────────────
    uis_narrative = uis_enrich_event(user_id, current, breakdown, threat, graph_result)

    # ── 6. Async ClickHouse logging ───────────────────────────────────────────
    asyncio.create_task(
        async_pipeline.process_event(
            request_id, user_id, current, breakdown, threat, graph_result,
            tenant_id=tid,
            uis_narrative=uis_narrative,
        )
    )

    # ── 7. Bump daily counter ─────────────────────────────────────────────────
    increment_event_counter(breakdown.tier.value, tenant_id=tid)

    bd = breakdown.to_dict()
    tc = threat.to_dict()
    gr = graph_result.to_dict()

    if breakdown.tier == RiskTier.REVOKE:
        push_baseline_history(user_id, baseline, tenant_id=tid)
        revoke_token(jti, ttl_seconds=3600, tenant_id=tid)
        asyncio.create_task(handle_revoke(user_id, request_id, jti, bd, current, tc, gr))
        return Response(
            content='{"status":"revoked","message":"Token revoked due to critical risk signals"}',
            status_code=401, media_type="application/json",
        )

    if breakdown.tier == RiskTier.BLOCK:
        asyncio.create_task(handle_block(user_id, request_id, bd, current, tc, gr))
        raise HTTPException(
            status_code=403,
            detail={"status": "blocked", "score": breakdown.final_score, "reasons": breakdown.reasons},
        )

    if breakdown.tier == RiskTier.STEP_UP:
        asyncio.create_task(handle_step_up(user_id, request_id))
        return Response(
            content=f'{{"status":"step_up","score":{breakdown.final_score}}}',
            status_code=202, media_type="application/json",
        )

    # Include UIS narrative in response for non-ALLOW tiers too
    response = {
        "status": "ok",
        "request_id": request_id,
        "score": breakdown.final_score,
        "tier": breakdown.tier.value,
        "uis_narrative": uis_narrative.to_dict() if uis_narrative else None,
    }
    return response


# ── Profile endpoints ─────────────────────────────────────────────────────────

@app.get("/profile/{user_id}")
async def get_profile(
    user_id: str,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    tr      = TenantRedis(get_redis(), tenant.tenant_id)
    profile = ml_model.get_profile(user_id, redis=tr)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    return {"user_id": user_id, "tenant_id": tenant.tenant_id, "profile": profile}


@app.delete("/profile/{user_id}")
async def reset_profile(
    user_id: str,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    tr = TenantRedis(get_redis(), tenant.tenant_id)
    ml_model.reset_profile(user_id, redis=tr)
    return {"status": "reset", "user_id": user_id}


# ── Manual revocation ─────────────────────────────────────────────────────────

@app.post("/revoke")
async def manual_revoke(
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    jti = body.get("jti")
    if not jti:
        raise HTTPException(status_code=400, detail="'jti' field required")
    ttl = int(body.get("ttl_seconds", 3600))
    revoke_token(jti, ttl_seconds=ttl, tenant_id=tenant.tenant_id)
    log_event(AuditEventType.AUTH_TOKEN_REVOKED, AuditOutcome.SUCCESS,
              tenant_id=tenant.tenant_id, subject=_tenant_subject(tenant),
              resource=f"jti:{jti}", detail={"ttl_seconds": ttl, "manual": True})
    return {"status": "revoked", "jti": jti, "ttl_seconds": ttl}


# ── Tenant management (admin) ─────────────────────────────────────────────────

@app.get("/admin/tenants")
async def list_tenants(tenant: TenantContext = Depends(require_role(Role.ADMIN))):
    tenants = tenant_store.list_tenants()
    log_event(AuditEventType.ACCESS_GRANTED, AuditOutcome.SUCCESS,
              tenant_id=tenant.tenant_id, subject=_tenant_subject(tenant),
              resource="/admin/tenants", detail={"action": "list"})
    return {"tenants": [
        {"id": t.id, "name": t.name, "plan": t.plan.value,
         "is_active": t.is_active, "owner_email": t.owner_email,
         "created_at": t.created_at.isoformat()}
        for t in tenants
    ]}


@app.post("/admin/tenants", status_code=201)
async def create_tenant(body: dict, tenant: TenantContext = Depends(require_role(Role.OWNER))):
    name  = body.get("name", "").strip()
    email = body.get("owner_email", "").strip()
    plan  = Plan(body.get("plan", "free"))
    if not name:
        raise HTTPException(status_code=400, detail="'name' required")
    new_tenant, raw_key = tenant_store.create_tenant(name=name, owner_email=email, plan=plan)
    log_event(AuditEventType.TENANT_CREATED, AuditOutcome.SUCCESS,
              tenant_id=tenant.tenant_id, subject=_tenant_subject(tenant),
              resource=f"tenant:{new_tenant.id}", detail={"name": name, "plan": plan.value})
    return {
        "tenant":  {"id": new_tenant.id, "name": new_tenant.name, "plan": new_tenant.plan.value},
        "api_key": raw_key,
        "warning": "Save this API key now — it will NOT be shown again.",
    }


@app.get("/admin/tenants/{tenant_id}/keys")
async def list_keys(tenant_id: str, tenant: TenantContext = Depends(require_role(Role.ADMIN))):
    if tenant_id != tenant.tenant_id and tenant.role != "owner":
        raise HTTPException(status_code=403, detail="Cannot list keys for another tenant")
    keys = tenant_store.list_api_keys(tenant_id)
    return {"keys": [
        {"id": k.id, "name": k.name, "prefix": k.key_prefix,
         "role": k.role, "is_active": k.is_active, "created_at": k.created_at.isoformat(),
         "last_used": k.last_used.isoformat() if k.last_used else None}
        for k in keys
    ]}


@app.post("/admin/tenants/{tenant_id}/keys", status_code=201)
async def create_key(tenant_id: str, body: dict, tenant: TenantContext = Depends(require_role(Role.ADMIN))):
    if tenant_id != tenant.tenant_id and tenant.role != "owner":
        raise HTTPException(status_code=403, detail="Cannot create keys for another tenant")
    name = body.get("name", "default").strip()
    role = body.get("role", "readonly")
    if str(role).strip().lower() == "owner" and tenant.role != "owner":
        raise HTTPException(status_code=403, detail="Only owner keys can create owner keys")
    try:
        record, raw_key = tenant_store.create_api_key(tenant_id=tenant_id, name=name, role=role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_event(
        AuditEventType.API_KEY_CREATED,
        AuditOutcome.SUCCESS,
        tenant_id=tenant.tenant_id,
        subject=tenant.api_key_id,
        resource=f"tenant:{tenant_id}:key:{record.id}",
        detail={"target_tenant_id": tenant_id, "key_name": name, "role": record.role},
    )
    return {"key_id": record.id, "prefix": record.key_prefix, "api_key": raw_key,
            "role": record.role,
            "warning": "Save this API key now — it will NOT be shown again."}


@app.delete("/admin/tenants/{tenant_id}/keys/{key_id}")
async def revoke_key(tenant_id: str, key_id: str, tenant: TenantContext = Depends(require_role(Role.ADMIN))):
    if tenant_id != tenant.tenant_id and tenant.role != "owner":
        raise HTTPException(status_code=403, detail="Cannot revoke keys for another tenant")
    tenant_store.revoke_api_key(key_id=key_id, tenant_id=tenant_id)
    log_event(
        AuditEventType.API_KEY_REVOKED,
        AuditOutcome.SUCCESS,
        tenant_id=tenant.tenant_id,
        subject=tenant.api_key_id,
        resource=f"tenant:{tenant_id}:key:{key_id}",
        detail={"target_tenant_id": tenant_id},
    )
    return {"status": "revoked", "key_id": key_id}


# ── AWS onboarding ────────────────────────────────────────────────────────────

@app.post("/onboarding/aws/external-id")
async def aws_external_id(_tenant: TenantContext = Depends(require_role(Role.ADMIN))):
    from onboarding.aws_connector import generate_external_id
    return {"external_id": generate_external_id()}


@app.post("/onboarding/aws/test")
async def aws_test(body: dict, tenant: TenantContext = Depends(require_role(Role.ADMIN))):
    from onboarding.aws_connector import AwsConnectionConfig, test_connection
    try:
        cfg = AwsConnectionConfig(
            tenant_id=tenant.tenant_id,
            account_id=body["account_id"],
            scan_role_arn=body["scan_role_arn"],
            external_id=body["external_id"],
            regions=body.get("regions", ["us-east-1"]),
        )
    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"Missing field: {e}")
    result = test_connection(cfg)
    return {
        "success":     result.success,
        "account_id":  result.account_id,
        "permissions": {"iam": result.iam_ok, "ec2": result.ec2_ok,
                        "s3": result.s3_ok, "guardduty": result.guardduty_ok},
        "errors":      result.errors,
        "warnings":    result.warnings,
    }

# ── Session Intelligence (/api/sessions) ──────────────────────────────────────

@app.get("/api/sessions")
async def api_sessions(
    limit: int = 50,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """
    Return per-user risk profiles for the Sessions Intelligence page.
    Aggregates from Redis ml_model profiles — no ClickHouse needed.
    """
    r  = get_redis()
    tr = TenantRedis(r, tenant.tenant_id)

    # Scan for profile keys in this tenant's namespace
    pattern = f"t:{tenant.tenant_id}:profile:*"
    try:
        keys = r.keys(pattern)
    except Exception:
        keys = []

    profiles = []
    for key in keys[:limit]:
        try:
            # key format: t:{tid}:profile:{user_id}
            user_id = key.decode("utf-8").split(":")[-1] if isinstance(key, bytes) else key.split(":")[-1]
            raw = r.hgetall(key)
            if not raw:
                continue
            decoded = {
                k.decode("utf-8") if isinstance(k, bytes) else k:
                v.decode("utf-8") if isinstance(v, bytes) else v
                for k, v in raw.items()
            }
            profiles.append({
                "user_id":   user_id,
                "avg_score": float(decoded.get("score_ema", 50)),
                "last_tier": decoded.get("last_tier", "ALLOW"),
                "requests":  int(decoded.get("request_count", 0)),
                "countries": [c for c in decoded.get("countries", "").split(",") if c],
                "tor_hits":  int(decoded.get("tor_hits", 0)),
                "last_seen": decoded.get("last_seen", ""),
            })
        except Exception:
            continue

    # Sort by highest risk first
    profiles.sort(key=lambda p: p["avg_score"])

    return {"profiles": profiles, "total": len(profiles), "tenant_id": tenant.tenant_id}


# ── Cloud Posture Findings (/api/cloud-findings) ───────────────────────────────

@app.get("/api/cloud-findings")
async def api_cloud_findings(
    limit: int = 100,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """
    Return the latest cloud posture findings for this tenant.
    Queries ClickHouse remediation_actions table which Aegis CSPM writes to.
    Falls back to Redis-cached last scan if ClickHouse unavailable.
    """
    try:
        rows = clickhouse_client.query_recent_events(
            tenant.tenant_id, limit=min(limit, 500)
        )
        # Filter for scan findings (event_type = "finding")
        findings = [r for r in rows if r.get("event_type") in ("finding", "scan_finding")]
    except Exception:
        findings = []

    # Build severity summary
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low").lower()
        if sev in summary:
            summary[sev] += 1

    return {
        "findings": findings,
        "summary": summary,
        "total": len(findings),
        "tenant_id": tenant.tenant_id,
    }


# ── Audit Log endpoint (OWNER only) ────────────────────────────────────────────

@app.get("/api/audit")
async def api_audit_log(
    limit: int = 100,
    tenant: TenantContext = Depends(require_role(Role.OWNER)),
):
    """
    Return recent audit log entries for this tenant.
    OWNER role required — audit logs are the most sensitive data in the platform.
    """
    from pathlib import Path
    import json as _json
    from modules.security.audit_log import AUDIT_FILE

    path = Path(AUDIT_FILE)
    entries = []
    try:
        if path.exists():
            lines = path.read_text().splitlines()[-limit:]
            for line in lines:
                try:
                    entry = _json.loads(line)
                    if entry.get("tenant_id") in (tenant.tenant_id, "_global_"):
                        entries.append(entry)
                except Exception:
                    continue
    except Exception:
        pass

    return {"entries": entries[-limit:], "total": len(entries)}


# ── Trust Graph endpoints ──────────────────────────────────────────────────────

# ── Blast Radius Simulator endpoints ──────────────────────────────────────────

@app.post("/api/simulate/blast_radius")
async def api_blast_radius(
    body: dict,
    tenant: TenantContext = Depends(require_feature("ent.blast_radius")),
):
    """
    POST /api/simulate/blast_radius

    Compute the blast radius if a given agent is compromised.

    Request body:
      { "agent_label": "<agent_id or subject>", "max_hops": 6 }

    Returns reachability graph, impact score (0-100), risk tier,
    and any policy bundles that intersect the blast radius.
    """
    agent_label = str(body.get("agent_label") or "").strip()
    if not agent_label:
        raise HTTPException(status_code=400, detail="'agent_label' is required")
    max_hops = int(body.get("max_hops") or 6)
    max_hops = max(1, min(max_hops, 10))

    result = blast_radius.simulate_blast_radius(
        tenant_id=tenant.tenant_id,
        agent_label=agent_label,
        max_hops=max_hops,
    )
    if not result.error:
        blast_radius.store_simulation(result)
    return result.as_dict()


@app.get("/api/simulate/blast_radius/history")
async def api_blast_radius_history(
    agent_label: str | None = None,
    limit: int = 20,
    tenant: TenantContext = Depends(require_feature("ent.blast_radius")),
):
    """
    GET /api/simulate/blast_radius/history

    Return recent blast radius simulation history for the tenant.
    Optional ?agent_label= to filter by a specific agent.
    """
    history = blast_radius.list_simulations(
        tenant_id=tenant.tenant_id,
        agent_label=agent_label,
        limit=min(limit, 100),
    )
    return {"tenant_id": tenant.tenant_id, "simulations": history, "count": len(history)}


# ── Intent Correlation endpoints ───────────────────────────────────────────────

# ── ZTIX Exchange endpoints ───────────────────────────────────────────────────

@app.post("/api/ztix/simulate")
async def api_ztix_simulate(
    body: dict,
    tenant: TenantContext = Depends(get_tenant),
):
    """
    POST /api/ztix/simulate — **DEMO ONLY**

    This endpoint is a hard-coded sales demo of the Zero-Trust Identity
    Exchange flow. The returned ``ztix_token`` is **not** cryptographically
    bound to anything — there is no signature, no DPoP JKT, no proof of
    possession. Do not present it as a real bearer.

    A real signed ZTIX token format will live at ``/api/ztix/token`` once
    that endpoint ships. Until then, the response carries ``demo: true``
    and a ``warning`` field so consumers cannot accidentally treat the
    output as production. The ``proof_of_control`` module backs the *real*
    ZTIX feature ("Periodic Proof of Control") that operates against
    federation verifiers — see /api/federation/verifiers/proof-* routes.

    Request: { "agent_a": "agt-orchestrator", "agent_b": "agt-analyst" }
    """
    agent_a = str(body.get("agent_a") or "").strip()
    agent_b = str(body.get("agent_b") or "").strip()
    if not agent_a or not agent_b:
        raise HTTPException(status_code=400, detail="'agent_a' and 'agent_b' are required")

    # Graph snapshot before
    graph_before = trust_graph.get_graph_data(tenant_id=tenant.tenant_id, limit=500)
    nodes_before = len(graph_before.get("nodes", []))
    edges_before = len(graph_before.get("edges", []))

    # Derive RFC-style subject from agent label
    if agent_a.startswith("agt-"):
        subject = "agent-" + agent_a[4:] + "@acme.svc"
    else:
        subject = agent_a + "@acme.svc"

    uis_event = normalize_from_protocol(
        protocol="spiffe",
        tenant_id=tenant.tenant_id,
        tenant_name=tenant.tenant_name,
        subject=subject,
        claims={
            "sub": subject,
            "iss": "https://auth.acme.io",
            "agent_id": agent_a,
            "attestation_id": f"att-{agent_a.replace('agt-', '')}-001",
        },
        request_context={
            "request_id": str(uuid.uuid4()),
            "ip": "10.0.0.1",
            "user_agent": "ztix-exchange/1.0",
        },
        risk_context={
            "risk_score": 22,
            "risk_tier": "allow",
            "indicators": [],
        },
    )
    uis_store.insert_event(tenant_id=tenant.tenant_id, event=uis_event)

    # Graph snapshot after
    graph_after = trust_graph.get_graph_data(tenant_id=tenant.tenant_id, limit=500)
    nodes_after = len(graph_after.get("nodes", []))
    edges_after = len(graph_after.get("edges", []))

    now = datetime.datetime.now(datetime.timezone.utc)
    ztix_token = {
        "ztix_id": f"ztix-demo-{str(uuid.uuid4())[:8]}",
        "bound_to": agent_a,
        "issued_at": now.isoformat(),
        "expires_in": 300,
        "scope": ["read:data", "execute:tools"],
        "trust_level": "verified",
        # Make the demo nature explicit on the token itself — operators
        # logging or persisting these tokens see the marker even if they
        # miss the wrapping response field.
        "demo": True,
        "signature": None,
        "binding": None,
    }

    return {
        "demo": True,
        "warning": (
            "This is a sales-demo simulation of ZTIX, not a production "
            "exchange. The returned ztix_token is not cryptographically "
            "bound to any key and must not be presented as a real bearer. "
            "A signed token format will ship at /api/ztix/token in a "
            "future sprint."
        ),
        "production_endpoint": None,
        "event": uis_event,
        "ztix_token": ztix_token,
        "graph_delta": {
            "nodes_before": nodes_before,
            "nodes_after": nodes_after,
            "edges_before": edges_before,
            "edges_after": edges_after,
        },
    }


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

@app.post("/api/admin/staged-rollout/grant")
async def api_staged_grant(
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.OWNER)),
):
    """Grant a tenant access to a feature outside its commercial tier.
    Body: {tenant_id, feature_key, granted_by, reason?}."""
    from modules.product import staged_rollout  # noqa: PLC0415
    target = str(body.get("tenant_id") or "").strip()
    feature = str(body.get("feature_key") or "").strip()
    granted_by = str(body.get("granted_by") or "").strip()
    if not target or not feature or not granted_by:
        raise HTTPException(
            status_code=400,
            detail="'tenant_id', 'feature_key', and 'granted_by' are required",
        )
    try:
        out = staged_rollout.grant_access(
            tenant_id=target, feature_key=feature,
            granted_by=granted_by, reason=str(body.get("reason") or ""),
        )
        return out.as_dict()
    except staged_rollout.AllowlistError as exc:
        reason = str(exc)
        code = 404 if reason == "unknown_feature_key" else 409
        raise HTTPException(status_code=code, detail={"error": reason}) from exc


@app.post("/api/admin/staged-rollout/revoke")
async def api_staged_revoke(
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.OWNER)),
):
    """Revoke an active grant. Body: {tenant_id, feature_key, revoked_by, reason?}."""
    from modules.product import staged_rollout  # noqa: PLC0415
    target = str(body.get("tenant_id") or "").strip()
    feature = str(body.get("feature_key") or "").strip()
    revoked_by = str(body.get("revoked_by") or "").strip()
    if not target or not feature or not revoked_by:
        raise HTTPException(
            status_code=400,
            detail="'tenant_id', 'feature_key', and 'revoked_by' are required",
        )
    out = staged_rollout.revoke_access(
        tenant_id=target, feature_key=feature,
        revoked_by=revoked_by, reason=str(body.get("reason") or ""),
    )
    if not out.get("revoked"):
        raise HTTPException(status_code=404, detail=out)
    return out


@app.get("/api/admin/staged-rollout/{tenant_id}")
async def api_staged_list(
    tenant_id: str,
    include_revoked: bool = False,
    tenant: TenantContext = Depends(require_role(Role.OWNER)),
):
    """List grants (active + optionally revoked) for one tenant."""
    from modules.product import staged_rollout  # noqa: PLC0415
    items = staged_rollout.list_grants(tenant_id, include_revoked=include_revoked)
    return {
        "tenant_id": tenant_id,
        "count": len(items),
        "grants": [g.as_dict() for g in items],
    }


@app.get("/api/admin/staged-rollout/feature/{feature_key}")
async def api_staged_list_for_feature(
    feature_key: str,
    tenant: TenantContext = Depends(require_role(Role.OWNER)),
):
    """List every tenant currently allowlisted onto one feature."""
    from modules.product import staged_rollout  # noqa: PLC0415
    items = staged_rollout.list_active_grants_for_feature(feature_key)
    return {
        "feature_key": feature_key,
        "count": len(items),
        "grants": [g.as_dict() for g in items],
    }


# ── Edge enforcement parity (Cloudflare Worker snapshot endpoints) ────────────
#
# Pulled by edge/index.js scheduled() handler every 60s and cached in KV so
# the request-path edge checks (cert revocation + drift score gating) are
# O(1) and never block on the backend.  Authenticates via a shared
# X-Edge-Sync-Token header (set as a Cloudflare Worker secret).

import hmac as _edge_hmac  # noqa: E402

def _edge_sync_authorized(request: Request) -> bool:
    expected = (os.getenv("EDGE_SYNC_TOKEN") or "").strip()
    if not expected:
        return False
    presented = (request.headers.get("X-Edge-Sync-Token") or "").strip()
    return bool(presented) and _edge_hmac.compare_digest(presented, expected)


@app.get("/api/edge/revoked-certs")
async def api_edge_revoked_certs(request: Request):
    """Return every currently revoked attestation cert id for the worker
    to mirror into KV."""
    if not _edge_sync_authorized(request):
        raise HTTPException(status_code=401, detail="X-Edge-Sync-Token missing or invalid")
    from modules.identity import attestation_store  # noqa: PLC0415
    items = attestation_store.list_revoked_certs(limit=10_000)
    return {
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "count": len(items),
        "certs": [
            {"cert_id": it["certificate_id"],
             "reason": it.get("revocation_reason") or "revoked",
             "revoked_at": it.get("revoked_at")}
            for it in items
        ],
    }


@app.get("/api/edge/drift-snapshot")
async def api_edge_drift_snapshot(request: Request):
    """Return the current drift tier + score for every agent, for the
    worker to mirror into KV and reject high-drift requests at the edge."""
    if not _edge_sync_authorized(request):
        raise HTTPException(status_code=401, detail="X-Edge-Sync-Token missing or invalid")
    from modules.identity import permission_drift  # noqa: PLC0415
    snapshot = permission_drift.edge_drift_snapshot(limit=10_000)
    return {
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "count": len(snapshot),
        "agents": snapshot,
    }
