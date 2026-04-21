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
from fastapi.responses import FileResponse, HTMLResponse

from auth import verify_token
from config import DEV_MODE, OIDC_ISSUER, RATE_LIMIT_PER_MINUTE
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
def sdk_attest_agent(**kwargs):
    """Thin alias — maps tenant_name→owner_org for sdk_create_attestation."""
    if "tenant_name" in kwargs:
        kwargs["owner_org"] = kwargs.pop("tenant_name")
    return sdk_create_attestation(**kwargs)
from modules.product import metering as feature_metering
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


def _encode_cursor(value: str) -> str:
    return __import__("base64").urlsafe_b64encode(value.encode("utf-8")).decode("utf-8")


def _decode_cursor(value: str | None) -> str | None:
    if not value:
        return None
    try:
        raw = __import__("base64").urlsafe_b64decode(value.encode("utf-8"))
        return raw.decode("utf-8")
    except Exception:
        return None


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


async def _startup_checks() -> None:
    if DEV_MODE:
        logger.warning("DEV_MODE=true — JWT auth disabled. Not for production.")
    if not OIDC_ISSUER and not DEV_MODE:
        logger.warning("OIDC_ISSUER not set — authenticated endpoints will 401.")

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

    _data_dir = os.path.dirname(os.getenv("DATA_DB_PATH", "/data/tokendna.db"))
    if _data_dir:
        os.makedirs(_data_dir, exist_ok=True)
    tenant_store.init_db()
    attestation_store.init_db()
    uis_store.init_db()
    trust_graph.init_db()
    intent_correlation.init_db()
    policy_guard.init_db()
    permission_drift.init_db()
    agent_lifecycle.init_db()
    mcp_inspector.init_db()
    cert_dashboard.init_db()
    policy_advisor.init_db()
    from modules.identity import passport as _passport_init  # noqa: PLC0415
    from modules.identity import verifier_reputation as _reputation_init  # noqa: PLC0415
    from modules.identity import proof_of_control as _poc_init  # noqa: PLC0415
    _passport_init.init_passport_db()
    _reputation_init.init_reputation_db()
    _poc_init.init_db()
    ct_log.init_db()
    network_intel.init_db()
    compliance.init_db()
    policy_bundles.init_db()
    decision_audit.init_db()
    trust_federation.init_db()
    feature_metering.init_db()

    from modules.identity.cache_redis import is_available as redis_ok
    logger.info("Redis: %s", "connected" if redis_ok() else "UNREACHABLE")
    logger.info("ClickHouse: %s", "connected" if clickhouse_client.is_available() else "UNREACHABLE")

    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, threat_intel._ensure_tor_list)

    # Emit startup audit event (AU-2: application startup)
    log_event(AuditEventType.STARTUP, AuditOutcome.SUCCESS,
              detail={"version": APP_VERSION, "dev_mode": DEV_MODE})


# ── Rate limiting dependency ──────────────────────────────────────────────────

async def check_rate_limit(
    request: Request,
    tenant: TenantContext = Depends(get_tenant),
) -> None:
    ip  = request.client.host if request.client else "unknown"
    key = f"rate:{ip}"
    # Rate limit is now per-tenant so one customer can't starve another
    count = increment_rate(key, window_seconds=60, tenant_id=tenant.tenant_id)
    if count > RATE_LIMIT_PER_MINUTE:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded ({RATE_LIMIT_PER_MINUTE} req/min)",
            headers={"Retry-After": "60"},
        )


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


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    if not _DASHBOARD_PATH.exists():
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return FileResponse(_DASHBOARD_PATH)


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

    dependencies = {
        "sqlite": {"ok": True},
        "redis": {"ok": redis_ok()},
        "clickhouse": {"ok": clickhouse_client.is_available()},
        "storage_backend": db_backend.get_backend_config().__dict__,
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
        "slo": slo,
        "posture": posture,
    }


@app.get("/api/product/features")
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


@app.post("/api/product/features/evaluate")
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


# ── Consolidation endpoints: UIS + Agent Attestation + MCP Verification ──────

@app.post("/api/uis/normalize")
async def api_uis_normalize(
    body: dict,
    request: Request,
    response: Response,
    tenant: TenantContext = Depends(get_tenant),
):
    protocol = str(body.get("protocol", "custom"))
    claims = body.get("claims") or {}
    provided_context = body.get("request_context") or {}
    request_context = {
        "request_id": str(uuid.uuid4()),
        "ip": request.client.host if request.client else "",
        "user_agent": request.headers.get("user-agent", ""),
        **provided_context,
    }
    risk_context = body.get("risk_context") or {}
    subject = str(body.get("subject") or claims.get("sub") or "unknown")

    event = normalize_from_protocol(
        protocol=protocol,
        tenant_id=tenant.tenant_id,
        tenant_name=tenant.tenant_name,
        subject=subject,
        claims=claims,
        request_context=request_context,
        risk_context=risk_context,
    )
    validation_warnings = validate_uis_event(event)
    if validation_warnings:
        for warning in validation_warnings:
            logging.getLogger(__name__).warning("UIS validation warning: %s", warning)
    uis_store.insert_event(tenant_id=tenant.tenant_id, event=event)
    response.headers["X-UIS-Version"] = "1.0"
    return {
        "tenant_id": tenant.tenant_id,
        "uis_version": "1.0",
        "uis_event": event,
        "validation_warnings": validation_warnings,
    }


@app.post("/api/agent/attest")
async def api_agent_attest(
    body: dict,
    tenant: TenantContext = Depends(get_tenant),
):
    agent_id = str(body.get("agent_id", "")).strip()
    if not agent_id:
        raise HTTPException(status_code=400, detail="'agent_id' is required")

    record = create_attestation_record(
        agent_id=agent_id,
        owner_org=str(body.get("owner_org") or tenant.tenant_name),
        created_by=str(body.get("created_by") or "unknown"),
        soul_hash=str(body.get("soul_hash") or ""),
        directive_hashes=list(body.get("directive_hashes") or []),
        model_fingerprint=str(body.get("model_fingerprint") or ""),
        mcp_manifest_hash=str(body.get("mcp_manifest_hash") or ""),
        auth_method=str(body.get("auth_method") or "token"),
        dpop_bound=bool(body.get("dpop_bound", False)),
        mtls_bound=bool(body.get("mtls_bound", False)),
        behavior_confidence=float(body.get("behavior_confidence", 0.0)),
        declared_purpose=str(body.get("declared_purpose") or "unspecified"),
        scope=list(body.get("scope") or []),
        delegation_chain=list(body.get("delegation_chain") or []),
        policy_trace_id=body.get("policy_trace_id"),
        runtime_context=dict(body.get("runtime_context") or {}),
        behavior_features=dict(body.get("behavior_features") or {}),
    )
    attestation_payload = record.to_dict()
    attestation_store.insert_attestation(tenant_id=tenant.tenant_id, record=attestation_payload)

    issue_cert = bool(body.get("issue_certificate", False))
    if issue_cert:
        cert = issue_certificate(
            tenant_id=tenant.tenant_id,
            attestation_id=attestation_payload["attestation_id"],
            subject=agent_id,
            issuer=str(body.get("issuer") or "TokenDNA Trust Authority"),
            claims={
                "integrity_digest": attestation_payload["integrity_digest"],
                "agent_dna_fingerprint": attestation_payload["agent_dna_fingerprint"],
                "who": attestation_payload["who"],
                "what": attestation_payload["what"],
                "how": attestation_payload["how"],
                "why": attestation_payload["why"],
            },
            ttl_hours=int(body.get("certificate_ttl_hours", 24)),
        )
        attestation_store.insert_certificate(tenant_id=tenant.tenant_id, certificate=cert)
        return {"tenant_id": tenant.tenant_id, "attestation": attestation_payload, "certificate": cert}

    return {"tenant_id": tenant.tenant_id, "attestation": attestation_payload}


@app.post("/api/mcp/verify")
async def api_mcp_verify(
    body: dict,
    tenant: TenantContext = Depends(get_tenant),
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


@app.get("/api/agent/attestations")
async def api_list_agent_attestations(
    page_size: int = 50,
    agent_id: str | None = None,
    cursor: str | None = None,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    page = attestation_store.list_attestations_paginated(
        tenant_id=tenant.tenant_id,
        page_size=min(max(page_size, 1), 200),
        cursor=cursor,
        agent_id=agent_id,
    )
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(page["items"]),
        "attestations": page["items"],
        "next_cursor": page["next_cursor"],
        "has_more": page["has_more"],
        "page_size": page["page_size"],
    }


@app.get("/api/agent/attestations/{attestation_id}")
async def api_get_agent_attestation(
    attestation_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    row = attestation_store.get_attestation(tenant_id=tenant.tenant_id, attestation_id=attestation_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Attestation not found")
    return {"tenant_id": tenant.tenant_id, "attestation": row}


@app.get("/api/agent/dna/{agent_id}")
async def api_get_agent_dna(
    agent_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    """Return the stored behavioral DNA for *agent_id*.

    Response fields:
    - ``dna``: the DNA dict, or null if not yet computed
    - ``fresh``: True if ``computed_at`` is within the last hour
    """
    from modules.identity import agent_dna as _agent_dna  # noqa: PLC0415
    from modules.identity.uis_store import init_db as _uis_init  # noqa: PLC0415
    _uis_init()
    _agent_dna.build_agent_dna_store()

    dna = _agent_dna.get_agent_dna(tenant_id=tenant.tenant_id, agent_id=agent_id)
    fresh = False
    if dna:
        try:
            computed_at = datetime.datetime.fromisoformat(dna["computed_at"])
            age = datetime.datetime.now(datetime.timezone.utc) - computed_at
            fresh = age.total_seconds() < 3600
        except Exception:  # noqa: BLE001
            pass
    return {"tenant_id": tenant.tenant_id, "agent_id": agent_id, "dna": dna, "fresh": fresh}


@app.post("/api/agent/dna/{agent_id}/refresh")
async def api_refresh_agent_dna(
    agent_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    """Synchronously recompute behavioral DNA for *agent_id* and return it."""
    from modules.identity import agent_dna as _agent_dna  # noqa: PLC0415
    from modules.identity.uis_store import init_db as _uis_init  # noqa: PLC0415
    _uis_init()
    _agent_dna.build_agent_dna_store()

    dna = _agent_dna.refresh_agent_dna(tenant_id=tenant.tenant_id, agent_id=agent_id)
    return {"tenant_id": tenant.tenant_id, "agent_id": agent_id, "dna": dna}


@app.post("/api/agent/certificates/verify")
async def api_verify_agent_certificate(
    body: dict,
    tenant: TenantContext = Depends(get_tenant),
):
    certificate = body.get("certificate")
    if not isinstance(certificate, dict):
        raise HTTPException(status_code=400, detail="'certificate' must be an object")
    if str(certificate.get("tenant_id", "")) != tenant.tenant_id:
        raise HTTPException(status_code=403, detail="Certificate tenant mismatch")

    result = verify_certificate(certificate)
    if result.get("valid"):
        stored = attestation_store.get_certificate(tenant_id=tenant.tenant_id, certificate_id=certificate["certificate_id"])
        if stored is None:
            attestation_store.insert_certificate(tenant_id=tenant.tenant_id, certificate=certificate)
    return {"tenant_id": tenant.tenant_id, "verification": result}


@app.get("/api/threat-intel/feed")
async def api_threat_intel_feed(
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
    return {"tenant_id": tenant.tenant_id, "count": len(rows), "signals": rows}


@app.get("/api/uis/spec")
async def api_uis_spec(
    _tenant: TenantContext = Depends(get_tenant),
):
    return {"uis_spec": get_uis_spec()}


@app.get("/api/oss/schema-bundle")
async def api_schema_bundle(
    _tenant: TenantContext = Depends(get_tenant),
):
    return {"bundle": schema_registry.build_schema_bundle()}


@app.get("/api/oss/schema-bundle/{artifact_name}")
async def api_schema_artifact(
    artifact_name: str,
    _tenant: TenantContext = Depends(get_tenant),
):
    artifact = schema_registry.get_schema_artifact(artifact_name)
    if artifact is None:
        raise HTTPException(status_code=404, detail="Schema artifact not found")
    return {"artifact": artifact}


@app.get("/api/uis/schema/artifacts")
async def api_uis_schema_artifacts(
    _tenant: TenantContext = Depends(get_tenant),
):
    return {"artifacts": schema_registry.build_schema_artifacts()}


@app.get("/api/schema/uis.json")
async def api_schema_uis_json(
    response: Response,
    _tenant: TenantContext = Depends(get_tenant),
):
    _schema_path = Path(__file__).parent / "modules" / "identity" / "uis_schema_v1.json"
    with _schema_path.open(encoding="utf-8") as _f:
        _schema = json.load(_f)
    response.headers["X-UIS-Schema-Version"] = "1.0"
    response.headers["Content-Type"] = "application/json"
    return _schema


@app.get("/api/schema/attestation.json")
async def api_schema_attestation_json(
    _tenant: TenantContext = Depends(get_tenant),
):
    return schema_registry.build_attestation_schema_artifact()


@app.post("/api/oss/sdk/normalize")
async def api_sdk_wrapper_normalize(
    body: dict,
    request: Request,
    tenant: TenantContext = Depends(get_tenant),
):
    protocol = str(body.get("protocol", "custom"))
    payload = body.get("payload") or {}
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="'payload' must be an object")
    options = body.get("options") or {}
    if not isinstance(options, dict):
        raise HTTPException(status_code=400, detail="'options' must be an object when provided")
    normalized = sdk_normalize_event(
        protocol=protocol,
        tenant_id=tenant.tenant_id,
        tenant_name=tenant.tenant_name,
        payload=payload,
        request_context={
            "request_id": str(options.get("request_id") or str(uuid.uuid4())),
            "ip": str(options.get("ip") or (request.client.host if request.client else "")),
            "user_agent": str(options.get("user_agent") or request.headers.get("user-agent", "")),
        },
        risk_context=(options.get("risk_context") if isinstance(options.get("risk_context"), dict) else {}),
    )
    uis_store.insert_event(tenant_id=tenant.tenant_id, event=normalized)
    return {"tenant_id": tenant.tenant_id, "uis_event": normalized}


@app.post("/api/oss/sdk/attest")
async def api_sdk_wrapper_attest(
    body: dict,
    tenant: TenantContext = Depends(get_tenant),
):
    options = body.get("options") or {}
    if not isinstance(options, dict):
        raise HTTPException(status_code=400, detail="'options' must be an object when provided")
    runtime_context = options.get("runtime_context") or {}
    if not isinstance(runtime_context, dict):
        raise HTTPException(status_code=400, detail="'runtime_context' must be an object when provided")
    behavior_features = options.get("behavior_features") or {}
    if not isinstance(behavior_features, dict):
        raise HTTPException(status_code=400, detail="'behavior_features' must be an object when provided")
    record = sdk_attest_agent(
        agent_id=str(body.get("agent_id", "")).strip(),
        tenant_name=tenant.tenant_name,
        created_by=str(body.get("created_by", "sdk-wrapper")),
        soul_hash=str(body.get("soul_hash", "")),
        directive_hashes=[str(v) for v in body.get("directive_hashes", []) if str(v)]
        if isinstance(body.get("directive_hashes"), list)
        else [],
        model_fingerprint=str(body.get("model_fingerprint", "")),
        mcp_manifest_hash=str(body.get("mcp_manifest_hash", "")),
        declared_purpose=str(body.get("declared_purpose", "runtime_access")),
        scope=[str(v) for v in body.get("scope", []) if str(v)] if isinstance(body.get("scope"), list) else [],
        delegation_chain=[str(v) for v in body.get("delegation_chain", []) if str(v)]
        if isinstance(body.get("delegation_chain"), list)
        else [],
        auth_method=str(options.get("auth_method", "token")),
        dpop_bound=bool(options.get("dpop_bound", False)),
        mtls_bound=bool(options.get("mtls_bound", False)),
        behavior_confidence=float(options.get("behavior_confidence", 0.8)),
        runtime_context=runtime_context,
        behavior_features=behavior_features,
    )
    attestation_store.insert_attestation(tenant_id=tenant.tenant_id, record=record)
    return {"tenant_id": tenant.tenant_id, "attestation": record}


@app.post("/api/uis/adapters/normalize")
async def api_uis_adapter_normalize(
    body: dict,
    request: Request,
    tenant: TenantContext = Depends(get_tenant),
):
    protocol = str(body.get("protocol", "custom"))
    payload = body.get("payload") or {}
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="'payload' must be an object")

    provided_context = body.get("request_context") or {}
    if not isinstance(provided_context, dict):
        raise HTTPException(status_code=400, detail="'request_context' must be an object when provided")

    request_context = {
        "request_id": str(uuid.uuid4()),
        "ip": request.client.host if request.client else "",
        "user_agent": request.headers.get("user-agent", ""),
        **provided_context,
    }

    risk_context = body.get("risk_context") or {}
    if not isinstance(risk_context, dict):
        raise HTTPException(status_code=400, detail="'risk_context' must be an object when provided")

    event = normalize_with_adapter(
        protocol=protocol,
        tenant_id=tenant.tenant_id,
        tenant_name=tenant.tenant_name,
        payload=payload,
        request_context=request_context,
        risk_context=risk_context,
    )
    uis_store.insert_event(tenant_id=tenant.tenant_id, event=event)
    return {"tenant_id": tenant.tenant_id, "uis_event": event}


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


@app.post("/api/agent/certificates/issue")
async def api_issue_agent_certificate(
    body: dict,
    tenant: TenantContext = Depends(get_tenant),
):
    attestation_id = str(body.get("attestation_id", "")).strip()
    if not attestation_id:
        raise HTTPException(status_code=400, detail="'attestation_id' is required")

    record = attestation_store.get_attestation(tenant_id=tenant.tenant_id, attestation_id=attestation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Attestation not found")

    subject = str(body.get("subject") or record.get("who", {}).get("agent_id") or "unknown-agent")
    cert = issue_certificate(
        tenant_id=tenant.tenant_id,
        attestation_id=attestation_id,
        subject=subject,
        issuer=str(body.get("issuer") or "TokenDNA Trust Authority"),
        claims={
            "integrity_digest": record.get("integrity_digest"),
            "agent_dna_fingerprint": record.get("agent_dna_fingerprint"),
            "who": record.get("who", {}),
            "what": record.get("what", {}),
            "how": record.get("how", {}),
            "why": record.get("why", {}),
        },
        ttl_hours=int(body.get("certificate_ttl_hours", 24)),
    )
    attestation_store.insert_certificate(tenant_id=tenant.tenant_id, certificate=cert)
    ct_entry = ct_log.append_log_entry(
        tenant_id=tenant.tenant_id,
        certificate_id=cert["certificate_id"],
        attestation_id=attestation_id,
        action="issued",
        payload=cert,
    )
    return {"tenant_id": tenant.tenant_id, "certificate": cert, "transparency_log_entry": ct_entry}


@app.get("/api/agent/certificates/{certificate_id}")
async def api_get_agent_certificate(
    certificate_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    cert = attestation_store.get_certificate(tenant_id=tenant.tenant_id, certificate_id=certificate_id)
    if cert is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return {"tenant_id": tenant.tenant_id, "certificate": cert}


@app.get("/api/agent/certificates")
async def api_list_agent_certificates(
    limit: int = 50,
    subject: str | None = None,
    status: str | None = None,
    cursor: str | None = None,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    page = attestation_store.list_certificates_paginated(
        tenant_id=tenant.tenant_id,
        page_size=min(max(limit, 1), 200),
        cursor=cursor,
        subject=subject,
        status=status,
    )
    rows = page["items"]
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(rows),
        "certificates": rows,
        "next_cursor": page["next_cursor"],
        "has_more": page["has_more"],
        "page_size": page["page_size"],
    }


@app.get("/api/agent/certificates/status/{certificate_id}")
async def api_certificate_status(
    certificate_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    cert = attestation_store.get_certificate(tenant_id=tenant.tenant_id, certificate_id=certificate_id)
    verification = verify_certificate(cert) if cert is not None else None
    status = certificate_status_payload(certificate=cert, verification=verification)
    return {"tenant_id": tenant.tenant_id, "status": status}


@app.get("/api/agent/certificates/crl")
async def api_certificate_crl(
    limit: int = 1000,
    tenant: TenantContext = Depends(get_tenant),
):
    revoked = attestation_store.list_certificates(
        tenant_id=tenant.tenant_id,
        status="revoked",
        limit=min(max(limit, 1), 5000),
    )
    return {"crl": build_crl(tenant_id=tenant.tenant_id, revoked_certificates=revoked)}


@app.post("/api/agent/certificates/revoke")
async def api_revoke_agent_certificate(
    body: dict,
    tenant: TenantContext = Depends(get_tenant),
):
    certificate_id = str(body.get("certificate_id", "")).strip()
    if not certificate_id:
        raise HTTPException(status_code=400, detail="'certificate_id' is required")
    existing = attestation_store.get_certificate(tenant_id=tenant.tenant_id, certificate_id=certificate_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Certificate not found")

    revoked = revoke_certificate(existing, reason=str(body.get("reason") or "manual_revoke"))
    attestation_store.insert_certificate(tenant_id=tenant.tenant_id, certificate=revoked)
    ct_entry = ct_log.append_log_entry(
        tenant_id=tenant.tenant_id,
        certificate_id=certificate_id,
        attestation_id=str(revoked.get("attestation_id", "")),
        action="revoked",
        payload={
            "reason": revoked.get("revocation_reason"),
            "status": revoked.get("status"),
            "revoked_at": revoked.get("revoked_at"),
        },
    )
    log_event(
        AuditEventType.CONFIG_CHANGED,
        AuditOutcome.SUCCESS,
        tenant_id=tenant.tenant_id,
        subject=tenant.tenant_name,
        resource=f"certificate:{certificate_id}",
        detail={"action": "revoke_certificate", "reason": revoked.get("revocation_reason")},
    )
    return {"tenant_id": tenant.tenant_id, "certificate": revoked, "transparency_log_entry": ct_entry}


@app.get("/api/agent/ca-keys")
async def api_list_ca_keys(
    status: str | None = None,
    limit: int = 50,
    _tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    if status:
        rows = attestation_store.list_ca_keys(status=status, limit=min(max(limit, 1), 200))
    else:
        rows = attestation_store.list_ca_keys(limit=min(max(limit, 1), 200))
    return {"count": len(rows), "keys": rows}


@app.post("/api/agent/ca-keys")
async def api_upsert_ca_key(
    body: dict,
    _tenant: TenantContext = Depends(require_role(Role.OWNER)),
):
    key_id = str(body.get("key_id", "")).strip()
    algorithm = str(body.get("algorithm", "")).strip().upper()
    backend = str(body.get("backend", "")).strip().lower()
    if not key_id:
        raise HTTPException(status_code=400, detail="'key_id' is required")
    if algorithm not in {"HS256", "RS256"}:
        raise HTTPException(status_code=400, detail="'algorithm' must be HS256 or RS256")
    if backend not in {"software", "hsm", "aws_kms"}:
        raise HTTPException(status_code=400, detail="'backend' must be software, hsm, or aws_kms")

    attestation_store.upsert_ca_key(
        key_id=key_id,
        algorithm=algorithm,
        backend=backend,
        kms_key_id=(str(body.get("kms_key_id", "")).strip() or None),
        public_key_pem=(str(body.get("public_key_pem", "")).strip() or None),
        status=str(body.get("status", "active")),
        activated_at=(str(body.get("activated_at", "")).strip() or None),
        deactivated_at=(str(body.get("deactivated_at", "")).strip() or None),
        metadata=(body.get("metadata") if isinstance(body.get("metadata"), dict) else {}),
    )
    key = attestation_store.get_ca_key(key_id)
    return {"key": key}


@app.get("/api/agent/ca-keyring")
async def api_ca_keyring_preview(
    _tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    return {"configured_keyring": list_key_configs()}


@app.get("/api/agent/certificates/transparency-log")
async def api_certificate_transparency_log(
    limit: int = 100,
    tenant: TenantContext = Depends(get_tenant),
):
    rows = ct_log.list_log_entries(
        tenant_id=tenant.tenant_id,
        limit=min(max(limit, 1), 500),
    )
    return {"tenant_id": tenant.tenant_id, "count": len(rows), "entries": rows}


@app.get("/api/agent/certificates/transparency-log/verify")
async def api_verify_certificate_transparency_log(
    tenant: TenantContext = Depends(get_tenant),
):
    result = ct_log.verify_log_integrity(tenant_id=tenant.tenant_id)
    return {"tenant_id": tenant.tenant_id, "integrity": result}


@app.get("/api/uis/events")
async def api_list_uis_events(
    limit: int = 50,
    subject: str | None = None,
    cursor: str | None = None,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    decoded = _decode_cursor(cursor)
    rows, next_ts = uis_store.list_events_with_cursor(
        tenant_id=tenant.tenant_id,
        limit=min(max(limit, 1), 200),
        subject=subject,
        before_event_timestamp=decoded,
    )
    next_cursor = _encode_cursor(next_ts) if next_ts else None
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(rows),
        "events": rows,
        "next_cursor": next_cursor,
    }


@app.get("/api/uis/events/{event_id}")
async def api_get_uis_event(
    event_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    row = uis_store.get_event(tenant_id=tenant.tenant_id, event_id=event_id)
    if row is None:
        raise HTTPException(status_code=404, detail="UIS event not found")
    return {"tenant_id": tenant.tenant_id, "event": row}


@app.post("/api/agent/drift/assess")
async def api_assess_agent_drift(
    body: dict,
    tenant: TenantContext = Depends(get_tenant),
):
    agent_id = str(body.get("agent_id", "")).strip()
    if not agent_id:
        raise HTTPException(status_code=400, detail="'agent_id' is required")

    attestation = None
    attestation_id = str(body.get("attestation_id", "")).strip()
    if attestation_id:
        attestation = attestation_store.get_attestation(tenant_id=tenant.tenant_id, attestation_id=attestation_id)
    else:
        attestation = attestation_store.get_latest_attestation_for_agent(tenant_id=tenant.tenant_id, agent_id=agent_id)

    if attestation is None:
        raise HTTPException(status_code=404, detail="Attestation baseline not found")

    headers = body.get("request_headers") or {}
    if not isinstance(headers, dict):
        raise HTTPException(status_code=400, detail="'request_headers' must be an object")

    observed_scope = body.get("observed_scope") or []
    if not isinstance(observed_scope, list):
        raise HTTPException(status_code=400, detail="'observed_scope' must be an array")

    assessment = assess_runtime_drift(
        attestation=attestation,
        request_headers={str(k).lower(): str(v) for k, v in headers.items()},
        observed_scope=[str(v) for v in observed_scope],
    )
    request_id = str(body.get("request_id") or str(uuid.uuid4()))
    drift_event = build_drift_event(
        tenant_id=tenant.tenant_id,
        agent_id=agent_id,
        attestation_id=attestation.get("attestation_id"),
        certificate_id=body.get("certificate_id"),
        assessment=assessment,
        request_id=request_id,
    )
    attestation_store.insert_drift_event(tenant_id=tenant.tenant_id, event=drift_event)
    return {"tenant_id": tenant.tenant_id, "drift": assessment.to_dict(), "drift_event": drift_event}


@app.get("/api/agent/drift/events")
async def api_list_agent_drift_events(
    limit: int = 100,
    agent_id: str | None = None,
    cursor: str | None = None,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    page = attestation_store.list_drift_events_paginated(
        tenant_id=tenant.tenant_id,
        page_size=min(max(limit, 1), 500),
        cursor=cursor,
        agent_id=agent_id,
    )
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(page["items"]),
        "events": page["items"],
        "next_cursor": page["next_cursor"],
        "has_more": page["has_more"],
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


@app.post("/api/federation/verifiers")
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


@app.post("/api/federation/verifiers/{verifier_id}/revoke")
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


@app.post("/api/federation/verifiers/{verifier_id}/rotate")
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


@app.get("/api/federation/verifiers/{verifier_id}/lifecycle")
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


@app.get("/api/federation/verifiers")
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


@app.post("/api/federation/attestations")
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


@app.get("/api/federation/attestations")
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


@app.post("/api/federation/quorum/evaluate")
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


@app.post("/api/policy/bundles")
async def api_create_policy_bundle(
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    name = str(body.get("name", "edge-default")).strip() or "edge-default"
    version = str(body.get("version", "")).strip()
    if not version:
        raise HTTPException(status_code=400, detail="'version' is required")
    config = body.get("config")
    if not isinstance(config, dict):
        raise HTTPException(status_code=400, detail="'config' must be an object")
    cfg = dict(config)
    cfg.setdefault("created_by", tenant.api_key_id)
    bundle = policy_bundles.create_bundle(
        tenant_id=tenant.tenant_id,
        name=name,
        version=version,
        description=str(body.get("description", "")).strip(),
        config=cfg,
    )
    return {"tenant_id": tenant.tenant_id, "bundle": bundle}


@app.get("/api/policy/bundles")
async def api_list_policy_bundles(
    name: str | None = None,
    status: str | None = None,
    limit: int = 50,
    cursor: str | None = None,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    page = policy_bundles.list_bundles_paginated(
        tenant_id=tenant.tenant_id,
        name=name,
        status=status,
        page_size=min(max(limit, 1), 200),
        cursor=cursor,
    )
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(page["items"]),
        "bundles": page["items"],
        "next_cursor": page["next_cursor"],
        "has_more": page["has_more"],
    }


@app.post("/api/policy/bundles/{bundle_id}/activate")
async def api_activate_policy_bundle(
    bundle_id: str,
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.OWNER)),
):
    approval_actor_id = str(body.get("approval_actor_id", "")).strip() or None
    try:
        bundle = policy_bundles.activate_bundle_with_approval(
            tenant_id=tenant.tenant_id,
            bundle_id=bundle_id,
            actor_id=tenant.api_key_id,
            approval_actor_id=approval_actor_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if bundle is None:
        raise HTTPException(status_code=404, detail="Policy bundle not found")
    return {"tenant_id": tenant.tenant_id, "bundle": bundle}


@app.post("/api/policy/bundles/{bundle_id}/review")
async def api_review_policy_bundle(
    bundle_id: str,
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    note = str(body.get("note", "")).strip()
    review = policy_bundles.review_bundle(
        tenant_id=tenant.tenant_id,
        bundle_id=bundle_id,
        actor_id=tenant.api_key_id,
        note=note,
    )
    if review is None:
        raise HTTPException(status_code=404, detail="Policy bundle not found")
    return {"tenant_id": tenant.tenant_id, "review": review}


@app.post("/api/policy/bundles/{bundle_id}/approve")
async def api_approve_policy_bundle(
    bundle_id: str,
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.OWNER)),
):
    note = str(body.get("note", "")).strip()
    approval = policy_bundles.approve_bundle(
        tenant_id=tenant.tenant_id,
        bundle_id=bundle_id,
        actor_id=tenant.api_key_id,
        note=note,
    )
    if approval is None:
        raise HTTPException(status_code=404, detail="Policy bundle not found")
    return {"tenant_id": tenant.tenant_id, "approval": approval}


@app.get("/api/policy/bundles/{bundle_id}/governance-log")
async def api_policy_bundle_governance_log(
    bundle_id: str,
    limit: int = 100,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    bundle = policy_bundles.get_bundle(tenant.tenant_id, bundle_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Policy bundle not found")
    rows = policy_bundles.list_governance_log(
        tenant_id=tenant.tenant_id,
        bundle_id=bundle_id,
        limit=min(max(limit, 1), 200),
    )
    return {"tenant_id": tenant.tenant_id, "count": len(rows), "events": rows}


@app.post("/api/policy/bundles/{bundle_id}/rollback")
async def api_policy_bundle_rollback(
    bundle_id: str,
    tenant: TenantContext = Depends(require_role(Role.OWNER)),
):
    bundle = policy_bundles.get_bundle(tenant.tenant_id, bundle_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Policy bundle not found")
    try:
        rolled = policy_bundles.rollback_to_previous_active(
            tenant_id=tenant.tenant_id,
            name=str(bundle.get("name") or "edge-default"),
            actor_id=tenant.api_key_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if rolled is None:
        raise HTTPException(status_code=400, detail="No previous active bundle available")
    return {"tenant_id": tenant.tenant_id, "bundle": rolled}


@app.post("/api/policy/bundles/simulate")
async def api_simulate_policy_bundle(
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    simulation = body.get("simulation")
    if not isinstance(simulation, dict):
        raise HTTPException(status_code=400, detail="'simulation' must be an object")
    bundle_id = str(body.get("bundle_id", "")).strip()
    bundle = None
    if bundle_id:
        bundle = policy_bundles.get_bundle(tenant.tenant_id, bundle_id)
    else:
        bundle_name = str(body.get("name", "edge-default")).strip() or "edge-default"
        bundle = policy_bundles.get_active_bundle(tenant.tenant_id, bundle_name)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Policy bundle not found")
    usage = feature_metering.record_usage(
        tenant_id=tenant.tenant_id,
        feature_key="policy.simulation.advanced",
        plan=PlanTier(str(tenant.plan.value) if hasattr(tenant.plan, "value") else str(tenant.plan)),
        amount=1,
        detail={"bundle_id": bundle.get("bundle_id"), "api": "/api/policy/bundles/simulate"},
    )
    if usage["usage"]["status"] == "blocked":
        raise HTTPException(status_code=402, detail="feature_usage_limit_exceeded:policy.simulation.advanced")
    result = policy_bundles.simulate_bundle(
        simulation=simulation,
        bundle_config=bundle.get("config", {}),
    )
    policy_bundles.record_simulation_result(
        tenant_id=tenant.tenant_id,
        bundle_id=bundle.get("bundle_id", ""),
        actor_id=tenant.api_key_id,
        simulation=result,
    )
    return {"tenant_id": tenant.tenant_id, "bundle": bundle, "simulation": result}


@app.post("/api/policy/bundles/active/simulate")
async def api_simulate_active_policy_bundle(
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    simulation = body.get("simulation")
    if not isinstance(simulation, dict):
        raise HTTPException(status_code=400, detail="'simulation' must be an object")
    bundle_name = str(body.get("name", "edge-default")).strip() or "edge-default"
    bundle = policy_bundles.get_active_bundle(tenant.tenant_id, bundle_name)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Active policy bundle not found")
    usage = feature_metering.record_usage(
        tenant_id=tenant.tenant_id,
        feature_key="policy.simulation.advanced",
        plan=PlanTier(str(tenant.plan.value) if hasattr(tenant.plan, "value") else str(tenant.plan)),
        amount=1,
        detail={"bundle_id": bundle.get("bundle_id"), "api": "/api/policy/bundles/active/simulate"},
    )
    if usage["usage"]["status"] == "blocked":
        raise HTTPException(status_code=402, detail="feature_usage_limit_exceeded:policy.simulation.advanced")
    result = policy_bundles.simulate_bundle(
        simulation=simulation,
        bundle_config=bundle.get("config", {}),
    )
    policy_bundles.record_simulation_result(
        tenant_id=tenant.tenant_id,
        bundle_id=bundle.get("bundle_id", ""),
        actor_id=tenant.api_key_id,
        simulation=result,
    )
    return {"tenant_id": tenant.tenant_id, "bundle": bundle, "simulation": result}


@app.get("/api/intel/feed")
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


@app.post("/api/intel/record")
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


@app.post("/api/intel/rules")
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


@app.get("/api/intel/rules")
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


@app.post("/api/intel/decay")
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


@app.post("/api/intel/assess")
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


@app.get("/api/intel/feed/taxii")
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


@app.get("/api/oss/onboarding")
async def api_oss_onboarding(
    _tenant: TenantContext = Depends(get_tenant),
):
    return {
        "cli_commands": [
            'python3 bin/tokendna-cli.py uis-spec',
            'python3 bin/tokendna-cli.py normalize --protocol oidc --tenant-id demo --tenant-name Demo --payload-json \'{"sub":"user-1","iss":"issuer","aud":"tokendna","jti":"j1"}\'',
        ],
        "developer_flow": [
            "Use UIS spec endpoint or CLI to understand schema contracts",
            "Normalize IdP or protocol events into UIS via adapter endpoint",
            "Use attestation APIs to create baseline and issue certificates",
            "Verify certs and monitor drift events in runtime",
            "Graduate to managed enforcement via /secure policy checks",
        ],
        "integration_endpoints": [
            "/api/integrations/idp/normalize",
            "/api/intel/feed/taxii",
            "/api/uis/adapters/normalize",
            "/api/agent/certificates/issue",
        ],
    }


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


@app.get("/api/compliance/frameworks")
async def api_compliance_frameworks(
    _tenant: TenantContext = Depends(get_tenant),
):
    return {"frameworks": sorted(list(compliance.CONTROL_MAPS.keys()))}


@app.get("/api/compliance/controls/{framework}")
async def api_compliance_controls(
    framework: str,
    _tenant: TenantContext = Depends(get_tenant),
):
    return {"control_map": compliance.build_control_map(framework)}


@app.post("/api/compliance/evidence/generate")
async def api_generate_compliance_evidence(
    body: dict,
    tenant: TenantContext = Depends(get_tenant),
):
    framework = str(body.get("framework", "")).strip().lower()
    if not framework:
        raise HTTPException(status_code=400, detail="'framework' is required")
    if framework not in compliance.CONTROL_MAPS:
        raise HTTPException(status_code=400, detail=f"Unsupported framework '{framework}'")

    uis_events = uis_store.list_events(tenant_id=tenant.tenant_id, limit=1000)
    attestations = attestation_store.list_attestations(tenant_id=tenant.tenant_id, limit=1000)
    certificates = attestation_store.list_certificates(tenant_id=tenant.tenant_id, limit=1000)
    drift_events = attestation_store.list_drift_events(tenant_id=tenant.tenant_id, limit=1000)
    threat_signals = network_intel.get_feed(limit=1000, min_tenant_count=1, min_confidence=0.0)

    package = compliance.generate_evidence_package(
        tenant_id=tenant.tenant_id,
        framework=framework,
        inputs={
            "uis_event_count": len(uis_events),
            "attestation_count": len(attestations),
            "certificate_count": len(certificates),
            "revoked_certificate_count": len([c for c in certificates if c.get("status") == "revoked"]),
            "drift_event_count": len(drift_events),
            "threat_signal_count": len(threat_signals),
        },
    )
    compliance.store_evidence_package(package)
    return {"tenant_id": tenant.tenant_id, "evidence_package": package}


@app.get("/api/compliance/evidence/packages")
async def api_list_compliance_evidence_packages(
    framework: str | None = None,
    limit: int = 50,
    tenant: TenantContext = Depends(get_tenant),
):
    rows = compliance.list_evidence_packages(
        tenant_id=tenant.tenant_id,
        framework=framework.lower() if framework else None,
        limit=min(max(limit, 1), 200),
    )
    return {"tenant_id": tenant.tenant_id, "count": len(rows), "packages": rows}


@app.post("/api/compliance/evidence/snapshot")
async def api_create_compliance_signed_snapshot(
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    package_id = str(body.get("package_id", "")).strip()
    if not package_id:
        raise HTTPException(status_code=400, detail="'package_id' is required")
    export_format = str(body.get("export_format", "oscal")).strip().lower()
    if export_format not in {"oscal", "emass"}:
        raise HTTPException(status_code=400, detail="'export_format' must be oscal or emass")

    package = compliance.get_evidence_package(tenant.tenant_id, package_id)
    if package is None:
        raise HTTPException(status_code=404, detail="Evidence package not found")
    usage = feature_metering.record_usage(
        tenant_id=tenant.tenant_id,
        feature_key="compliance.signed_snapshots",
        plan=PlanTier(str(tenant.plan.value) if hasattr(tenant.plan, "value") else str(tenant.plan)),
        amount=1,
        detail={"package_id": package_id, "api": "/api/compliance/evidence/snapshot"},
    )
    if usage["usage"]["status"] == "blocked":
        raise HTTPException(status_code=402, detail="feature_usage_limit_exceeded:compliance.signed_snapshots")
    snapshot = compliance.create_signed_snapshot(
        package=package,
        export_format=export_format,
        key_id=(str(body.get("key_id", "")).strip() or None),
        algorithm=str(body.get("algorithm", "HS256")).strip().upper(),
    )
    compliance.store_signed_snapshot(snapshot)
    verification = compliance.verify_signed_snapshot(snapshot)
    return {"tenant_id": tenant.tenant_id, "snapshot": snapshot, "verification": verification}


@app.get("/api/product/usage")
async def api_product_usage(
    month: str | None = None,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    statement = feature_metering.build_usage_statement(
        tenant_id=tenant.tenant_id,
        month_bucket=month,
    )
    return {"tenant_id": tenant.tenant_id, "statement": statement}


@app.get("/api/product/usage/exports")
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


@app.post("/api/product/usage/export")
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


@app.post("/api/product/usage/evaluate")
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


@app.get("/api/compliance/evidence/snapshots")
async def api_list_compliance_signed_snapshots(
    limit: int = 50,
    tenant: TenantContext = Depends(get_tenant),
):
    rows = compliance.list_signed_snapshots(
        tenant_id=tenant.tenant_id,
        limit=min(max(limit, 1), 200),
    )
    return {"tenant_id": tenant.tenant_id, "count": len(rows), "snapshots": rows}


@app.get("/api/compliance/evidence/snapshots/{snapshot_id}")
async def api_get_compliance_signed_snapshot(
    snapshot_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    snapshot = compliance.get_signed_snapshot(tenant.tenant_id, snapshot_id)
    if snapshot is None:
        raise HTTPException(status_code=404, detail="Signed snapshot not found")
    verification = compliance.verify_signed_snapshot(snapshot)
    return {"tenant_id": tenant.tenant_id, "snapshot": snapshot, "verification": verification}


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
    _user: dict = Depends(verify_token),
    tenant: TenantContext = Depends(get_tenant),
):
    tr      = TenantRedis(get_redis(), tenant.tenant_id)
    profile = ml_model.get_profile(user_id, redis=tr)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    return {"user_id": user_id, "tenant_id": tenant.tenant_id, "profile": profile}


@app.delete("/profile/{user_id}")
async def reset_profile(
    user_id: str,
    _user: dict = Depends(verify_token),
    tenant: TenantContext = Depends(get_tenant),
):
    tr = TenantRedis(get_redis(), tenant.tenant_id)
    ml_model.reset_profile(user_id, redis=tr)
    return {"status": "reset", "user_id": user_id}


# ── Manual revocation ─────────────────────────────────────────────────────────

@app.post("/revoke")
async def manual_revoke(
    body: dict,
    _user: dict = Depends(verify_token),
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    jti = body.get("jti")
    if not jti:
        raise HTTPException(status_code=400, detail="'jti' field required")
    ttl = int(body.get("ttl_seconds", 3600))
    revoke_token(jti, ttl_seconds=ttl, tenant_id=tenant.tenant_id)
    log_event(AuditEventType.AUTH_TOKEN_REVOKED, AuditOutcome.SUCCESS,
              tenant_id=tenant.tenant_id, subject=tenant.owner_email,
              resource=f"jti:{jti}", detail={"ttl_seconds": ttl, "manual": True})
    return {"status": "revoked", "jti": jti, "ttl_seconds": ttl}


# ── Tenant management (admin) ─────────────────────────────────────────────────

@app.get("/admin/tenants")
async def list_tenants(tenant: TenantContext = Depends(require_role(Role.ADMIN))):
    tenants = tenant_store.list_tenants()
    log_event(AuditEventType.ACCESS_GRANTED, AuditOutcome.SUCCESS,
              tenant_id=tenant.tenant_id, subject=tenant.owner_email,
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
              tenant_id=tenant.tenant_id, subject=tenant.owner_email,
              resource=f"tenant:{new_tenant.id}", detail={"name": name, "plan": plan.value})
    return {
        "tenant":  {"id": new_tenant.id, "name": new_tenant.name, "plan": new_tenant.plan.value},
        "api_key": raw_key,
        "warning": "Save this API key now — it will NOT be shown again.",
    }


@app.get("/admin/tenants/{tenant_id}/keys")
async def list_keys(tenant_id: str, _user: dict = Depends(verify_token)):
    keys = tenant_store.list_api_keys(tenant_id)
    return {"keys": [
        {"id": k.id, "name": k.name, "prefix": k.key_prefix,
         "is_active": k.is_active, "created_at": k.created_at.isoformat(),
         "last_used": k.last_used.isoformat() if k.last_used else None}
        for k in keys
    ]}


@app.post("/admin/tenants/{tenant_id}/keys", status_code=201)
async def create_key(tenant_id: str, body: dict, _user: dict = Depends(verify_token)):
    name = body.get("name", "default").strip()
    record, raw_key = tenant_store.create_api_key(tenant_id=tenant_id, name=name)
    return {"key_id": record.id, "prefix": record.key_prefix, "api_key": raw_key,
            "warning": "Save this API key now — it will NOT be shown again."}


@app.delete("/admin/tenants/{tenant_id}/keys/{key_id}")
async def revoke_key(tenant_id: str, key_id: str, _user: dict = Depends(verify_token)):
    tenant_store.revoke_api_key(key_id=key_id, tenant_id=tenant_id)
    return {"status": "revoked", "key_id": key_id}


# ── AWS onboarding ────────────────────────────────────────────────────────────

@app.post("/onboarding/aws/external-id")
async def aws_external_id(_user: dict = Depends(verify_token)):
    from onboarding.aws_connector import generate_external_id
    return {"external_id": generate_external_id()}


@app.post("/onboarding/aws/test")
async def aws_test(body: dict, _user: dict = Depends(verify_token)):
    from onboarding.aws_connector import AwsConnectionConfig, test_connection
    try:
        cfg = AwsConnectionConfig(
            tenant_id=_user.get("sub", "unknown"),
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
    from config import AUDIT_LOG_PATH  # type: ignore[attr-defined]

    path = Path(AUDIT_LOG_PATH) if "AUDIT_LOG_PATH" in dir() else Path("/var/log/aegis/audit.jsonl")
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

@app.get("/api/graph/path/{from_label:path}")
async def api_graph_path(
    from_label: str,
    to: str,
    tenant: TenantContext = Depends(get_tenant),
):
    """
    GET /api/graph/path/{from_label}?to={to_label}

    Find the shortest trust path between two nodes (identified by label).
    Returns the path as a list of node objects and the hop count.
    """
    result = trust_graph.shortest_path(
        tenant_id=tenant.tenant_id,
        from_label=from_label,
        to_label=to,
    )
    return {"tenant_id": tenant.tenant_id, **result}


@app.get("/api/graph/anomalies")
async def api_graph_anomalies(
    limit: int = 50,
    severity: str | None = None,
    tenant: TenantContext = Depends(get_tenant),
):
    """
    GET /api/graph/anomalies

    Return detected trust-graph anomalies for the tenant, newest first.
    Optional ?severity=low|medium|high|critical filter.
    """
    anomalies = trust_graph.get_anomalies(
        tenant_id=tenant.tenant_id,
        limit=min(limit, 200),
        severity=severity,
    )
    return {
        "tenant_id": tenant.tenant_id,
        "anomalies": anomalies,
        "count": len(anomalies),
    }


@app.get("/api/graph/stats")
async def api_graph_stats(
    tenant: TenantContext = Depends(get_tenant),
):
    """
    GET /api/graph/stats

    Return graph shape statistics for the tenant: node count, edge count,
    type breakdowns, and anomaly count.
    """
    stats = trust_graph.get_stats(tenant_id=tenant.tenant_id)
    return {"tenant_id": tenant.tenant_id, **stats}


@app.get("/api/graph/data")
async def api_graph_data(
    limit: int = 200,
    tenant: TenantContext = Depends(get_tenant),
):
    """
    GET /api/graph/data

    Return all nodes and edges for graph visualization.
    """
    data = trust_graph.get_graph_data(tenant_id=tenant.tenant_id, limit=limit)
    return {"tenant_id": tenant.tenant_id, **data}


# ── Blast Radius Simulator endpoints ──────────────────────────────────────────

@app.post("/api/simulate/blast_radius")
async def api_blast_radius(
    body: dict,
    tenant: TenantContext = Depends(get_tenant),
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
    tenant: TenantContext = Depends(get_tenant),
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

@app.get("/api/intent/matches")
async def api_intent_matches(
    limit: int = 50,
    severity: str | None = None,
    playbook_id: str | None = None,
    tenant: TenantContext = Depends(get_tenant),
):
    """
    GET /api/intent/matches

    Return recent exploit intent matches for the tenant, newest first.
    Optional ?severity= and ?playbook_id= filters.
    Each match includes the playbook that fired, confidence score,
    and the event IDs that triggered the match.
    """
    matches = intent_correlation.get_matches(
        tenant_id=tenant.tenant_id,
        limit=min(limit, 200),
        severity=severity,
        playbook_id=playbook_id,
    )
    return {
        "tenant_id": tenant.tenant_id,
        "matches": matches,
        "count": len(matches),
    }


@app.get("/api/intent/playbooks")
async def api_intent_playbooks(
    include_builtin: bool = True,
    tenant: TenantContext = Depends(get_tenant),
):
    """
    GET /api/intent/playbooks

    Return all active playbooks for the tenant (global built-ins + custom).
    """
    playbooks = intent_correlation.get_playbooks(
        tenant_id=tenant.tenant_id,
        include_builtin=include_builtin,
    )
    return {
        "tenant_id": tenant.tenant_id,
        "playbooks": playbooks,
        "count": len(playbooks),
    }


@app.post("/api/intent/playbooks")
async def api_intent_add_playbook(
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """
    POST /api/intent/playbooks

    Create a custom attack playbook for the tenant.

    Request body:
      {
        "name": "My Custom Playbook",
        "description": "...",
        "severity": "high",
        "steps": [
          { "category": "auth_anomaly", "min_confidence": 0.5 },
          { "category": "privilege_escalation" }
        ],
        "window_seconds": 3600
      }
    """
    name = str(body.get("name") or "").strip()
    description = str(body.get("description") or "").strip()
    severity = str(body.get("severity") or "medium")
    steps = body.get("steps") or []
    window_seconds = int(body.get("window_seconds") or 3600)

    if not name:
        raise HTTPException(status_code=400, detail="'name' is required")
    if not steps:
        raise HTTPException(status_code=400, detail="'steps' must be a non-empty list")

    try:
        pid = intent_correlation.add_playbook(
            tenant_id=tenant.tenant_id,
            name=name,
            description=description,
            severity=severity,
            steps=steps,
            window_seconds=window_seconds,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    return {"playbook_id": pid, "tenant_id": tenant.tenant_id, "name": name}


@app.delete("/api/intent/playbooks/{playbook_id}")
async def api_intent_delete_playbook(
    playbook_id: str,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """
    DELETE /api/intent/playbooks/{playbook_id}

    Delete a custom playbook. Built-in playbooks cannot be deleted.
    """
    deleted = intent_correlation.delete_playbook(
        tenant_id=tenant.tenant_id,
        playbook_id=playbook_id,
    )
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="Playbook not found, not owned by this tenant, or is a built-in",
        )
    return {"deleted": True, "playbook_id": playbook_id}


# ── ZTIX Exchange endpoints ───────────────────────────────────────────────────

@app.post("/api/ztix/simulate")
async def api_ztix_simulate(
    body: dict,
    tenant: TenantContext = Depends(get_tenant),
):
    """
    POST /api/ztix/simulate

    Simulate a Zero-Trust Identity Exchange between two agents.
    Normalizes a UIS event for agent_a and returns a mock ZTIX token
    plus graph delta.

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
        "ztix_id": f"ztix-{str(uuid.uuid4())[:8]}",
        "bound_to": agent_a,
        "issued_at": now.isoformat(),
        "expires_in": 300,
        "scope": ["read:data", "execute:tools"],
        "trust_level": "verified",
    }

    return {
        "event": uis_event,
        "ztix_token": ztix_token,
        "graph_delta": {
            "nodes_before": nodes_before,
            "nodes_after": nodes_after,
            "edges_before": edges_before,
            "edges_after": edges_after,
        },
    }


# ── Policy Guard (Sprint 5-1) ─────────────────────────────────────────────────

@app.post("/api/policy/guard/evaluate")
async def api_policy_guard_evaluate(
    body: dict,
    tenant: TenantContext = Depends(get_tenant),
):
    """
    Evaluate a pending policy action against PolicyGuard constitutional rules.

    Returns disposition: allow | flag | block.
    BLOCK means the action must not proceed — a violation record is created
    and human approval is required via POST /api/policy/guard/violations/{id}/approve.

    Body fields:
      actor_id           str  required  agent/service attempting the action
      actor_type         str  required  "agent" | "service" | "human"
      action_type        str  required  "create" | "update" | "delete" | "activate" | "rollback"
      target_policy_id   str  required  policy being modified
      target_policy_name str  required  human-readable policy name
      scope_delta        list optional  permissions being added/removed
      metadata           dict optional  governed_agent, actor_scopes, delegated_scopes, etc.
    """
    policy_guard.init_db()
    try:
        action = policy_guard.PolicyAction(
            actor_id=str(body.get("actor_id", "")).strip(),
            actor_type=str(body.get("actor_type", "agent")).strip(),
            action_type=str(body.get("action_type", "")).strip(),
            target_policy_id=str(body.get("target_policy_id", "")).strip(),
            target_policy_name=str(body.get("target_policy_name", "")).strip(),
            tenant_id=tenant.tenant_id,
            scope_delta=body.get("scope_delta", []),
            metadata=body.get("metadata", {}),
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if not action.actor_id or not action.action_type or not action.target_policy_id:
        raise HTTPException(
            status_code=400,
            detail="actor_id, action_type, and target_policy_id are required",
        )

    result = policy_guard.evaluate(action)
    return {
        "request_id": result.request_id,
        "actor_id": result.actor_id,
        "target_policy_id": result.target_policy_id,
        "disposition": result.disposition.value,
        "rules_triggered": result.rules_triggered,
        "reasons": result.reasons,
        "violation_id": result.violation_id,
        "evaluated_at": result.evaluated_at,
        "proceed": result.disposition == policy_guard.Disposition.ALLOW,
    }


@app.get("/api/policy/guard/violations")
async def api_policy_guard_violations(
    status: Optional[str] = None,
    actor_id: Optional[str] = None,
    disposition: Optional[str] = None,
    limit: int = 50,
    tenant: TenantContext = Depends(get_tenant),
):
    """
    List PolicyGuard violations for the current tenant.
    Default: open violations (requiring human review).
    BLOCK violations must be approved before the action can proceed.
    """
    policy_guard.init_db()
    violations = policy_guard.list_violations(
        tenant_id=tenant.tenant_id,
        status=status,
        actor_id=actor_id,
        disposition=disposition,
        limit=min(limit, 200),
    )
    return {
        "violations": [
            {
                "violation_id": v.violation_id,
                "actor_id": v.actor_id,
                "actor_type": v.actor_type,
                "action_type": v.action_type,
                "target_policy_id": v.target_policy_id,
                "target_policy_name": v.target_policy_name,
                "disposition": v.disposition.value,
                "rules_triggered": v.rules_triggered,
                "reasons": v.reasons,
                "status": v.status.value,
                "detected_at": v.detected_at,
                "resolved_at": v.resolved_at,
                "resolved_by": v.resolved_by,
                "resolution_note": v.resolution_note,
            }
            for v in violations
        ],
        "count": len(violations),
        "tenant_id": tenant.tenant_id,
    }


@app.get("/api/policy/guard/violations/{violation_id}")
async def api_policy_guard_get_violation(
    violation_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    """Get a specific PolicyGuard violation by ID."""
    policy_guard.init_db()
    violation = policy_guard.get_violation(violation_id, tenant.tenant_id)
    if not violation:
        raise HTTPException(status_code=404, detail="Violation not found")
    return {
        "violation_id": violation.violation_id,
        "actor_id": violation.actor_id,
        "actor_type": violation.actor_type,
        "action_type": violation.action_type,
        "target_policy_id": violation.target_policy_id,
        "target_policy_name": violation.target_policy_name,
        "disposition": violation.disposition.value,
        "rules_triggered": violation.rules_triggered,
        "reasons": violation.reasons,
        "status": violation.status.value,
        "detected_at": violation.detected_at,
        "resolved_at": violation.resolved_at,
        "resolved_by": violation.resolved_by,
        "resolution_note": violation.resolution_note,
        "metadata": violation.metadata,
    }


@app.post("/api/policy/guard/violations/{violation_id}/approve")
async def api_policy_guard_approve(
    violation_id: str,
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """
    Human operator approves a blocked policy action.
    The action may now proceed; the violation audit record remains.

    Body fields:
      approved_by  str  required  operator identity
      note         str  optional  justification
    """
    policy_guard.init_db()
    approved_by = str(body.get("approved_by", "")).strip()
    if not approved_by:
        raise HTTPException(status_code=400, detail="approved_by is required")
    violation = policy_guard.approve_violation(
        violation_id=violation_id,
        tenant_id=tenant.tenant_id,
        approved_by=approved_by,
        note=str(body.get("note", "")),
    )
    if not violation:
        raise HTTPException(
            status_code=404,
            detail="Violation not found or not in open status",
        )
    return {
        "violation_id": violation.violation_id,
        "status": violation.status.value,
        "approved_by": violation.resolved_by,
        "resolved_at": violation.resolved_at,
        "proceed": True,
    }


@app.post("/api/policy/guard/violations/{violation_id}/reject")
async def api_policy_guard_reject(
    violation_id: str,
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """
    Human operator rejects a blocked policy action (must not proceed).

    Body fields:
      rejected_by  str  required  operator identity
      note         str  optional  justification
    """
    policy_guard.init_db()
    rejected_by = str(body.get("rejected_by", "")).strip()
    if not rejected_by:
        raise HTTPException(status_code=400, detail="rejected_by is required")
    violation = policy_guard.reject_violation(
        violation_id=violation_id,
        tenant_id=tenant.tenant_id,
        rejected_by=rejected_by,
        note=str(body.get("note", "")),
    )
    if not violation:
        raise HTTPException(
            status_code=404,
            detail="Violation not found or not in open status",
        )
    return {
        "violation_id": violation.violation_id,
        "status": violation.status.value,
        "rejected_by": violation.resolved_by,
        "resolved_at": violation.resolved_at,
        "proceed": False,
    }


@app.get("/api/policy/guard/stats")
async def api_policy_guard_stats(
    tenant: TenantContext = Depends(get_tenant),
):
    """Summary statistics for PolicyGuard violations in the current tenant."""
    policy_guard.init_db()
    return policy_guard.violation_stats(tenant.tenant_id)


# ── Permission Drift Tracker (Sprint 5-2) ─────────────────────────────────

@app.post("/api/drift/record")
async def api_drift_record(
    body: dict,
    tenant: TenantContext = Depends(get_tenant),
):
    """
    Record a permission scope observation for an agent.
    Triggers drift detection as a side effect; may create a DriftAlert.

    Body fields:
      agent_id          str   required
      policy_id         str   required
      scope             list  required  list of permission strings
      source_event      str   optional  UIS event ID
      has_attestation   bool  optional  default false
      changed_by        str   optional  actor that made the change
    """
    permission_drift.init_db()
    agent_id = str(body.get("agent_id", "")).strip()
    policy_id = str(body.get("policy_id", "")).strip()
    scope = body.get("scope", [])
    if not agent_id or not policy_id:
        raise HTTPException(status_code=400,
                            detail="agent_id and policy_id are required")
    obs = permission_drift.record_observation(
        tenant_id=tenant.tenant_id,
        agent_id=agent_id,
        policy_id=policy_id,
        scope=scope,
        source_event=body.get("source_event"),
        has_attestation=bool(body.get("has_attestation", False)),
        changed_by=body.get("changed_by"),
        metadata=body.get("metadata", {}),
    )
    return {
        "observation_id": obs.observation_id,
        "agent_id": obs.agent_id,
        "policy_id": obs.policy_id,
        "scope_weight": obs.scope_weight,
        "recorded_at": obs.recorded_at,
        "has_attestation": obs.has_attestation,
    }


@app.get("/api/drift/alerts")
async def api_drift_alerts(
    status: Optional[str] = "open",
    agent_id: Optional[str] = None,
    limit: int = 50,
    tenant: TenantContext = Depends(get_tenant),
):
    """
    List permission drift alerts for the current tenant.
    Default: open alerts (agents whose permissions grew >2× without attestation).
    Ordered by growth factor descending — worst offenders first.
    """
    permission_drift.init_db()
    alerts = permission_drift.list_alerts(
        tenant_id=tenant.tenant_id,
        status=status,
        agent_id=agent_id,
        limit=min(limit, 200),
    )
    return {
        "alerts": [
            {
                "drift_id": a.drift_id,
                "agent_id": a.agent_id,
                "policy_id": a.policy_id,
                "baseline_weight": a.baseline_weight,
                "current_weight": a.current_weight,
                "growth_factor": a.growth_factor,
                "baseline_date": a.baseline_date,
                "detected_at": a.detected_at,
                "status": a.status,
                "unattested_changes": a.unattested_changes,
                "observations_in_window": a.observations_in_window,
            }
            for a in alerts
        ],
        "count": len(alerts),
        "tenant_id": tenant.tenant_id,
    }


@app.get("/api/drift/report/{agent_id}")
async def api_drift_report(
    agent_id: str,
    policy_id: str,
    days: int = 30,
    tenant: TenantContext = Depends(get_tenant),
):
    """
    Full permission history timeline for one agent on one policy.
    Returns every recorded scope observation in the window, baseline→current
    delta, and growth factor.
    """
    permission_drift.init_db()
    if not policy_id:
        raise HTTPException(status_code=400, detail="policy_id query param required")
    report = permission_drift.agent_drift_report(
        tenant_id=tenant.tenant_id,
        agent_id=agent_id,
        policy_id=policy_id,
        days=min(days, 365),
    )
    return {
        "agent_id": report.agent_id,
        "policy_id": report.policy_id,
        "baseline_weight": report.baseline_weight,
        "current_weight": report.current_weight,
        "growth_factor": report.growth_factor,
        "open_alerts": report.open_alerts,
        "unattested_changes": report.unattested_changes,
        "observation_count": len(report.observations),
        "observations": [
            {
                "observation_id": o.observation_id,
                "scope": o.scope,
                "scope_weight": o.scope_weight,
                "recorded_at": o.recorded_at,
                "has_attestation": o.has_attestation,
                "changed_by": o.changed_by,
            }
            for o in report.observations
        ],
        "report_generated_at": report.report_generated_at,
    }


@app.post("/api/drift/approve/{drift_id}")
async def api_drift_approve(
    drift_id: str,
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """
    Human operator approves a drift event
    (accepts the permission growth as intentional).

    Body fields:
      approved_by  str  required  operator identity
      note         str  optional  justification
    """
    permission_drift.init_db()
    approved_by = str(body.get("approved_by", "")).strip()
    if not approved_by:
        raise HTTPException(status_code=400, detail="approved_by is required")
    alert = permission_drift.approve_drift(
        drift_id=drift_id,
        tenant_id=tenant.tenant_id,
        approved_by=approved_by,
        note=str(body.get("note", "")),
    )
    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Drift alert not found or not in open status",
        )
    return {
        "drift_id": alert.drift_id,
        "status": alert.status,
        "approved_by": alert.approved_by,
        "approved_at": alert.approved_at,
        "approval_note": alert.approval_note,
    }


@app.get("/api/drift/summary")
async def api_drift_summary(
    tenant: TenantContext = Depends(get_tenant),
):
    """
    Tenant-level drift summary: agents tracked, agents with open alerts,
    total open alerts, highest growth factor.
    """
    permission_drift.init_db()
    summary = permission_drift.drift_summary(tenant.tenant_id)
    return {
        "tenant_id": summary.tenant_id,
        "agents_tracked": summary.agents_tracked,
        "agents_with_open_alerts": summary.agents_with_open_alerts,
        "total_open_alerts": summary.total_open_alerts,
        "total_approved": summary.total_approved,
        "highest_growth_factor": summary.highest_growth_factor,
        "highest_growth_agent": summary.highest_growth_agent,
        "computed_at": summary.computed_at,
    }


@app.get("/api/drift/blast-comparison/{agent_id}")
async def api_drift_blast_comparison(
    agent_id: str,
    policy_id: str,
    baseline_days: int = 30,
    tenant: TenantContext = Depends(get_tenant),
):
    """
    Blast radius comparison: current permission surface vs. baseline.
    Returns growth_factor and a qualitative blast_radius_growth_estimate
    (low/medium/high/critical).
    This is the killer demo visual: 'your agent\'s blast radius increased
    2.4× this month.'
    """
    permission_drift.init_db()
    if not policy_id:
        raise HTTPException(status_code=400, detail="policy_id query param required")
    return permission_drift.blast_radius_comparison(
        tenant_id=tenant.tenant_id,
        agent_id=agent_id,
        policy_id=policy_id,
        baseline_days=min(baseline_days, 365),
    )


# ── Sprint 5-3: Ghost Agent Offboarding Enforcement ───────────────────────────

@app.post("/api/agents/register")
async def api_register_agent(
    body: dict = Body(...),
    tenant: TenantContext = Depends(get_tenant),
):
    """Register a new agent in the lifecycle inventory."""
    agent_lifecycle.init_db()
    agent_id = str(body.get("agent_id", "")).strip() or None
    display_name = str(body.get("display_name", "")).strip()
    if not display_name:
        raise HTTPException(status_code=400, detail="'display_name' is required")
    try:
        agent = agent_lifecycle.register_agent(
            tenant_id=tenant.tenant_id,
            agent_id=agent_id,
            display_name=display_name,
            platform=str(body.get("platform", "unknown")),
            owner=body.get("owner"),
            credential_ids=list(body.get("credential_ids", [])),
            last_token_id=body.get("last_token_id"),
            metadata=body.get("metadata", {}),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return agent


@app.post("/api/agents/decommission/{agent_id}")
async def api_decommission_agent(
    agent_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(get_tenant),
):
    """
    Decommission an agent (terminal).  Automatically revokes credentials and
    converts the agent's token to a deception-mesh honeypot.
    """
    agent_lifecycle.init_db()
    try:
        result = agent_lifecycle.decommission_agent(
            tenant_id=tenant.tenant_id,
            agent_id=agent_id,
            actor=body.get("actor"),
            reason=body.get("reason"),
            revoke_credentials=bool(body.get("revoke_credentials", True)),
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result


@app.post("/api/agents/suspend/{agent_id}")
async def api_suspend_agent(
    agent_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(get_tenant),
):
    """Suspend an active agent (reversible)."""
    agent_lifecycle.init_db()
    try:
        return agent_lifecycle.suspend_agent(
            tenant_id=tenant.tenant_id,
            agent_id=agent_id,
            actor=body.get("actor"),
            reason=body.get("reason"),
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/agents/reactivate/{agent_id}")
async def api_reactivate_agent(
    agent_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(get_tenant),
):
    """Reactivate a suspended agent."""
    agent_lifecycle.init_db()
    try:
        return agent_lifecycle.reactivate_agent(
            tenant_id=tenant.tenant_id,
            agent_id=agent_id,
            actor=body.get("actor"),
            reason=body.get("reason"),
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/agents/heartbeat/{agent_id}")
async def api_agent_heartbeat(
    agent_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    """Record agent activity (updates last_seen_at)."""
    agent_lifecycle.init_db()
    try:
        return agent_lifecycle.record_heartbeat(
            tenant_id=tenant.tenant_id,
            agent_id=agent_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/agents/inventory")
async def api_agent_inventory(
    status: str | None = None,
    limit: int = 200,
    tenant: TenantContext = Depends(get_tenant),
):
    """Return full agent inventory for the tenant."""
    agent_lifecycle.init_db()
    try:
        return {"agents": agent_lifecycle.list_inventory(
            tenant_id=tenant.tenant_id,
            status=status,
            limit=limit,
        )}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/agents/orphans")
async def api_agent_orphans(
    orphan_days: int = 30,
    limit: int = 200,
    tenant: TenantContext = Depends(get_tenant),
):
    """Return agents with no activity in >orphan_days days."""
    agent_lifecycle.init_db()
    orphans = agent_lifecycle.list_orphans(
        tenant_id=tenant.tenant_id,
        orphan_days=max(orphan_days, 1),
        limit=limit,
    )
    return {"orphans": orphans, "count": len(orphans), "orphan_threshold_days": orphan_days}


@app.get("/api/agents/{agent_id}/events")
async def api_agent_events(
    agent_id: str,
    limit: int = 100,
    tenant: TenantContext = Depends(get_tenant),
):
    """Return lifecycle event log for a specific agent."""
    agent_lifecycle.init_db()
    try:
        events = agent_lifecycle.get_lifecycle_events(
            tenant_id=tenant.tenant_id,
            agent_id=agent_id,
            limit=limit,
        )
        return {"agent_id": agent_id, "events": events}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/agents/{agent_id}")
async def api_get_agent(
    agent_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    """Return a single agent record."""
    agent_lifecycle.init_db()
    try:
        return agent_lifecycle.get_agent(
            tenant_id=tenant.tenant_id,
            agent_id=agent_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ── Sprint 5-4: MCP Intent-Aware Inspection ───────────────────────────────────

@app.post("/api/mcp/inspect")
async def api_mcp_inspect(
    body: dict = Body(...),
    tenant: TenantContext = Depends(get_tenant),
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


@app.post("/api/mcp/tools/register")
async def api_mcp_register_tool(
    body: dict = Body(...),
    tenant: TenantContext = Depends(get_tenant),
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


@app.get("/api/mcp/tools")
async def api_mcp_list_tools(
    tenant: TenantContext = Depends(get_tenant),
):
    """List all tool intent profiles available to this tenant."""
    mcp_inspector.init_db()
    return {"tools": mcp_inspector.list_tools(tenant_id=tenant.tenant_id)}


@app.get("/api/mcp/tools/{tool_name}")
async def api_mcp_get_tool(
    tool_name: str,
    tenant: TenantContext = Depends(get_tenant),
):
    """Return a single tool intent profile."""
    mcp_inspector.init_db()
    profile = mcp_inspector.get_tool(tenant_id=tenant.tenant_id, tool_name=tool_name)
    if not profile:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_name}' not found")
    return profile


@app.get("/api/mcp/violations")
async def api_mcp_violations(
    resolved: bool | None = None,
    limit: int = 200,
    tenant: TenantContext = Depends(get_tenant),
):
    """Return MCP violations for this tenant."""
    mcp_inspector.init_db()
    violations = mcp_inspector.list_violations(
        tenant_id=tenant.tenant_id,
        resolved=resolved,
        limit=limit,
    )
    return {"violations": violations, "count": len(violations)}


@app.post("/api/mcp/violations/{violation_id}/resolve")
async def api_mcp_resolve_violation(
    violation_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(get_tenant),
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


@app.get("/api/mcp/chain/{session_id}")
async def api_mcp_chain(
    session_id: str,
    limit: int = 200,
    tenant: TenantContext = Depends(get_tenant),
):
    """Return the full tool-call chain for a session."""
    mcp_inspector.init_db()
    chain = mcp_inspector.get_chain(
        tenant_id=tenant.tenant_id,
        session_id=session_id,
        limit=limit,
    )
    return {"session_id": session_id, "chain": chain, "count": len(chain)}


# ── Sprint 6-1: Agent Attestation Certificate Lifecycle Dashboard ─────────────

@app.get("/api/certs/fleet")
async def api_certs_fleet(
    status: str | None = None,
    limit: int = 500,
    tenant: TenantContext = Depends(get_tenant),
):
    """
    Full certificate fleet view for the tenant.
    Returns all certs with health labels, days_until_expiry, and summary stats.
    """
    cert_dashboard.init_db()
    return cert_dashboard.fleet_view(
        tenant_id=tenant.tenant_id,
        status=status,
        limit=limit,
    )


@app.get("/api/certs/fleet/summary")
async def api_certs_fleet_summary(
    tenant: TenantContext = Depends(get_tenant),
):
    """Quick-summary stats for the operator dashboard header widget."""
    cert_dashboard.init_db()
    return cert_dashboard.fleet_summary(tenant_id=tenant.tenant_id)


@app.get("/api/certs/expiring")
async def api_certs_expiring(
    within_days: int = 30,
    limit: int = 200,
    tenant: TenantContext = Depends(get_tenant),
):
    """
    Certs expiring within `within_days` days (default 30).
    Automatically creates/refreshes expiry alert records.
    """
    cert_dashboard.init_db()
    certs = cert_dashboard.get_expiring(
        tenant_id=tenant.tenant_id,
        within_days=max(within_days, 1),
        limit=limit,
    )
    return {"expiring": certs, "count": len(certs), "within_days": within_days}


@app.post("/api/certs/expiry-alerts/{alert_id}/acknowledge")
async def api_ack_expiry_alert(
    alert_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(get_tenant),
):
    """Acknowledge a certificate expiry alert."""
    cert_dashboard.init_db()
    acknowledged_by = str(body.get("acknowledged_by", "")).strip()
    if not acknowledged_by:
        raise HTTPException(status_code=400, detail="'acknowledged_by' is required")
    try:
        return cert_dashboard.acknowledge_expiry_alert(
            tenant_id=tenant.tenant_id,
            alert_id=alert_id,
            acknowledged_by=acknowledged_by,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/certs/usage")
async def api_record_cert_usage(
    body: dict = Body(...),
    tenant: TenantContext = Depends(get_tenant),
):
    """
    Record a certificate usage event. Runs anomaly detection automatically.
    Fires alerts for: revoked cert used, unexpected agent/IP.
    """
    cert_dashboard.init_db()
    certificate_id = str(body.get("certificate_id", "")).strip()
    if not certificate_id:
        raise HTTPException(status_code=400, detail="'certificate_id' is required")
    result = cert_dashboard.record_usage(
        tenant_id=tenant.tenant_id,
        certificate_id=certificate_id,
        agent_id=body.get("agent_id"),
        source_ip=body.get("source_ip"),
        cert_status=str(body.get("cert_status", "active")),
        verified=bool(body.get("verified", True)),
        metadata=dict(body.get("metadata", {})),
    )
    # Deception mesh bridge: revoked cert use → record as decoy hit
    if body.get("cert_status") == "revoked":
        try:
            from modules.identity import agent_lifecycle as _al  # noqa: PLC0415
            _al.init_db()
            _al.record_decoy_hit(
                tenant_id=tenant.tenant_id,
                token_id=certificate_id,
            )
        except Exception:  # noqa: BLE001
            pass  # best-effort; deception mesh is non-fatal
    return result


@app.get("/api/certs/anomalies")
async def api_cert_anomalies(
    resolved: bool | None = None,
    limit: int = 200,
    tenant: TenantContext = Depends(get_tenant),
):
    """Return certificate usage anomalies for this tenant."""
    cert_dashboard.init_db()
    anomalies = cert_dashboard.list_anomalies(
        tenant_id=tenant.tenant_id,
        resolved=resolved,
        limit=limit,
    )
    return {"anomalies": anomalies, "count": len(anomalies)}


@app.post("/api/certs/anomalies/{anomaly_id}/resolve")
async def api_resolve_cert_anomaly(
    anomaly_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(get_tenant),
):
    """Resolve a certificate anomaly."""
    cert_dashboard.init_db()
    resolved_by = str(body.get("resolved_by", "")).strip()
    if not resolved_by:
        raise HTTPException(status_code=400, detail="'resolved_by' is required")
    try:
        return cert_dashboard.resolve_anomaly(
            tenant_id=tenant.tenant_id,
            anomaly_id=anomaly_id,
            resolved_by=resolved_by,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/certs/{cert_id}/history")
async def api_cert_history(
    cert_id: str,
    limit: int = 200,
    tenant: TenantContext = Depends(get_tenant),
):
    """Full usage history for a single certificate."""
    cert_dashboard.init_db()
    history = cert_dashboard.get_cert_history(
        tenant_id=tenant.tenant_id,
        certificate_id=cert_id,
        limit=limit,
    )
    return {"certificate_id": cert_id, "history": history, "count": len(history)}


# ==========================================================================
# Policy Advisor — Adaptive Policy Suggestion Engine (Sprint 6-2)
# ==========================================================================


@app.post("/api/policy/suggestions/analyze")
async def api_policy_suggestions_analyze(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(get_tenant),
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


@app.get("/api/policy/suggestions")
async def api_list_policy_suggestions(
    status: str | None = None,
    amendment_type: str | None = None,
    min_confidence: float = 0.0,
    limit: int = 50,
    tenant: TenantContext = Depends(get_tenant),
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


@app.get("/api/policy/suggestions/stats")
async def api_policy_suggestion_stats(
    tenant: TenantContext = Depends(get_tenant),
):
    """Summary statistics for this tenant's policy suggestions."""
    policy_advisor.init_db()
    return policy_advisor.suggestion_stats(tenant_id=tenant.tenant_id)


@app.get("/api/policy/suggestions/{suggestion_id}")
async def api_get_policy_suggestion(
    suggestion_id: str,
    tenant: TenantContext = Depends(get_tenant),
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


@app.post("/api/policy/suggestions/{suggestion_id}/approve")
async def api_approve_policy_suggestion(
    suggestion_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(get_tenant),
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


@app.post("/api/policy/suggestions/{suggestion_id}/reject")
async def api_reject_policy_suggestion(
    suggestion_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(get_tenant),
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


@app.post("/api/policy/suggestions/auto-tighten")
async def api_policy_auto_tighten(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(get_tenant),
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


# ==========================================================================
# Agent Identity Passport (Sprint 3-1) — restored 2026-04-21
# ==========================================================================

from modules.identity import passport as passport_module


@app.post("/api/passport/request")
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


@app.post("/api/passport/{passport_id}/approve")
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


@app.post("/api/passport/{passport_id}/issue")
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


@app.post("/api/passport/{passport_id}/revoke")
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


@app.post("/api/passport/verify")
async def api_passport_verify(body: dict = Body(default={})):
    """
    Verify a passport bundle. Open endpoint — no auth required.
    Third-party integrators call this to validate a passport presented by an agent.
    """
    result = passport_module.verify_passport(body)
    status_code = 200 if result["valid"] else 401
    from fastapi.responses import JSONResponse  # noqa: PLC0415
    return JSONResponse(content=result, status_code=status_code)


@app.get("/api/passport/{passport_id}")
async def api_passport_get(
    passport_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    """Retrieve a passport by ID."""
    p = passport_module.get_passport(passport_id)
    if p is None:
        raise HTTPException(status_code=404, detail="Passport not found")
    return {"passport": p.to_dict()}


@app.get("/api/passport/{passport_id}/status")
async def api_passport_status_check(passport_id: str):
    """
    Revocation check endpoint (public). Returns minimal status.
    Used as the revocation_url target in issued passports.
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


@app.get("/api/passports")
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


@app.post("/api/passport/{passport_id}/evidence")
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


@app.get("/api/passport/{passport_id}/evidence")
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


@app.get("/api/passport/integrations/playbooks")
async def api_passport_playbooks_list():
    """List available cross-vendor integration playbooks."""
    return {"playbooks": passport_module.list_integration_playbooks()}


@app.get("/api/passport/integrations/playbook/{vendor}")
async def api_passport_playbook_detail(vendor: str):
    """Return detailed integration playbook for a specific vendor."""
    try:
        playbook = passport_module.get_integration_playbook(vendor)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"playbook": playbook}


# ==========================================================================
# Verifier Reputation Network (Sprint 3-2) — restored 2026-04-21
# ==========================================================================

from modules.identity import verifier_reputation as reputation_module


@app.post("/api/verifier/{verifier_id}/challenge")
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


@app.post("/api/verifier/challenge/{challenge_id}/respond")
async def api_resolve_challenge(
    challenge_id: str,
    body: dict = Body(default={}),
):
    """Submit a verifier's response to a challenge. Open endpoint."""
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


@app.get("/api/verifier/{verifier_id}/reputation")
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


@app.get("/api/verifier/reputation/leaderboard")
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


@app.get("/api/verifier/reputation/anomalies")
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


@app.post("/api/verifier/reputation/quorum")
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


@app.post("/api/verifier/reputation/expire-challenges")
async def api_expire_pending_challenges(
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Expire all pending challenges past their timeout window."""
    count = reputation_module.expire_pending_challenges(tenant_id=tenant.tenant_id)
    return {"expired": count}


@app.post("/api/verifier/reputation/sync-scores")
async def api_sync_static_scores(
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """Push current reputation scores back to trust_federation_verifiers.trust_score."""
    count = reputation_module.sync_static_scores(tenant_id=tenant.tenant_id)
    return {"synced": count}


@app.get("/api/verifier/{verifier_id}/challenges")
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


@app.get("/api/verifier/reputation/due-for-challenge")
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


# ==========================================================================
# ZTIX Continuous Proof-of-Control (Expansion #2) — Sprint 7-B
# ==========================================================================

from modules.identity import proof_of_control as poc_module


@app.get("/api/federation/verifiers/{verifier_id}/proof-status")
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


@app.post("/api/federation/verifiers/{verifier_id}/proof-interval")
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


@app.post("/api/federation/verifiers/proof-sweep")
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


@app.post("/api/federation/verifiers/proof-renew-all")
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


@app.get("/api/federation/verifiers/proof-registry")
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


@app.get("/api/federation/verifiers/proof-stats")
async def api_proof_stats(
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Summary statistics for proof-of-control status across all verifiers."""
    poc_module.init_db()
    return poc_module.proof_stats(tenant_id=tenant.tenant_id)
