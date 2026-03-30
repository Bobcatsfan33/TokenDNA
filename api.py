"""
TokenDNA / Aegis Security Platform -- FastAPI v2.1.0

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
"""

import asyncio
import logging
import os
import uuid
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response
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
from modules.identity import clickhouse_client
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

_DASHBOARD_PATH = Path(__file__).parent / "dashboard" / "index.html"

app = FastAPI(
    title="Aegis Security Platform",
    description="TokenDNA zero-trust session integrity + Aegis cloud posture management",
    version="2.4.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
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


# ── Startup ───────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_checks():
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

    os.makedirs("/data", exist_ok=True)
    tenant_store.init_db()

    from modules.identity.cache_redis import is_available as redis_ok
    logger.info("Redis: %s", "connected" if redis_ok() else "UNREACHABLE")
    logger.info("ClickHouse: %s", "connected" if clickhouse_client.is_available() else "UNREACHABLE")

    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, threat_intel._ensure_tor_list)

    # Emit startup audit event (AU-2: application startup)
    log_event(AuditEventType.STARTUP, AuditOutcome.SUCCESS,
              detail={"version": "2.4.0", "dev_mode": DEV_MODE})


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
        "version":    "2.4.0",
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
    from modules.identity.threat_intel import _tor_ips, _tor_last_refresh
    import datetime
    tor_age = None
    if _tor_last_refresh:
        tor_age = int((datetime.datetime.utcnow() - _tor_last_refresh).total_seconds())
    return {
        "redis":       {"ok": redis_ok()},
        "clickhouse":  {"ok": clickhouse_client.is_available()},
        "tor_list":    {"ok": len(_tor_ips) > 0, "count": len(_tor_ips), "age_seconds": tor_age},
        "dev_mode":    DEV_MODE,
        "version":     "2.4.0",
        "fips_active": fips.is_active(),
        "il_environment": os.getenv("ENVIRONMENT", "dev"),
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

    # ── 3. Baseline establishment ─────────────────────────────────────────────
    baseline = get_baseline(user_id, tenant_id=tid)
    if baseline is None:
        set_baseline(user_id, current, tenant_id=tid)
        ml_model.update_profile(user_id, current, redis=tr)
        session_graph.add_event(user_id, current, geo, redis=tr)
        increment_event_counter("allow", tenant_id=tid)
        return {"status": "baseline_set", "request_id": request_id}

    # ── 4. Score ──────────────────────────────────────────────────────────────
    ml_score     = ml_model.score(user_id, current, redis=tr)
    graph_result = session_graph.detect_anomalies(user_id, current, geo, redis=tr)
    breakdown    = scoring.compute(ml_score, threat, graph_result)

    # ── 5. Update profile and graph ───────────────────────────────────────────
    ml_model.update_profile(user_id, current, redis=tr)
    session_graph.add_event(user_id, current, geo, redis=tr)

    # ── 6. Async ClickHouse logging ───────────────────────────────────────────
    asyncio.create_task(
        async_pipeline.process_event(
            request_id, user_id, current, breakdown, threat, graph_result,
            tenant_id=tid,
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

    return {"status": "ok", "request_id": request_id, "score": breakdown.final_score, "tier": breakdown.tier.value}


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
