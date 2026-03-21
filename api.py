"""
TokenDNA / Aegis Security Platform -- FastAPI v2.7.0

Endpoints
─────────
GET  /                          health check (unauthenticated)
GET  /dashboard                 admin dashboard SPA (unauthenticated)

GET  /api/stats                 KPI counters for current tenant
GET  /api/events                recent session events for current tenant
GET  /api/events/hourly         hourly volume for past 24h (chart data)
GET  /api/threats               threat signal breakdown for past 24h
GET  /api/health                detailed system health

GET  /secure                    main token integrity check (DPoP optional/required)
GET  /profile/{uid}             inspect user adaptive profile
DELETE /profile/{uid}           reset user profile
POST /revoke                    manually revoke token by jti (ANALYST+)

GET  /admin/hvip/{uid}          get HVIP profile for user (ADMIN+)
PUT  /admin/hvip/{uid}          create/update HVIP profile (ADMIN+)
DELETE /admin/hvip/{uid}        delete HVIP profile (OWNER only)

POST /admin/traps               issue trap token(s) for a user (ADMIN+)
GET  /admin/traps/hits          recent trap hit telemetry (ADMIN+)

POST /admin/tenants             create tenant  (returns raw API key, show once)
GET  /admin/tenants             list all tenants
GET  /admin/tenants/{id}/keys   list API keys for a tenant
POST /admin/tenants/{id}/keys   rotate / add API key
DELETE /admin/tenants/{id}/keys/{kid}  revoke a key

POST /onboarding/aws/external-id   generate ExternalId for CloudFormation
POST /onboarding/aws/test          test IAM role + quick posture scan

POST /webhook/preflight/{idp}  pre-issuance risk gate webhook
                                idp ∈ "auth0" | "okta" | "keycloak" | "generic"

v2.4.0 — IL5 Foundation:
  - FIPS 140-2 startup enforcement (FATAL in IL5/IL6 if not FIPS-active).
  - DPoP RFC 9449 token binding wired into /secure (optional_dpop) and
    ANALYST+ routes (require_dpop when DPOP_REQUIRED=true).
  - HVIP enforcer applied in scoring pipeline — OWNER/ADMIN identities
    checked against hardened profile policies (geo, DPoP, MFA, score thresholds).
  - /admin/hvip/* endpoints for HVIP profile management.

v2.5.0 — Active Defense + Pre-Issuance Gate:
  - Token Trap (SC-26 honeypot): trap token middleware intercepts stolen-
    credential use before verify_token runs; issues synthetic response to
    attacker while revoking all real tokens for that uid/tenant and firing
    SIEM + Slack alerts.
  - Pre-issuance Risk Gate: /webhook/preflight/{idp} evaluates 8 risk signals
    (impossible travel, threat intel, new device, cred stuffing, velocity, HVIP,
    ML score, global block) before IdP issues a token.  Returns IdP-native
    response format (Auth0 / Okta / Keycloak / generic).
  - Token Trap admin endpoints: POST /admin/traps (issue), GET /admin/traps/hits.

v2.7.0 — mTLS Service Mesh:
  - MTLSMiddleware: proxy mode (Nginx/Envoy) and native mode (Uvicorn TLS).
  - PeerIdentity bound into request.state for downstream RBAC enrichment.
  - FIPS-approved cipher suite (TLS 1.2+, ECDHE-AES-GCM, DHE-AES-GCM).
  - Zero-downtime cert rotation via background _CertWatcher thread (60s poll).
  - CN allowlist enforcement (MTLS_ALLOWED_CNS env) with SAN fallback.
  - Expired-cert rejection with AU-2 audit log emission.
  - NIST SC-8, SC-8(1), IA-3, SC-17, MA-3, SC-23 coverage.
  - get_uvicorn_ssl_config() helper for native Uvicorn mTLS deployment.
"""

import asyncio
import logging
import os
import uuid
from pathlib import Path
from typing import Any, Callable, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

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
from modules.security.fips import fips as _fips
from modules.security.headers import RequestValidationMiddleware, SecurityHeadersMiddleware
from modules.security.rbac import Role, require_role
from modules.identity.dpop import optional_dpop, require_dpop, DPoPClaims
from modules.identity.hvip import enforcer as _hvip_enforcer, registry as _hvip_registry, HVIPConfig, HVIPDecision
from modules.defense.token_trap import (
    TrapHitRecord,
    _store as _trap_store,
    trap_token_check as _trap_token_check,
    get_synthetic_response,
    issue_trap,
    issue_trap_batch,
    recent_trap_hits,
)
from modules.identity.preflight import (
    GateDecision,
    build_preflight_context,
    evaluate_preflight,
)
from modules.transport.mtls import (
    MTLSMiddleware,
    check_mtls_config,
    get_uvicorn_ssl_config,
    start_cert_watcher,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

_DASHBOARD_PATH = Path(__file__).parent / "dashboard" / "index.html"

app = FastAPI(
    title="Aegis Security Platform",
    description="TokenDNA zero-trust session integrity + Aegis cloud posture management",
    version="2.7.0",
    docs_url="/api/docs" if DEV_MODE else None,
    redoc_url="/api/redoc" if DEV_MODE else None,
)


# ── Token Trap Middleware (must register before route middleware) ───────────────
# SC-26 (Honeypots), IR-4 (Incident Handling), AU-2 (Event Logging)
# Intercepts trap-token requests BEFORE verify_token so the attacker never gets
# a meaningful 401 — they receive a plausible synthetic 200 instead.
@app.middleware("http")
async def trap_token_middleware(request: Request, call_next: Any):
    """
    Transparent trap-token interceptor.

    1. Checks Bearer token against the trap store (O(1) SHA-256 lookup).
    2. If match → fires TrapMonitor (HMAC verify, revoke real tokens, SIEM alert).
    3. Returns synthetic API response that looks like a real 200 success.
    4. If not a trap → lets request proceed normally to route handlers.

    Placed as a raw ASGI middleware so it runs before FastAPI dependency
    injection (including verify_token), giving zero-leak deception.
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        raw_token = auth_header[7:].strip()
        if raw_token and _trap_store.is_trap(raw_token):
            # Token is a trap — run full inspection pipeline before verify_token
            try:
                hit = await _trap_token_check(request)
                if hit is not None:
                    synthetic = get_synthetic_response(hit)
                    logger.warning(
                        "[TrapToken] HIT uid=%s tenant=%s ip=%s trap_id=%s "
                        "real_tokens_revoked=%d",
                        hit.uid, hit.tenant_id,
                        hit.attacker_ip, hit.trap_id,
                        hit.real_tokens_revoked,
                    )
                    return JSONResponse(content=synthetic, status_code=200)
            except Exception as exc:
                logger.error("[TrapToken] Monitor error: %s", exc)
                # Return synthetic response even on monitor error — never leak trap status
                return JSONResponse(
                    content={"status": "ok", "message": "Request processed."},
                    status_code=200,
                )

    return await call_next(request)

# Security middleware (order matters — outermost added last executes first in Starlette)
# Execution order: CORS → mTLS → RequestValidation → SecurityHeaders → TrapToken → routes
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestValidationMiddleware)
# SC-8 / IA-3: mTLS transport layer — enforces client certificate authentication
# MTLSMiddleware runs before route handlers; PeerIdentity injected into request.state
if os.getenv("MTLS_MODE", "").lower() in ("proxy", "native"):
    app.add_middleware(MTLSMiddleware)
    logger.info("mTLS middleware ENABLED (mode=%s)", os.getenv("MTLS_MODE"))
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "X-API-Key", "X-Correlation-ID", "Content-Type",
                   "X-Client-Cert", "X-Forwarded-Client-Cert"],
    allow_credentials=False,  # explicit — never wildcard credentials
)


# ── Startup ───────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_checks():
    # SC-13 / IA-7: FIPS 140-2 enforcement — FATAL in IL5/IL6 if FIPS not active
    _fips.startup_check()
    fips_summary = _fips.compliance_summary()
    if fips_summary.get("fips_active"):
        logger.info("FIPS 140-2: ACTIVE — all cryptographic operations use validated modules.")
    else:
        logger.warning(
            f"FIPS 140-2: NOT ACTIVE (environment={fips_summary.get('environment')}). "
            "Enable kernel FIPS mode before deploying to IL4/IL5/IL6."
        )

    if DEV_MODE:
        logger.warning("DEV_MODE=true — JWT auth disabled. Not for production.")
    if not OIDC_ISSUER and not DEV_MODE:
        logger.warning("OIDC_ISSUER not set — authenticated endpoints will 401.")

    dpop_required = os.getenv("DPOP_REQUIRED", "false").lower() == "true"
    logger.info("DPoP token binding: %s", "REQUIRED" if dpop_required else "optional")
    logger.info("HVIP auto-admin profiles: %s",
                "ENABLED" if os.getenv("HVIP_AUTO_ADMIN", "true").lower() == "true" else "DISABLED")

    os.makedirs("/data", exist_ok=True)
    tenant_store.init_db()

    from modules.identity.cache_redis import is_available as redis_ok
    logger.info("Redis: %s", "connected" if redis_ok() else "UNREACHABLE")
    logger.info("ClickHouse: %s", "connected" if clickhouse_client.is_available() else "UNREACHABLE")

    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, threat_intel._ensure_tor_list)

    # v2.5: Token Trap + Preflight gate readiness
    trap_hmac_set = bool(os.getenv("TRAP_HMAC_KEY"))
    logger.info(
        "Token Trap (SC-26 honeypot): ACTIVE — TRAP_HMAC_KEY %s",
        "SET (secure)" if trap_hmac_set else "NOT SET (ephemeral key — set TRAP_HMAC_KEY in production!)",
    )
    logger.info("Pre-issuance Risk Gate: ACTIVE — webhook endpoints: /webhook/preflight/{idp}")

    # v2.7: mTLS service mesh configuration check (SC-8, IA-3)
    mtls_mode = os.getenv("MTLS_MODE", "").lower()
    mtls_summary: dict = {}
    if mtls_mode in ("proxy", "native"):
        try:
            mtls_summary = check_mtls_config()
            logger.info(
                "mTLS: CONFIGURED — mode=%s header=%s allowed_cns=%s",
                mtls_summary.get("mode"),
                mtls_summary.get("cert_header"),
                mtls_summary.get("allowed_cns"),
            )
            # Start cert rotation watcher in background (zero-downtime rotation)
            start_cert_watcher()
        except Exception as exc:
            logger.error("mTLS config error: %s", exc)
    else:
        logger.warning(
            "mTLS: NOT ENABLED (MTLS_MODE not set). "
            "Set MTLS_MODE=proxy or MTLS_MODE=native for IL4/IL5 transport security (SC-8)."
        )

    # Emit startup audit event (AU-2: application startup)
    log_event(AuditEventType.STARTUP, AuditOutcome.SUCCESS,
              detail={
                  "version": "2.7.0",
                  "dev_mode": DEV_MODE,
                  "fips_active": fips_summary.get("fips_active", False),
                  "dpop_required": dpop_required,
                  "trap_hmac_configured": trap_hmac_set,
                  "mtls_mode": mtls_mode or "disabled",
                  "mtls_allowed_cns": list(mtls_summary.get("allowed_cns") or []),
              })


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
    fips_info = _fips.compliance_summary()
    return {
        "service":       "TokenDNA",
        "version":       "2.7.0",
        "redis":         redis_ok(),
        "clickhouse":    clickhouse_client.is_available(),
        "dev_mode":      DEV_MODE,
        "fips_active":   fips_info.get("fips_active", False),
        "dpop_required": os.getenv("DPOP_REQUIRED", "false").lower() == "true",
        "trap_active":   True,
        "preflight_gate": True,
        "mtls_enabled":  os.getenv("MTLS_MODE", "").lower() in ("proxy", "native"),
        "mtls_mode":     os.getenv("MTLS_MODE", "disabled"),
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
        "version":     "2.1.0",
    }


# ── Main integrity check ──────────────────────────────────────────────────────

@app.get("/secure")
async def secure(
    request: Request,
    user: dict = Depends(verify_token),
    tenant: TenantContext = Depends(get_tenant),
    _rate: None = Depends(check_rate_limit),
    dpop: Optional[DPoPClaims] = Depends(optional_dpop),
):
    """
    Main zero-trust token integrity check.
    DPoP proof is validated if present; required when DPOP_REQUIRED=true.
    HVIP policies enforced for OWNER/ADMIN identities.
    """
    request_id = str(uuid.uuid4())
    user_id    = user.get("sub", "unknown")
    jti        = user.get("jti", "")
    tid        = tenant.tenant_id
    user_role  = user.get("role", "user")

    # ── 0. DPoP binding check ──────────────────────────────────────────────────
    # If DPOP_REQUIRED=true and no DPoP proof was presented, reject
    dpop_required_env = os.getenv("DPOP_REQUIRED", "false").lower() == "true"
    if dpop_required_env and dpop is None:
        raise HTTPException(
            status_code=401,
            detail="DPoP proof required. Include DPoP header with RFC 9449 proof JWT.",
            headers={"WWW-Authenticate": 'Bearer error="invalid_dpop_proof"'},
        )

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

    # ── 4b. HVIP Policy Enforcement (OWNER / ADMIN identities) ──────────────
    # High-Value Identity Profiles apply stricter controls to privileged roles.
    # IA-5 / AC-6 / SC-13: Privileged identity hardening.
    hvip_context = {
        "ip":                   request.client.host if request.client else "",
        "country":              geo.country if geo else "",
        "asn":                  str(geo.asn) if geo else "",
        "has_dpop":             dpop is not None,
        "has_hardware_mfa":     user.get("amr", []) and any(
                                    m in user.get("amr", [])
                                    for m in ("hwk", "pop", "fido", "u2f")
                                ),
        "token_issued_at":      user.get("iat"),
        "anomaly_score":        breakdown.final_score,
        "anomaly_reasons":      breakdown.reasons,
        "request_id":           request_id,
        "tenant_id":            tid,
        "role":                 user_role,
    }
    hvip_decision = _hvip_enforcer.evaluate(user_id, tid, user_role, hvip_context)

    if hvip_decision == HVIPDecision.REVOKE:
        push_baseline_history(user_id, baseline, tenant_id=tid)
        revoke_token(jti, ttl_seconds=3600, tenant_id=tid)
        log_event(AuditEventType.AUTH_TOKEN_REVOKED, AuditOutcome.SUCCESS,
                  tenant_id=tid, subject=user_id,
                  resource=f"jti:{jti}",
                  detail={"reason": "hvip_revoke", "context": hvip_context})
        return Response(
            content='{"status":"revoked","message":"Token revoked by HVIP policy"}',
            status_code=401, media_type="application/json",
        )
    elif hvip_decision == HVIPDecision.BLOCK:
        log_event(AuditEventType.ACCESS_DENIED, AuditOutcome.FAILURE,
                  tenant_id=tid, subject=user_id,
                  detail={"reason": "hvip_block", "context": hvip_context})
        raise HTTPException(
            status_code=403,
            detail={"status": "blocked", "reason": "hvip_policy_violation",
                    "message": "Access denied by High-Value Identity Profile policy"},
        )
    elif hvip_decision == HVIPDecision.STEP_UP:
        return Response(
            content='{"status":"step_up","reason":"hvip_policy","message":"Step-up authentication required"}',
            status_code=202, media_type="application/json",
        )

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

    return {
        "status":      "ok",
        "request_id":  request_id,
        "score":       breakdown.final_score,
        "tier":        breakdown.tier.value,
        "dpop_bound":  dpop is not None,
        "hvip_decision": hvip_decision.value if hvip_decision else "allow",
    }


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


# ── HVIP Profile Management ───────────────────────────────────────────────────

@app.get("/admin/hvip/{uid}")
async def get_hvip_profile(
    uid: str,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """
    Retrieve the HVIP policy profile for a user.
    ADMIN+ required — HVIP profiles are privileged security configuration.
    IA-5 / AC-6: Identity management and least privilege.
    """
    profile = _hvip_registry.get(uid, tenant.tenant_id)
    if profile is None:
        raise HTTPException(status_code=404, detail=f"No HVIP profile found for user '{uid}'")

    log_event(AuditEventType.ACCESS_GRANTED, AuditOutcome.SUCCESS,
              tenant_id=tenant.tenant_id, subject=tenant.owner_email,
              resource=f"hvip:{uid}", detail={"action": "get_hvip_profile"})

    return {
        "user_id":   uid,
        "tenant_id": tenant.tenant_id,
        "profile": {
            "geo_lock":              profile.geo_lock,
            "allowed_asns":          profile.allowed_asns,
            "allowed_ips":           profile.allowed_ips,
            "max_token_age_seconds": profile.max_token_age_seconds,
            "require_dpop":          profile.require_dpop,
            "require_hardware_mfa":  profile.require_hardware_mfa,
            "step_up_on_any_anomaly": profile.step_up_on_any_anomaly,
            "revoke_on_high_anomaly": profile.revoke_on_high_anomaly,
            "min_allow_score":       profile.min_allow_score,
            "allowed_hours_utc":     profile.allowed_hours_utc,
            "allowed_days_of_week":  profile.allowed_days_of_week,
        },
    }


@app.put("/admin/hvip/{uid}", status_code=200)
async def upsert_hvip_profile(
    uid: str,
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """
    Create or update a High-Value Identity Profile for a user.
    ADMIN+ required. Validates all fields before persisting.
    IA-5 / AC-6 / SC-13: Privileged identity hardening.
    """
    try:
        profile = HVIPConfig(
            user_id=uid,
            tenant_id=tenant.tenant_id,
            geo_lock=body.get("geo_lock", []),
            allowed_asns=body.get("allowed_asns", []),
            allowed_ips=body.get("allowed_ips", []),
            max_token_age_seconds=int(body.get("max_token_age_seconds", 3600)),
            require_dpop=bool(body.get("require_dpop", False)),
            require_hardware_mfa=bool(body.get("require_hardware_mfa", False)),
            step_up_on_any_anomaly=bool(body.get("step_up_on_any_anomaly", False)),
            revoke_on_high_anomaly=bool(body.get("revoke_on_high_anomaly", True)),
            min_allow_score=float(body.get("min_allow_score", 0.0)),
            allowed_hours_utc=body.get("allowed_hours_utc"),
            allowed_days_of_week=body.get("allowed_days_of_week"),
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid HVIP profile: {exc}")

    _hvip_registry.put(profile)

    log_event(AuditEventType.ACCESS_GRANTED, AuditOutcome.SUCCESS,
              tenant_id=tenant.tenant_id, subject=tenant.owner_email,
              resource=f"hvip:{uid}", detail={"action": "upsert_hvip_profile",
                                              "require_dpop": profile.require_dpop,
                                              "require_hardware_mfa": profile.require_hardware_mfa})

    return {
        "status":    "saved",
        "user_id":   uid,
        "tenant_id": tenant.tenant_id,
    }


@app.delete("/admin/hvip/{uid}")
async def delete_hvip_profile(
    uid: str,
    tenant: TenantContext = Depends(require_role(Role.OWNER)),
):
    """
    Delete a user's HVIP profile, reverting to default scoring rules.
    OWNER role required — profile deletion is a destructive privileged action.
    """
    existing = _hvip_registry.get(uid, tenant.tenant_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"No HVIP profile for '{uid}'")

    _hvip_registry.delete(uid, tenant.tenant_id)

    log_event(AuditEventType.ACCESS_GRANTED, AuditOutcome.SUCCESS,
              tenant_id=tenant.tenant_id, subject=tenant.owner_email,
              resource=f"hvip:{uid}", detail={"action": "delete_hvip_profile"})

    return {"status": "deleted", "user_id": uid}


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


# ── Token Trap Admin Endpoints ────────────────────────────────────────────────
# SC-26 (Honeypots) / IR-4 (Incident Handling) / AU-2 (Event Logging)
# ADMIN+ required: trap tokens are sensitive operational security tooling.

@app.post("/admin/traps", status_code=201)
async def create_trap_tokens(
    body: dict,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """
    Issue one or more trap tokens for a user identity.

    Request body:
      uid    (str)  — user id to impersonate in trap token
      label  (str)  — human label for the trap, e.g. "s3-backup" (optional)
      count  (int)  — number of trap tokens to issue; 1=single, 2-5=batch (optional)

    Returns the issued trap token(s) including the raw bearer token value.
    Store these tokens in realistic-looking locations (S3, Git history, env files)
    to catch credential-exfiltration attackers.

    SECURITY: Trap tokens are signed with TRAP_HMAC_KEY (separate from real JWT key).
    The raw token value is shown only on issuance — store securely.
    """
    uid   = body.get("uid", "").strip()
    label = body.get("label", "default").strip()
    count = max(1, min(int(body.get("count", 1)), 5))  # cap at 5

    if not uid:
        raise HTTPException(status_code=400, detail="'uid' field required")

    log_event(AuditEventType.ACCESS_GRANTED, AuditOutcome.SUCCESS,
              tenant_id=tenant.tenant_id, subject=tenant.owner_email,
              resource=f"trap:{uid}",
              detail={"action": "issue_trap", "count": count, "label": label})

    if count == 1:
        trap = issue_trap(uid, tenant.tenant_id, label=label)
        return {
            "status":   "issued",
            "uid":      uid,
            "trap_id":  trap.trap_id,
            "token":    trap.token,
            "expires_at": trap.expires_at,
            "label":    trap.label,
            "warning":  (
                "Store this token in a realistic location (env file, git history, "
                "S3 object) to bait credential-theft attackers. "
                "Any use of this token will trigger full incident response."
            ),
        }
    else:
        traps = issue_trap_batch(uid, tenant.tenant_id, count=count)
        return {
            "status": "issued",
            "uid":    uid,
            "count":  len(traps),
            "traps": [
                {
                    "trap_id":   t.trap_id,
                    "token":     t.token,
                    "label":     t.label,
                    "expires_at": t.expires_at,
                }
                for t in traps
            ],
            "warning": (
                "Distribute these tokens across different exfiltration paths "
                "(env files, Git history, S3 objects, CI/CD secrets) to "
                "fingerprint the specific exfiltration channel when hit."
            ),
        }


@app.get("/admin/traps/hits")
async def get_trap_hits(
    limit: int = 50,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    """
    Return recent trap token hit records.
    Each record includes attacker IP, User-Agent, ASN, country, token age,
    number of real tokens revoked, and the label of the triggered trap.

    ADMIN+ required — trap hit telemetry is sensitive incident response data.
    SI-3 / IR-4 / SC-26 / AU-2.
    """
    limit = max(1, min(limit, 200))
    hits  = recent_trap_hits(limit=limit)

    log_event(AuditEventType.ACCESS_GRANTED, AuditOutcome.SUCCESS,
              tenant_id=tenant.tenant_id, subject=tenant.owner_email,
              resource="/admin/traps/hits",
              detail={"action": "list_trap_hits", "limit": limit})

    return {
        "total": len(hits),
        "hits":  hits,
        "tenant_id": tenant.tenant_id,
    }


# ── Pre-Issuance Risk Gate Webhooks ──────────────────────────────────────────
# NIST IA-5 / IA-11 / AC-2 / SI-4: Evaluate risk BEFORE the IdP issues tokens.
# Supports Auth0 Pre-Token-Generation Actions, Okta Token Inline Hooks,
# Keycloak Event Listener SPI, and a generic webhook format.

@app.post("/webhook/preflight/{idp}")
async def preflight_webhook(
    idp: str,
    body: dict,
    request: Request,
):
    """
    Pre-issuance risk gate webhook.  Called by your IdP before issuing tokens.

    idp path parameter:
      "auth0"     — Auth0 Pre-Token-Generation Action hook
      "okta"      — Okta Token Inline Hook
      "keycloak"  — Keycloak Event Listener SPI
      "generic"   — Generic webhook (any IdP)

    The gate evaluates 8 risk signals:
      1. Global block list (instant DENY)
      2. Impossible travel (>900 km/h velocity)
      3. Threat intelligence (Tor, VPN, malicious ASN)
      4. New device fingerprint
      5. Credential stuffing (failed-login spike)
      6. Token velocity (>20 tokens/hour per uid)
      7. HVIP policy check (for privileged identities)
      8. ML anomaly score

    Gate decisions:
      ALLOW   → IdP issues token normally
      ENRICH  → IdP issues token + injects risk claims
      STEP_UP → IdP challenges user for step-up MFA
      DENY    → IdP blocks token issuance entirely

    Response format matches the IdP's native hook response schema.

    Authentication: This endpoint should be called from your IdP's network only.
    Protect with IP allowlisting or mutual TLS at the ingress layer.
    """
    idp = idp.lower().strip()
    valid_idps = {"auth0", "okta", "keycloak", "generic"}
    if idp not in valid_idps:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown IdP '{idp}'. Valid values: {sorted(valid_idps)}",
        )

    try:
        result = evaluate_preflight(body, idp=idp)
    except Exception as exc:
        logger.error("[Preflight] Evaluation error for idp=%s: %s", idp, exc)
        # Fail open (allow) on internal errors — avoids blocking all logins if
        # Redis is down. Operators can configure PREFLIGHT_FAIL_CLOSED=true to
        # fail closed in high-security environments.
        fail_closed = os.getenv("PREFLIGHT_FAIL_CLOSED", "false").lower() == "true"
        if fail_closed:
            # Return deny in the appropriate IdP format
            error_body = {"uid": body.get("user_id") or body.get("data", {}).get("userProfile", {}).get("login", "unknown")}
            result = evaluate_preflight({"error": True}, idp="generic")
        else:
            # Fail open — return minimal allow response
            if idp == "auth0":
                return {"access": "continue"}
            elif idp == "okta":
                return {"commands": []}
            elif idp == "keycloak":
                return {"deny": False, "extra_claims": {}}
            else:
                return {"decision": "allow", "signals": []}

    # Audit log every preflight evaluation (AU-2 / IA-11)
    logger.info(
        "[Preflight] idp=%s uid=%s decision=%s score=%.1f signals=%s",
        idp, result.uid, result.decision.value,
        result.risk_score,
        [s.name for s in result.signals if s.triggered],
    )

    if result.decision in (GateDecision.DENY, GateDecision.STEP_UP):
        logger.warning(
            "[Preflight] %s uid=%s score=%.1f triggered=%s",
            result.decision.value.upper(),
            result.uid, result.risk_score,
            [s.name for s in result.signals if s.triggered],
        )

    # Return IdP-native response
    if idp == "auth0":
        return result.to_auth0_action_response()
    elif idp == "okta":
        return result.to_okta_hook_response()
    elif idp == "keycloak":
        return result.to_keycloak_hook_response()
    else:
        # Generic: return structured decision + signal breakdown
        return {
            "decision":   result.decision.value,
            "risk_score": result.risk_score,
            "uid":        result.uid,
            "signals": [
                {
                    "name":      s.name,
                    "triggered": s.triggered,
                    "weight":    s.weight,
                    "evidence":  s.evidence,
                    "mitre":     s.mitre,
                    "nist":      s.nist,
                }
                for s in result.signals
                if s.triggered
            ],
            "claims": result.enrichment_claims,
        }


# ── Attribution Dashboard Endpoints ───────────────────────────────────────────
# NIST SI-3 · IR-4 · SC-26 · AU-2 · RA-3 · PM-16
# Builds attacker profiles, campaign clusters, kill-chain maps, IOC lists.
# ADMIN+ required — attribution data is the most sensitive telemetry in the platform.

@app.get("/api/attribution")
async def attribution_dashboard(
    window_hours: int = 168,
    _user: dict = Depends(verify_token),
    _role: Any  = Depends(require_role(Role.ADMIN)),
):
    """
    Full attribution data payload for the Attribution Dashboard.

    Returns:
      kpis             — total hits, unique IPs, campaigns, tokens revoked
      geo              — top countries by hit count
      asns             — top ASNs (attacker hosting infrastructure)
      kill_chain       — MITRE ATT&CK kill chain stage distribution
      mitre            — technique frequency table
      daily_hits       — 30-day hit timeline
      attacker_profiles — per-IP aggregated attacker records
      campaigns        — correlated multi-IP campaign clusters
      iocs             — IP/ASN/UA indicators of compromise
      preflight_stats  — gate decision breakdown + signal frequency

    ADMIN+ required — attribution data surfaces specific attacker IPs and IOCs.
    SI-3 / IR-4 / SC-26 / RA-3.
    """
    from modules.attribution.engine import build_attribution_summary
    window_hours = max(1, min(window_hours, 720))
    summary = build_attribution_summary(window_hours=window_hours)
    return summary.to_dict()


@app.get("/api/attribution/iocs")
async def attribution_iocs(
    min_confidence: float = 0.3,
    ioc_type: str = "",
    limit: int = 200,
    _user: dict = Depends(verify_token),
    _role: Any  = Depends(require_role(Role.ADMIN)),
):
    """
    Export IOC list for ingestion into SIEM, EDR, firewall, or block lists.

    Each IOC includes type (ip | asn | user_agent), value, confidence score,
    hit count, first/last seen timestamps, and human-readable context.

    Use ?ioc_type=ip to filter to IP IOCs only for firewall ACL ingestion.
    ADMIN+ required.
    """
    from modules.attribution.engine import AttributionEngine, build_attribution_summary
    from modules.defense.token_trap import recent_trap_hits

    raw_hits = recent_trap_hits(limit=500)
    engine   = AttributionEngine()
    profiles = engine.build_profiles(raw_hits)
    iocs     = engine.build_iocs(profiles, min_confidence=min_confidence)

    if ioc_type:
        iocs = [i for i in iocs if i.ioc_type == ioc_type]

    return {
        "iocs":           [i.to_dict() for i in iocs[:limit]],
        "total":          len(iocs),
        "min_confidence": min_confidence,
        "ioc_type_filter": ioc_type or None,
        "generated_at":   __import__("datetime").datetime.utcnow().isoformat() + "Z",
    }


@app.get("/dashboard/attribution", response_class=HTMLResponse)
async def attribution_dashboard_ui():
    """Serve the Attribution Dashboard SPA."""
    from pathlib import Path
    path = Path(__file__).parent / "dashboard" / "attribution.html"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Attribution Dashboard not found")
    return FileResponse(path)
