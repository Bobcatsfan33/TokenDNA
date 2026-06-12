"""
TokenDNA Identity Backbone -- FastAPI app factory (v2.5.0).

This module is the APP FACTORY only (T-1 decomposition complete). It builds the
FastAPI app, wires middleware + lifespan + startup checks, and mounts every
product domain router via ``api_routers.mount_all``. The 305 product routes live
in ``api_routers/<domain>.py`` — one router per domain, each declaring its own
auth + tier-gate dependencies. The CI ratchet
(``scripts/ci/api_monolith_ratchet.py``) keeps this file from regrowing; new
endpoints are born in ``api_routers/``, never here.

Only infrastructure endpoints remain in this file:
  GET /          service info / health
  GET /healthz   Kubernetes liveness
  GET /readyz    Kubernetes readiness (503 when a dependency is down)
  GET /metrics   Prometheus exposition
"""
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import DEV_MODE, OIDC_ISSUER
from modules.identity import threat_intel
from modules.identity import clickhouse_client

# alias used in /api/oss/sdk/attest route
from modules.security.audit_log import AuditEventType, AuditOutcome, log_event
from modules.security.headers import RequestValidationMiddleware, SecurityHeadersMiddleware
from modules.security.fips import fips

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)
from api_routers._shared import APP_VERSION  # noqa: E402

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
