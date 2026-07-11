"""misc domain router (T-1 decomposition).

Handlers MOVED VERBATIM from api.py (decorator-only change). Route surface
unchanged (scripts/ci/openapi_route_guard.py). Imports copied from api.py
(ruff ignores unused F401) so every handler resolves.
"""
from __future__ import annotations

from fastapi import APIRouter

from api_routers._shared import APP_VERSION, _edge_sync_authorized

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
from modules.identity import scoring, threat_intel
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

router = APIRouter(prefix="", tags=["misc"])


@router.get("/api/stats")
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


@router.get("/api/events")
async def api_events(
    limit: int = 50,
    tenant: TenantContext = Depends(get_tenant),
):
    """Recent session events for the current tenant, newest first."""
    events = clickhouse_client.query_recent_events(tenant.tenant_id, limit=min(limit, 200))
    return {"tenant_id": tenant.tenant_id, "events": events, "count": len(events)}


@router.get("/api/events/hourly")
async def api_events_hourly(
    hours: int = 24,
    tenant: TenantContext = Depends(get_tenant),
):
    """Hourly event volume for the past N hours. Powers the area chart."""
    rows = clickhouse_client.query_hourly_volume(tenant.tenant_id, hours=min(hours, 168))
    return {"tenant_id": tenant.tenant_id, "rows": rows}


@router.get("/api/threats")
async def api_threats(tenant: TenantContext = Depends(get_tenant)):
    """Threat signal breakdown for the past 24 hours."""
    breakdown = clickhouse_client.query_threat_breakdown(tenant.tenant_id)
    return {"tenant_id": tenant.tenant_id, "breakdown": breakdown}


@router.get("/api/health")
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


@router.get("/api/operator/status")
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


@router.get("/api/threat-intel/feed")
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


@router.get("/api/schema/uis.json")
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


@router.get("/api/schema/attestation.json")
async def api_schema_attestation_json(
    _tenant: TenantContext = Depends(get_tenant),
):
    return schema_registry.build_attestation_schema_artifact()


@router.get("/api/attestation/spec")
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


@router.post("/api/abac/evaluate")
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


@router.get("/api/decision-audit")
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


@router.get("/api/decision-audit/{audit_id}")
async def api_get_decision_audit(
    audit_id: str,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    record = decision_audit.get_decision(tenant_id=tenant.tenant_id, audit_id=audit_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Decision audit not found")
    return {"tenant_id": tenant.tenant_id, "audit": record}


@router.post("/api/decision-audit/{audit_id}/replay")
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


@router.post("/api/integrations/idp/normalize")
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


@router.get("/api/integrations/catalog")
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


@router.get("/api/sessions")
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


@router.get("/api/cloud-findings")
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


@router.get("/api/audit")
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


@router.post("/api/simulate/blast_radius")
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


@router.get("/api/simulate/blast_radius/history")
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


@router.post("/api/ztix/simulate")
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


@router.post("/api/admin/staged-rollout/grant")
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


@router.post("/api/admin/staged-rollout/revoke")
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


@router.get("/api/admin/staged-rollout/{tenant_id}")
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


@router.get("/api/admin/staged-rollout/feature/{feature_key}")
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


@router.get("/api/edge/revoked-certs")
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


@router.get("/api/edge/drift-snapshot")
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


