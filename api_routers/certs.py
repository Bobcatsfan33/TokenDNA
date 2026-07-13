"""certs domain router (T-1 decomposition).

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
from modules.identity import pipeline
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
from modules.identity.pipeline import RiskTier
from modules.identity.pipeline import generate_dna, migrate_dna
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

router = APIRouter(prefix="", tags=["certs"])


@router.get("/api/certs/fleet")
async def api_certs_fleet(
    status: str | None = None,
    limit: int = 500,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
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


@router.get("/api/certs/fleet/summary")
async def api_certs_fleet_summary(
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """Quick-summary stats for the operator dashboard header widget."""
    cert_dashboard.init_db()
    return cert_dashboard.fleet_summary(tenant_id=tenant.tenant_id)


@router.get("/api/certs/expiring")
async def api_certs_expiring(
    within_days: int = 30,
    limit: int = 200,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
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


@router.post("/api/certs/sweep")
async def api_certs_sweep(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """Run the adaptive certificate-lifecycle sweep (T-4 automation).

    Classifies the fleet, refreshes expiry alerts, and triggers registered
    renewal hooks for certs inside the renewal window — idempotently.
    Body: {"renew_within_days": int?, "dry_run": bool?}.
    """
    cert_dashboard.init_db()
    renew_within = body.get("renew_within_days")
    return cert_dashboard.run_expiry_sweep(
        tenant_id=tenant.tenant_id,
        renew_within_days=int(renew_within) if renew_within is not None else cert_dashboard.RENEWAL_THRESHOLD_DAYS,
        dry_run=bool(body.get("dry_run", False)),
    )


@router.get("/api/certs/renewals")
async def api_certs_renewals(
    limit: int = 200,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """List recorded certificate renewal actions for the tenant (T-4)."""
    cert_dashboard.init_db()
    renewals = cert_dashboard.list_renewals(tenant_id=tenant.tenant_id, limit=limit)
    return {"renewals": renewals, "count": len(renewals)}


@router.post("/api/certs/expiry-alerts/{alert_id}/acknowledge")
async def api_ack_expiry_alert(
    alert_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
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


@router.post("/api/certs/usage")
async def api_record_cert_usage(
    body: dict = Body(...),
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
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


@router.get("/api/certs/anomalies")
async def api_cert_anomalies(
    resolved: bool | None = None,
    limit: int = 200,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """Return certificate usage anomalies for this tenant."""
    cert_dashboard.init_db()
    anomalies = cert_dashboard.list_anomalies(
        tenant_id=tenant.tenant_id,
        resolved=resolved,
        limit=limit,
    )
    return {"anomalies": anomalies, "count": len(anomalies)}


@router.post("/api/certs/anomalies/{anomaly_id}/resolve")
async def api_resolve_cert_anomaly(
    anomaly_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
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


@router.get("/api/certs/{cert_id}/history")
async def api_cert_history(
    cert_id: str,
    limit: int = 200,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """Full usage history for a single certificate."""
    cert_dashboard.init_db()
    history = cert_dashboard.get_cert_history(
        tenant_id=tenant.tenant_id,
        certificate_id=cert_id,
        limit=limit,
    )
    return {"certificate_id": cert_id, "history": history, "count": len(history)}


