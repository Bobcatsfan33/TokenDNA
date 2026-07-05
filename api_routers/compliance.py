"""compliance domain router (T-1 decomposition).

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

router = APIRouter(prefix="", tags=["compliance"])


@router.get("/api/compliance/frameworks")
async def api_compliance_frameworks(
    _tenant: TenantContext = Depends(get_tenant),
):
    return {"frameworks": sorted(list(compliance.CONTROL_MAPS.keys()))}


@router.get("/api/compliance/controls/{framework}")
async def api_compliance_controls(
    framework: str,
    _tenant: TenantContext = Depends(get_tenant),
):
    return {"control_map": compliance.build_control_map(framework)}


@router.post("/api/compliance/evidence/generate")
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


@router.get("/api/compliance/evidence/packages")
async def api_list_compliance_evidence_packages(
    framework: str | None = None,
    limit: int = 50,
    cursor: str | None = None,
    tenant: TenantContext = Depends(get_tenant),
):
    """Cursor-paginated evidence packages.  ?limit=N (default 50, max 200)
    + ?cursor=<opaque>; response includes ``next_cursor`` (null when
    exhausted)."""
    from modules.storage.pagination import paginate_offset  # noqa: PLC0415
    page = paginate_offset(
        lambda offset, lim: compliance.list_evidence_packages(
            tenant_id=tenant.tenant_id,
            framework=framework.lower() if framework else None,
            limit=lim, offset=offset,
        ),
        cursor=cursor,
        limit=limit,
    )
    return page.as_response("packages", extra={"tenant_id": tenant.tenant_id})


@router.post("/api/compliance/evidence/snapshot")
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


@router.get("/api/compliance/evidence/snapshots")
async def api_list_compliance_signed_snapshots(
    limit: int = 50,
    tenant: TenantContext = Depends(get_tenant),
):
    rows = compliance.list_signed_snapshots(
        tenant_id=tenant.tenant_id,
        limit=min(max(limit, 1), 200),
    )
    return {"tenant_id": tenant.tenant_id, "count": len(rows), "snapshots": rows}


@router.get("/api/compliance/evidence/snapshots/{snapshot_id}")
async def api_get_compliance_signed_snapshot(
    snapshot_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    snapshot = compliance.get_signed_snapshot(tenant.tenant_id, snapshot_id)
    if snapshot is None:
        raise HTTPException(status_code=404, detail="Signed snapshot not found")
    verification = compliance.verify_signed_snapshot(snapshot)
    return {"tenant_id": tenant.tenant_id, "snapshot": snapshot, "verification": verification}


@router.get("/api/compliance/frameworks")
async def api_ce_list_frameworks(
    _tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    return {"frameworks": compliance_engine.list_frameworks()}


@router.get("/api/compliance/frameworks/{framework_id}/controls")
async def api_ce_framework_controls(
    framework_id: str,
    _tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    try:
        return {"framework_id": framework_id, "controls": compliance_engine.get_framework_controls(framework_id)}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/compliance/agents/{agent_id}/classify")
async def api_ce_classify(
    agent_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    compliance_engine.init_db()
    framework_id = str(body.get("framework_id") or "eu_ai_act")
    factors = body.get("factors") or {}
    try:
        return compliance_engine.classify_agent(
            tenant.tenant_id, agent_id, framework_id, factors,
            classified_by=str(body.get("classified_by") or tenant.tenant_id),
            override_risk_level=body.get("override_risk_level"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/api/compliance/agents/{agent_id}/classification")
async def api_ce_get_classification(
    agent_id: str,
    framework_id: str = "eu_ai_act",
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    compliance_engine.init_db()
    result = compliance_engine.get_classification(tenant.tenant_id, agent_id, framework_id)
    if result is None:
        raise HTTPException(status_code=404, detail="No classification found")
    return result


@router.post("/api/compliance/agents/{agent_id}/assess")
async def api_ce_assess(
    agent_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    compliance_engine.init_db()
    framework_id = str(body.get("framework_id") or "eu_ai_act")
    controls_present = body.get("controls_present") or {}
    try:
        return compliance_engine.assess_compliance(
            tenant.tenant_id, agent_id, framework_id, controls_present,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/api/compliance/agents/{agent_id}/assessment")
async def api_ce_get_assessment(
    agent_id: str,
    framework_id: str = "eu_ai_act",
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    compliance_engine.init_db()
    result = compliance_engine.get_latest_assessment(tenant.tenant_id, agent_id, framework_id)
    if result is None:
        raise HTTPException(status_code=404, detail="No assessment found")
    return result


@router.get("/api/compliance/dashboard")
async def api_ce_dashboard(
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    compliance_engine.init_db()
    return compliance_engine.compliance_dashboard(tenant.tenant_id)


@router.post("/api/compliance/agents/{agent_id}/enforce")
async def api_ce_enforce(
    agent_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    compliance_engine.init_db()
    framework_id = str(body.get("framework_id") or "eu_ai_act")
    try:
        mappings = compliance_engine.create_compliance_enforcement(
            tenant.tenant_id, agent_id, framework_id,
        )
        return {"agent_id": agent_id, "framework_id": framework_id, "policies_created": mappings}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/api/compliance/agents/{agent_id}/audit")
async def api_ce_audit_export(
    agent_id: str,
    framework_id: str | None = None,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    compliance_engine.init_db()
    return compliance_engine.generate_audit_export(
        tenant.tenant_id, agent_id, framework_id,
    )


@router.post("/api/compliance/posture/{framework}/generate")
async def api_posture_generate(
    framework: str,
    body: dict,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """Generate a signed posture statement for the framework. Body may
    include period_start / period_end ISO strings; both default to a
    30-day lookback ending now."""
    from modules.identity import compliance_posture as cp  # noqa: PLC0415
    try:
        out = cp.generate_posture_statement(
            tenant_id=tenant.tenant_id,
            framework=framework,
            period_start=body.get("period_start"),
            period_end=body.get("period_end"),
        )
        return out.as_dict()
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": str(exc), "valid": sorted(cp.SUPPORTED_FRAMEWORKS)},
        ) from exc


@router.get("/api/compliance/posture/statements/{statement_id}")
async def api_posture_get(
    statement_id: str,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    from modules.identity import compliance_posture as cp  # noqa: PLC0415
    out = cp.get_posture_statement(statement_id, tenant_id=tenant.tenant_id)
    if not out:
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    return out


@router.get("/api/compliance/posture/statements")
async def api_posture_list(
    framework: str | None = None,
    limit: int = 50,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    from modules.identity import compliance_posture as cp  # noqa: PLC0415
    items = cp.list_posture_statements(
        tenant.tenant_id,
        framework=framework,
        limit=limit,
    )
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(items),
        "statements": items,
    }


@router.get("/api/compliance/posture/statements/{statement_id}/verify")
async def api_posture_verify(
    statement_id: str,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    from modules.identity import compliance_posture as cp  # noqa: PLC0415
    return cp.verify_posture_statement(statement_id, tenant_id=tenant.tenant_id)


@router.post("/api/compliance/incident/{agent_id}/reconstruct")
async def api_incident_reconstruct(
    agent_id: str,
    body: dict,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """Build a signed incident dossier joining delegation receipts,
    blast-radius simulations, intent matches, drift events, and
    policy-guard violations for one agent within a time window."""
    from modules.identity import compliance_posture as cp  # noqa: PLC0415
    since = str(body.get("since") or "").strip()
    until = body.get("until")
    if not since:
        raise HTTPException(status_code=400, detail="'since' is required (ISO timestamp)")
    return cp.incident_reconstruction(
        tenant_id=tenant.tenant_id,
        agent_id=agent_id,
        since=since,
        until=until,
    )


@router.get("/api/compliance/incident/reports/{report_id}")
async def api_incident_get(
    report_id: str,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    from modules.identity import compliance_posture as cp  # noqa: PLC0415
    out = cp.get_incident_report(report_id, tenant_id=tenant.tenant_id)
    if not out:
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    return out


