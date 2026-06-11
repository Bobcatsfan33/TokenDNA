"""threat-sharing domain router (T-1 decomposition).

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

router = APIRouter(prefix="", tags=["threat-sharing"])


@router.post("/api/threat-sharing/opt-in")
async def api_threat_sharing_opt_in(
    tenant: TenantContext = Depends(require_feature("ent.intent_correlation")),
):
    """Opt the current tenant into the threat-sharing network."""
    from modules.product import threat_sharing  # noqa: PLC0415
    return threat_sharing.opt_in(tenant.tenant_id)


@router.post("/api/threat-sharing/opt-out")
async def api_threat_sharing_opt_out(
    tenant: TenantContext = Depends(require_feature("ent.intent_correlation")),
):
    """Opt the current tenant out. Past propagations are retained."""
    from modules.product import threat_sharing  # noqa: PLC0415
    return threat_sharing.opt_out(tenant.tenant_id)


@router.get("/api/threat-sharing/status")
async def api_threat_sharing_status(
    tenant: TenantContext = Depends(require_feature("ent.intent_correlation")),
):
    """Opt-in status + counters for the current tenant."""
    from modules.product import threat_sharing  # noqa: PLC0415
    return threat_sharing.get_status(tenant.tenant_id)


@router.post("/api/threat-sharing/publish/{playbook_id}")
async def api_threat_sharing_publish(
    playbook_id: str,
    tenant: TenantContext = Depends(require_feature("ent.intent_correlation")),
):
    """Anonymize and publish one of the tenant's custom playbooks."""
    from modules.product import threat_sharing  # noqa: PLC0415
    try:
        return threat_sharing.publish_playbook(tenant.tenant_id, playbook_id)
    except ValueError as exc:
        reason = str(exc)
        if reason == "not_opted_in":
            raise HTTPException(
                status_code=409,
                detail={"error": "not_opted_in",
                        "message": "Tenant must opt in to the threat-sharing network before publishing."},
            ) from exc
        if reason == "not_found":
            raise HTTPException(
                status_code=404,
                detail={"error": "playbook_not_found",
                        "message": f"Playbook {playbook_id!r} not found or not owned by this tenant."},
            ) from exc
        if reason == "builtin_blocked":
            raise HTTPException(
                status_code=400,
                detail={"error": "builtin_not_publishable",
                        "message": "Built-in playbooks are global; only tenant-owned custom playbooks can be published."},
            ) from exc
        raise


@router.post("/api/threat-sharing/sync")
async def api_threat_sharing_sync(
    tenant: TenantContext = Depends(require_feature("ent.intent_correlation")),
):
    """Pull every new network playbook the tenant has not yet received."""
    from modules.product import threat_sharing  # noqa: PLC0415
    added = threat_sharing.sync_network_playbooks(tenant.tenant_id)
    return {
        "tenant_id": tenant.tenant_id,
        "added": added,
        "opted_in": threat_sharing.is_opted_in(tenant.tenant_id),
    }


@router.get("/api/threat-sharing/network")
async def api_threat_sharing_network(
    limit: int = 100,
    tenant: TenantContext = Depends(require_feature("ent.intent_correlation")),
):
    """Browse the anonymized network catalog."""
    from modules.product import threat_sharing  # noqa: PLC0415
    playbooks = threat_sharing.list_network_playbooks(limit=limit)
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(playbooks),
        "playbooks": playbooks,
    }


@router.post("/api/threat-sharing/network/{network_playbook_id}/hit")
async def api_flywheel_record_hit(
    network_playbook_id: str,
    body: dict,
    tenant: TenantContext = Depends(require_feature("ent.intent_correlation")),
):
    """Log that a network-sourced playbook fired in this tenant."""
    from modules.product import threat_sharing_flywheel as fw  # noqa: PLC0415
    match_id = str(body.get("match_id") or "").strip() or None
    hit = fw.record_network_hit(
        tenant_id=tenant.tenant_id,
        network_playbook_id=network_playbook_id,
        match_id=match_id,
    )
    return {"recorded": hit is not None, "hit": hit}


@router.post("/api/threat-sharing/hits/{hit_id}/confirm")
async def api_flywheel_confirm_hit(
    hit_id: str,
    body: dict,
    tenant: TenantContext = Depends(require_feature("ent.intent_correlation")),
):
    """Operator confirms a network-playbook hit was a true positive."""
    from modules.product import threat_sharing_flywheel as fw  # noqa: PLC0415
    confirmed_by = str(body.get("confirmed_by") or "").strip()
    if not confirmed_by:
        raise HTTPException(status_code=400, detail="'confirmed_by' is required")
    ok = fw.confirm_hit(hit_id, confirmed_by)
    if not ok:
        raise HTTPException(
            status_code=404,
            detail={"error": "hit_not_found_or_already_confirmed"},
        )
    return {"confirmed": True, "hit_id": hit_id}


@router.get("/api/threat-sharing/network/scored")
async def api_flywheel_scored_catalog(
    limit: int = 100,
    min_confidence: float = 0.0,
    tenant: TenantContext = Depends(require_feature("ent.intent_correlation")),
):
    """Browse the network catalog with derived confidence scores attached.
    Sorted by confidence desc."""
    from modules.product import threat_sharing_flywheel as fw  # noqa: PLC0415
    items = fw.list_scored_catalog(limit=limit, min_confidence=min_confidence)
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(items),
        "playbooks": items,
    }


@router.get("/api/threat-sharing/network/{network_playbook_id}/score")
async def api_flywheel_playbook_score(
    network_playbook_id: str,
    tenant: TenantContext = Depends(require_feature("ent.intent_correlation")),
):
    from modules.product import threat_sharing_flywheel as fw  # noqa: PLC0415
    return fw.score_network_playbook(network_playbook_id).as_dict()


@router.post("/api/threat-sharing/industry")
async def api_flywheel_set_industry(
    body: dict,
    tenant: TenantContext = Depends(require_feature("ent.intent_correlation")),
):
    """Tag the tenant with an industry vertical for digest clustering."""
    from modules.product import threat_sharing_flywheel as fw  # noqa: PLC0415
    industry = str(body.get("industry") or "").strip()
    try:
        return fw.set_tenant_industry(tenant.tenant_id, industry)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": str(exc), "valid": sorted(fw.VALID_INDUSTRIES)},
        ) from exc


@router.get("/api/threat-sharing/industry/digest")
async def api_flywheel_industry_digest(
    days: int = 7,
    limit: int = 25,
    tenant: TenantContext = Depends(require_feature("ent.intent_correlation")),
):
    """Confirmed attacks against peers in the same industry vertical."""
    from modules.product import threat_sharing_flywheel as fw  # noqa: PLC0415
    return fw.get_industry_digest(tenant.tenant_id, days=days, limit=limit)


@router.post("/api/threat-sharing/subscription")
async def api_flywheel_set_subscription(
    body: dict,
    tenant: TenantContext = Depends(require_feature("ent.intent_correlation")),
):
    """Enable or disable auto-subscribe + tune the confidence threshold."""
    from modules.product import threat_sharing_flywheel as fw  # noqa: PLC0415
    enabled = bool(body.get("enabled"))
    min_conf = body.get("min_confidence")
    return fw.set_auto_subscribe(
        tenant.tenant_id,
        enabled=enabled,
        min_confidence=min_conf if min_conf is not None else None,
    )


@router.post("/api/threat-sharing/auto-sync")
async def api_flywheel_auto_sync(
    tenant: TenantContext = Depends(require_feature("ent.intent_correlation")),
):
    """Honour auto-subscribe — pull every network playbook above the
    tenant's confidence threshold. Falls through to plain sync if
    auto-subscribe is off."""
    from modules.product import threat_sharing_flywheel as fw  # noqa: PLC0415
    return fw.auto_sync_subscribed(tenant.tenant_id)


