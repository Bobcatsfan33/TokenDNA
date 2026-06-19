"""enterprise domain router (T-1 decomposition).

Handlers MOVED VERBATIM from api.py (decorator-only change). Route surface
unchanged (scripts/ci/openapi_route_guard.py). Imports copied from api.py
(ruff ignores unused F401) so every handler resolves.
"""
from __future__ import annotations

from fastapi import APIRouter

from api_routers._shared import (
    _DASHBOARD_PATH, _scim_handle, _scim_response, _tenant_subject, serve_dashboard_html,
    check_rate_limit, check_rate_limit_open,
)

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

router = APIRouter(prefix="", tags=["enterprise"])


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    if not _DASHBOARD_PATH.exists():
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return serve_dashboard_html(_DASHBOARD_PATH)


@router.get("/saml/metadata", response_class=Response)
async def saml_metadata():
    from modules.auth.saml import generate_metadata
    return Response(content=generate_metadata(), media_type="application/xml")


@router.get("/saml/login")
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


@router.post("/saml/acs")
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


@router.get("/scim/v2/ServiceProviderConfig")
async def scim_spc():
    from modules.auth.scim import service_provider_config
    return _scim_response(service_provider_config())


@router.get("/scim/v2/ResourceTypes")
async def scim_resource_types():
    from modules.auth.scim import resource_types
    return _scim_response(resource_types())


@router.post("/scim/v2/Users")
@_scim_handle
async def scim_create_user(request: Request, tenant: TenantContext = Depends(get_tenant)):
    from modules.auth.scim import create_user
    payload = await request.json()
    body = create_user(payload, tenant_id=tenant.tenant_id)
    return _scim_response(body, status=201)


@router.get("/scim/v2/Users/{user_id}")
@_scim_handle
async def scim_get_user(user_id: str, tenant: TenantContext = Depends(get_tenant)):
    from modules.auth.scim import get_user
    return _scim_response(get_user(user_id, tenant_id=tenant.tenant_id))


@router.put("/scim/v2/Users/{user_id}")
@_scim_handle
async def scim_replace_user(user_id: str, request: Request, tenant: TenantContext = Depends(get_tenant)):
    from modules.auth.scim import replace_user
    payload = await request.json()
    return _scim_response(replace_user(user_id, payload, tenant_id=tenant.tenant_id))


@router.patch("/scim/v2/Users/{user_id}")
@_scim_handle
async def scim_patch_user(user_id: str, request: Request, tenant: TenantContext = Depends(get_tenant)):
    from modules.auth.scim import patch_user
    payload = await request.json()
    return _scim_response(patch_user(user_id, payload, tenant_id=tenant.tenant_id))


@router.delete("/scim/v2/Users/{user_id}")
@_scim_handle
async def scim_delete_user(user_id: str, tenant: TenantContext = Depends(get_tenant)):
    from modules.auth.scim import delete_user
    delete_user(user_id, tenant_id=tenant.tenant_id)
    return Response(status_code=204)


@router.get("/scim/v2/Users")
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


@router.post("/scim/v2/Groups")
@_scim_handle
async def scim_create_group(request: Request, tenant: TenantContext = Depends(get_tenant)):
    from modules.auth.scim import create_group
    payload = await request.json()
    return _scim_response(create_group(payload, tenant_id=tenant.tenant_id), status=201)


@router.get("/scim/v2/Groups/{group_id}")
@_scim_handle
async def scim_get_group(group_id: str, tenant: TenantContext = Depends(get_tenant)):
    from modules.auth.scim import get_group
    return _scim_response(get_group(group_id, tenant_id=tenant.tenant_id))


@router.get("/scim/v2/Groups")
@_scim_handle
async def scim_list_groups(
    filter: str | None = None,
    tenant: TenantContext = Depends(get_tenant),
):
    from modules.auth.scim import list_groups
    return _scim_response(list_groups(tenant_id=tenant.tenant_id, filter_expr=filter))


@router.patch("/scim/v2/Groups/{group_id}")
@_scim_handle
async def scim_patch_group(group_id: str, request: Request, tenant: TenantContext = Depends(get_tenant)):
    from modules.auth.scim import patch_group
    payload = await request.json()
    return _scim_response(patch_group(group_id, payload, tenant_id=tenant.tenant_id))


@router.delete("/scim/v2/Groups/{group_id}")
@_scim_handle
async def scim_delete_group(group_id: str, tenant: TenantContext = Depends(get_tenant)):
    from modules.auth.scim import delete_group
    delete_group(group_id, tenant_id=tenant.tenant_id)
    return Response(status_code=204)


@router.get("/secure")
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


@router.get("/profile/{user_id}")
async def get_profile(
    user_id: str,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    tr      = TenantRedis(get_redis(), tenant.tenant_id)
    profile = ml_model.get_profile(user_id, redis=tr)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    return {"user_id": user_id, "tenant_id": tenant.tenant_id, "profile": profile}


@router.delete("/profile/{user_id}")
async def reset_profile(
    user_id: str,
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    tr = TenantRedis(get_redis(), tenant.tenant_id)
    ml_model.reset_profile(user_id, redis=tr)
    return {"status": "reset", "user_id": user_id}


@router.post("/revoke")
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


@router.get("/admin/tenants")
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


@router.post("/admin/tenants", status_code=201)
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


@router.get("/admin/tenants/{tenant_id}/keys")
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


@router.post("/admin/tenants/{tenant_id}/keys", status_code=201)
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


@router.delete("/admin/tenants/{tenant_id}/keys/{key_id}")
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


@router.post("/onboarding/aws/external-id")
async def aws_external_id(_tenant: TenantContext = Depends(require_role(Role.ADMIN))):
    from onboarding.aws_connector import generate_external_id
    return {"external_id": generate_external_id()}


@router.post("/onboarding/aws/test")
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


