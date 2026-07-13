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


