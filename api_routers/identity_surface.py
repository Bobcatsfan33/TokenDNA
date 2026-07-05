"""identity-surface domain router (T-1 decomposition).

Handlers MOVED VERBATIM from api.py (decorator-only change). Route surface
unchanged (scripts/ci/openapi_route_guard.py). Imports copied from api.py
(ruff ignores unused F401) so every handler resolves.
"""
from __future__ import annotations

from fastapi import APIRouter

from api_routers._shared import _decode_cursor, _encode_cursor, sdk_attest_agent

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

router = APIRouter(prefix="", tags=["identity-surface"])


@router.post("/api/uis/normalize")
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


@router.get("/api/uis/spec")
async def api_uis_spec(
    _tenant: TenantContext = Depends(get_tenant),
):
    return {"uis_spec": get_uis_spec()}


@router.get("/api/oss/schema-bundle")
async def api_schema_bundle(
    _tenant: TenantContext = Depends(get_tenant),
):
    return {"bundle": schema_registry.build_schema_bundle()}


@router.get("/api/oss/schema-bundle/{artifact_name}")
async def api_schema_artifact(
    artifact_name: str,
    _tenant: TenantContext = Depends(get_tenant),
):
    artifact = schema_registry.get_schema_artifact(artifact_name)
    if artifact is None:
        raise HTTPException(status_code=404, detail="Schema artifact not found")
    return {"artifact": artifact}


@router.get("/api/uis/schema/artifacts")
async def api_uis_schema_artifacts(
    _tenant: TenantContext = Depends(get_tenant),
):
    return {"artifacts": schema_registry.build_schema_artifacts()}


@router.post("/api/oss/sdk/normalize")
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


@router.post("/api/oss/sdk/attest")
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


@router.post("/api/uis/adapters/normalize")
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


@router.get("/api/uis/events")
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


@router.get("/api/uis/events/{event_id}")
async def api_get_uis_event(
    event_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    row = uis_store.get_event(tenant_id=tenant.tenant_id, event_id=event_id)
    if row is None:
        raise HTTPException(status_code=404, detail="UIS event not found")
    return {"tenant_id": tenant.tenant_id, "event": row}


@router.get("/api/oss/onboarding")
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


@router.get("/api/graph/path/{from_label:path}")
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


@router.get("/api/graph/anomalies")
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


@router.get("/api/graph/stats")
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


@router.get("/api/graph/data")
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


@router.get("/api/intent/matches")
async def api_intent_matches(
    limit: int = 50,
    severity: str | None = None,
    playbook_id: str | None = None,
    tenant: TenantContext = Depends(require_feature("ent.intent_correlation")),
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


@router.get("/api/intent/playbooks")
async def api_intent_playbooks(
    include_builtin: bool = True,
    tenant: TenantContext = Depends(require_feature("ent.intent_correlation")),
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


@router.post("/api/intent/playbooks",
    dependencies=[Depends(require_feature("ent.intent_correlation"))],
)
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


@router.delete("/api/intent/playbooks/{playbook_id}",
    dependencies=[Depends(require_feature("ent.intent_correlation"))],
)
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


@router.post("/api/drift/record")
async def api_drift_record(
    body: dict,
    tenant: TenantContext = Depends(require_feature("ent.behavioral_dna")),
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


@router.get("/api/drift/alerts")
async def api_drift_alerts(
    status: Optional[str] = "open",
    agent_id: Optional[str] = None,
    limit: int = 50,
    tenant: TenantContext = Depends(require_feature("ent.behavioral_dna")),
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


@router.get("/api/drift/report/{agent_id}")
async def api_drift_report(
    agent_id: str,
    policy_id: str,
    days: int = 30,
    tenant: TenantContext = Depends(require_feature("ent.behavioral_dna")),
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


@router.post("/api/drift/approve/{drift_id}",
    dependencies=[Depends(require_feature("ent.behavioral_dna"))],
)
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


@router.get("/api/drift/summary")
async def api_drift_summary(
    tenant: TenantContext = Depends(require_feature("ent.behavioral_dna")),
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


@router.get("/api/drift/blast-comparison/{agent_id}")
async def api_drift_blast_comparison(
    agent_id: str,
    policy_id: str,
    baseline_days: int = 30,
    tenant: TenantContext = Depends(require_feature("ent.behavioral_dna")),
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


@router.post("/api/behavioral/event",
    dependencies=[Depends(require_feature("ent.behavioral_dna"))],
)
async def api_bd_record_event(
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    """Record a behavioural event for an agent."""
    behavioral_dna.init_db()
    agent_id = str(body.get("agent_id") or "")
    event_type = str(body.get("event_type") or "")
    if not agent_id or not event_type:
        raise HTTPException(status_code=422, detail="agent_id and event_type are required")
    return behavioral_dna.record_event(
        tenant.tenant_id, agent_id, event_type,
        tool_name=str(body.get("tool_name") or ""),
        resource=str(body.get("resource") or ""),
        action_type=str(body.get("action_type") or ""),
        params=body.get("params") or {},
    )


@router.get("/api/behavioral/baseline/{agent_id}",
    dependencies=[Depends(require_feature("ent.behavioral_dna"))],
)
async def api_bd_baseline(
    agent_id: str,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    behavioral_dna.init_db()
    return behavioral_dna.get_baseline(tenant.tenant_id, agent_id)


@router.get("/api/behavioral/drift/{agent_id}",
    dependencies=[Depends(require_feature("ent.behavioral_dna"))],
)
async def api_bd_drift(
    agent_id: str,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    behavioral_dna.init_db()
    return behavioral_dna.compute_drift_score(tenant.tenant_id, agent_id)


@router.get("/api/behavioral/alerts",
    dependencies=[Depends(require_feature("ent.behavioral_dna"))],
)
async def api_bd_alerts(
    agent_id: str | None = None,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    behavioral_dna.init_db()
    return {"alerts": behavioral_dna.list_drift_alerts(tenant.tenant_id, agent_id=agent_id)}


@router.post("/api/behavioral/alerts/{alert_id}/acknowledge",
    dependencies=[Depends(require_feature("ent.behavioral_dna"))],
)
async def api_bd_ack_alert(
    alert_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    behavioral_dna.init_db()
    acknowledged_by = str(body.get("acknowledged_by") or tenant.tenant_id)
    try:
        return behavioral_dna.acknowledge_drift_alert(tenant.tenant_id, alert_id, acknowledged_by)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/behavioral/snapshot/{agent_id}",
    dependencies=[Depends(require_feature("ent.behavioral_dna"))],
)
async def api_bd_snapshot(
    agent_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    behavioral_dna.init_db()
    return behavioral_dna.take_snapshot(
        tenant.tenant_id, agent_id,
        trigger=str(body.get("trigger") or "manual"),
    )


@router.get("/api/behavioral/audit/{agent_id}",
    dependencies=[Depends(require_feature("ent.behavioral_dna"))],
)
async def api_bd_audit(
    agent_id: str,
    limit: int = 200,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    behavioral_dna.init_db()
    return {"events": behavioral_dna.get_audit_trail(
        tenant.tenant_id, agent_id, limit=min(limit, 1000)
    )}


@router.post("/api/honeypot/decoy/synthetic-agent")
async def api_honeypot_synthesize_agent(
    body: dict,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """Mint a synthetic agent decoy. The returned secret_value is shown
    once — caller seeds it on bait surfaces and discards."""
    from modules.identity import honeypot_mesh as hp  # noqa: PLC0415
    out = hp.synthesize_decoy_agent(
        tenant_id=tenant.tenant_id,
        name_hint=body.get("name_hint"),
        metadata=body.get("metadata") if isinstance(body.get("metadata"), dict) else None,
    )
    return out.as_dict()


@router.post("/api/honeypot/decoy/honeytoken")
async def api_honeypot_seed_honeytoken(
    body: dict,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """Seed a credential / certificate honeytoken. Body: {kind?, metadata?}."""
    from modules.identity import honeypot_mesh as hp  # noqa: PLC0415
    kind = str(body.get("kind") or "honeytoken_credential")
    try:
        out = hp.seed_honeytoken(
            tenant_id=tenant.tenant_id,
            kind=kind,
            metadata=body.get("metadata") if isinstance(body.get("metadata"), dict) else None,
        )
        return out.as_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": str(exc)}) from exc


@router.get("/api/honeypot/decoys")
async def api_honeypot_list_decoys(
    kind: str | None = None,
    active_only: bool = True,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    from modules.identity import honeypot_mesh as hp  # noqa: PLC0415
    items = hp.get_decoy_inventory(tenant.tenant_id, kind=kind, active_only=active_only)
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(items),
        "decoys": items,
    }


@router.post("/api/honeypot/decoys/{decoy_id}/deactivate")
async def api_honeypot_deactivate(
    decoy_id: str,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    from modules.identity import honeypot_mesh as hp  # noqa: PLC0415
    if not hp.deactivate_decoy(decoy_id, tenant_id=tenant.tenant_id):
        raise HTTPException(status_code=404,
                            detail={"error": "decoy_not_found_or_already_inactive"})
    return {"decoy_id": decoy_id, "active": False}


@router.post("/api/honeypot/hits/record")
async def api_honeypot_record_hit(
    body: dict,
    request: Request,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    """
    Caller (typically the edge gateway) reports that a decoy was touched.
    Body: {decoy_id, source_ip?, user_agent?, request_path?, request_meta?}.
    Falls back to request.client.host when source_ip is not supplied.
    """
    from modules.identity import honeypot_mesh as hp  # noqa: PLC0415
    decoy_id = str(body.get("decoy_id") or "").strip()
    if not decoy_id:
        raise HTTPException(status_code=400, detail="'decoy_id' is required")
    source_ip = body.get("source_ip") or (request.client.host if request.client else None)
    out = hp.record_decoy_hit(
        decoy_id,
        source_ip=source_ip,
        user_agent=body.get("user_agent") or request.headers.get("user-agent"),
        request_path=body.get("request_path"),
        request_meta=body.get("request_meta") if isinstance(body.get("request_meta"), dict) else None,
        severity=str(body.get("severity") or "critical"),
        tenant_id=tenant.tenant_id,
    )
    if not out:
        raise HTTPException(status_code=404,
                            detail={"error": "decoy_not_found_or_cross_tenant"})
    return out


@router.get("/api/honeypot/hits")
async def api_honeypot_hits(
    decoy_id: str | None = None,
    acknowledged: bool = False,
    limit: int = 200,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    from modules.identity import honeypot_mesh as hp  # noqa: PLC0415
    items = hp.get_decoy_hits(
        tenant.tenant_id,
        decoy_id=decoy_id,
        acknowledged=acknowledged,
        limit=limit,
    )
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(items),
        "hits": items,
    }


@router.post("/api/honeypot/hits/{hit_id}/acknowledge")
async def api_honeypot_ack(
    hit_id: str,
    body: dict,
    tenant: TenantContext = Depends(require_feature("ent.enforcement_plane")),
):
    from modules.identity import honeypot_mesh as hp  # noqa: PLC0415
    ack_by = str(body.get("acknowledged_by") or "").strip()
    if not ack_by:
        raise HTTPException(status_code=400, detail="'acknowledged_by' is required")
    if not hp.acknowledge_hit(hit_id, ack_by, tenant_id=tenant.tenant_id):
        raise HTTPException(status_code=404,
                            detail={"error": "hit_not_found_or_already_acknowledged"})
    return {"acknowledged": True, "hit_id": hit_id}


