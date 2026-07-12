"""agents domain router (T-1 decomposition).

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

router = APIRouter(prefix="", tags=["agents"])


@router.post("/api/agent/attest")
async def api_agent_attest(
    body: dict,
    tenant: TenantContext = Depends(get_tenant),
):
    agent_id = str(body.get("agent_id", "")).strip()
    if not agent_id:
        raise HTTPException(status_code=400, detail="'agent_id' is required")

    record = create_attestation_record(
        agent_id=agent_id,
        owner_org=str(body.get("owner_org") or tenant.tenant_name),
        created_by=str(body.get("created_by") or "unknown"),
        soul_hash=str(body.get("soul_hash") or ""),
        directive_hashes=list(body.get("directive_hashes") or []),
        model_fingerprint=str(body.get("model_fingerprint") or ""),
        mcp_manifest_hash=str(body.get("mcp_manifest_hash") or ""),
        auth_method=str(body.get("auth_method") or "token"),
        dpop_bound=bool(body.get("dpop_bound", False)),
        mtls_bound=bool(body.get("mtls_bound", False)),
        behavior_confidence=float(body.get("behavior_confidence", 0.0)),
        declared_purpose=str(body.get("declared_purpose") or "unspecified"),
        scope=list(body.get("scope") or []),
        delegation_chain=list(body.get("delegation_chain") or []),
        policy_trace_id=body.get("policy_trace_id"),
        runtime_context=dict(body.get("runtime_context") or {}),
        behavior_features=dict(body.get("behavior_features") or {}),
    )
    attestation_payload = record.to_dict()
    attestation_store.insert_attestation(tenant_id=tenant.tenant_id, record=attestation_payload)

    issue_cert = bool(body.get("issue_certificate", False))
    if issue_cert:
        cert = issue_certificate(
            tenant_id=tenant.tenant_id,
            attestation_id=attestation_payload["attestation_id"],
            subject=agent_id,
            issuer=str(body.get("issuer") or "TokenDNA Trust Authority"),
            claims={
                "integrity_digest": attestation_payload["integrity_digest"],
                "agent_dna_fingerprint": attestation_payload["agent_dna_fingerprint"],
                "who": attestation_payload["who"],
                "what": attestation_payload["what"],
                "how": attestation_payload["how"],
                "why": attestation_payload["why"],
            },
            ttl_hours=int(body.get("certificate_ttl_hours", 24)),
        )
        attestation_store.insert_certificate(tenant_id=tenant.tenant_id, certificate=cert)
        return {"tenant_id": tenant.tenant_id, "attestation": attestation_payload, "certificate": cert}

    return {"tenant_id": tenant.tenant_id, "attestation": attestation_payload}


@router.get("/api/agent/attestations")
async def api_list_agent_attestations(
    page_size: int = 50,
    agent_id: str | None = None,
    cursor: str | None = None,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    page = attestation_store.list_attestations_paginated(
        tenant_id=tenant.tenant_id,
        page_size=min(max(page_size, 1), 200),
        cursor=cursor,
        agent_id=agent_id,
    )
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(page["items"]),
        "attestations": page["items"],
        "next_cursor": page["next_cursor"],
        "has_more": page["has_more"],
        "page_size": page["page_size"],
    }


@router.get("/api/agent/attestations/{attestation_id}")
async def api_get_agent_attestation(
    attestation_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    row = attestation_store.get_attestation(tenant_id=tenant.tenant_id, attestation_id=attestation_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Attestation not found")
    return {"tenant_id": tenant.tenant_id, "attestation": row}


@router.get("/api/agent/dna/{agent_id}")
async def api_get_agent_dna(
    agent_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    """Return the stored behavioral DNA for *agent_id*.

    Response fields:
    - ``dna``: the DNA dict, or null if not yet computed
    - ``fresh``: True if ``computed_at`` is within the last hour
    """
    from modules.identity import agent_dna as _agent_dna  # noqa: PLC0415
    from modules.identity.uis_store import init_db as _uis_init  # noqa: PLC0415
    _uis_init()
    _agent_dna.build_agent_dna_store()

    dna = _agent_dna.get_agent_dna(tenant_id=tenant.tenant_id, agent_id=agent_id)
    fresh = False
    if dna:
        try:
            computed_at = datetime.datetime.fromisoformat(dna["computed_at"])
            age = datetime.datetime.now(datetime.timezone.utc) - computed_at
            fresh = age.total_seconds() < 3600
        except Exception:  # noqa: BLE001
            pass
    return {"tenant_id": tenant.tenant_id, "agent_id": agent_id, "dna": dna, "fresh": fresh}


@router.post("/api/agent/dna/{agent_id}/refresh")
async def api_refresh_agent_dna(
    agent_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    """Synchronously recompute behavioral DNA for *agent_id* and return it."""
    from modules.identity import agent_dna as _agent_dna  # noqa: PLC0415
    from modules.identity.uis_store import init_db as _uis_init  # noqa: PLC0415
    _uis_init()
    _agent_dna.build_agent_dna_store()

    dna = _agent_dna.refresh_agent_dna(tenant_id=tenant.tenant_id, agent_id=agent_id)
    return {"tenant_id": tenant.tenant_id, "agent_id": agent_id, "dna": dna}


@router.post("/api/agent/certificates/verify")
async def api_verify_agent_certificate(
    body: dict,
    tenant: TenantContext = Depends(get_tenant),
):
    certificate = body.get("certificate")
    if not isinstance(certificate, dict):
        raise HTTPException(status_code=400, detail="'certificate' must be an object")
    if str(certificate.get("tenant_id", "")) != tenant.tenant_id:
        raise HTTPException(status_code=403, detail="Certificate tenant mismatch")

    result = verify_certificate(certificate)
    if result.get("valid"):
        stored = attestation_store.get_certificate(tenant_id=tenant.tenant_id, certificate_id=certificate["certificate_id"])
        if stored is None:
            attestation_store.insert_certificate(tenant_id=tenant.tenant_id, certificate=certificate)
    return {"tenant_id": tenant.tenant_id, "verification": result}


@router.post("/api/agent/certificates/issue")
async def api_issue_agent_certificate(
    body: dict,
    tenant: TenantContext = Depends(get_tenant),
):
    attestation_id = str(body.get("attestation_id", "")).strip()
    if not attestation_id:
        raise HTTPException(status_code=400, detail="'attestation_id' is required")

    record = attestation_store.get_attestation(tenant_id=tenant.tenant_id, attestation_id=attestation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Attestation not found")

    subject = str(body.get("subject") or record.get("who", {}).get("agent_id") or "unknown-agent")
    cert = issue_certificate(
        tenant_id=tenant.tenant_id,
        attestation_id=attestation_id,
        subject=subject,
        issuer=str(body.get("issuer") or "TokenDNA Trust Authority"),
        claims={
            "integrity_digest": record.get("integrity_digest"),
            "agent_dna_fingerprint": record.get("agent_dna_fingerprint"),
            "who": record.get("who", {}),
            "what": record.get("what", {}),
            "how": record.get("how", {}),
            "why": record.get("why", {}),
        },
        ttl_hours=int(body.get("certificate_ttl_hours", 24)),
    )
    attestation_store.insert_certificate(tenant_id=tenant.tenant_id, certificate=cert)
    ct_entry = ct_log.append_log_entry(
        tenant_id=tenant.tenant_id,
        certificate_id=cert["certificate_id"],
        attestation_id=attestation_id,
        action="issued",
        payload=cert,
    )
    return {"tenant_id": tenant.tenant_id, "certificate": cert, "transparency_log_entry": ct_entry}


@router.get("/api/agent/certificates/{certificate_id}")
async def api_get_agent_certificate(
    certificate_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    cert = attestation_store.get_certificate(tenant_id=tenant.tenant_id, certificate_id=certificate_id)
    if cert is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return {"tenant_id": tenant.tenant_id, "certificate": cert}


@router.get("/api/agent/certificates")
async def api_list_agent_certificates(
    limit: int = 50,
    subject: str | None = None,
    status: str | None = None,
    cursor: str | None = None,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    page = attestation_store.list_certificates_paginated(
        tenant_id=tenant.tenant_id,
        page_size=min(max(limit, 1), 200),
        cursor=cursor,
        subject=subject,
        status=status,
    )
    rows = page["items"]
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(rows),
        "certificates": rows,
        "next_cursor": page["next_cursor"],
        "has_more": page["has_more"],
        "page_size": page["page_size"],
    }


@router.get("/api/agent/certificates/status/{certificate_id}")
async def api_certificate_status(
    certificate_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    cert = attestation_store.get_certificate(tenant_id=tenant.tenant_id, certificate_id=certificate_id)
    verification = verify_certificate(cert) if cert is not None else None
    status = certificate_status_payload(certificate=cert, verification=verification)
    return {"tenant_id": tenant.tenant_id, "status": status}


@router.get("/api/agent/certificates/crl")
async def api_certificate_crl(
    limit: int = 1000,
    tenant: TenantContext = Depends(get_tenant),
):
    revoked = attestation_store.list_certificates(
        tenant_id=tenant.tenant_id,
        status="revoked",
        limit=min(max(limit, 1), 5000),
    )
    return {"crl": build_crl(tenant_id=tenant.tenant_id, revoked_certificates=revoked)}


@router.post("/api/agent/certificates/revoke")
async def api_revoke_agent_certificate(
    body: dict,
    tenant: TenantContext = Depends(get_tenant),
):
    certificate_id = str(body.get("certificate_id", "")).strip()
    if not certificate_id:
        raise HTTPException(status_code=400, detail="'certificate_id' is required")
    existing = attestation_store.get_certificate(tenant_id=tenant.tenant_id, certificate_id=certificate_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Certificate not found")

    revoked = revoke_certificate(existing, reason=str(body.get("reason") or "manual_revoke"))
    attestation_store.insert_certificate(tenant_id=tenant.tenant_id, certificate=revoked)
    ct_entry = ct_log.append_log_entry(
        tenant_id=tenant.tenant_id,
        certificate_id=certificate_id,
        attestation_id=str(revoked.get("attestation_id", "")),
        action="revoked",
        payload={
            "reason": revoked.get("revocation_reason"),
            "status": revoked.get("status"),
            "revoked_at": revoked.get("revoked_at"),
        },
    )
    log_event(
        AuditEventType.CONFIG_CHANGED,
        AuditOutcome.SUCCESS,
        tenant_id=tenant.tenant_id,
        subject=tenant.tenant_name,
        resource=f"certificate:{certificate_id}",
        detail={"action": "revoke_certificate", "reason": revoked.get("revocation_reason")},
    )
    return {"tenant_id": tenant.tenant_id, "certificate": revoked, "transparency_log_entry": ct_entry}


@router.get("/api/agent/ca-keys")
async def api_list_ca_keys(
    status: str | None = None,
    limit: int = 50,
    _tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    if status:
        rows = attestation_store.list_ca_keys(status=status, limit=min(max(limit, 1), 200))
    else:
        rows = attestation_store.list_ca_keys(limit=min(max(limit, 1), 200))
    return {"count": len(rows), "keys": rows}


@router.post("/api/agent/ca-keys")
async def api_upsert_ca_key(
    body: dict,
    _tenant: TenantContext = Depends(require_role(Role.OWNER)),
):
    key_id = str(body.get("key_id", "")).strip()
    algorithm = str(body.get("algorithm", "")).strip().upper()
    backend = str(body.get("backend", "")).strip().lower()
    if not key_id:
        raise HTTPException(status_code=400, detail="'key_id' is required")
    if algorithm not in {"HS256", "RS256"}:
        raise HTTPException(status_code=400, detail="'algorithm' must be HS256 or RS256")
    if backend not in {"software", "hsm", "aws_kms"}:
        raise HTTPException(status_code=400, detail="'backend' must be software, hsm, or aws_kms")

    attestation_store.upsert_ca_key(
        key_id=key_id,
        algorithm=algorithm,
        backend=backend,
        kms_key_id=(str(body.get("kms_key_id", "")).strip() or None),
        public_key_pem=(str(body.get("public_key_pem", "")).strip() or None),
        status=str(body.get("status", "active")),
        activated_at=(str(body.get("activated_at", "")).strip() or None),
        deactivated_at=(str(body.get("deactivated_at", "")).strip() or None),
        metadata=(body.get("metadata") if isinstance(body.get("metadata"), dict) else {}),
    )
    key = attestation_store.get_ca_key(key_id)
    return {"key": key}


@router.get("/api/agent/ca-keyring")
async def api_ca_keyring_preview(
    _tenant: TenantContext = Depends(require_role(Role.ADMIN)),
):
    return {"configured_keyring": list_key_configs()}


@router.get("/api/agent/certificates/transparency-log")
async def api_certificate_transparency_log(
    limit: int = 50,
    cursor: str | None = None,
    tenant: TenantContext = Depends(get_tenant),
):
    """Cursor-paginated transparency log.  ?limit=N (default 50, max 200)
    + ?cursor=<opaque>; response includes ``next_cursor`` (null when
    exhausted)."""
    from modules.storage.pagination import paginate_offset  # noqa: PLC0415
    page = paginate_offset(
        lambda offset, lim: ct_log.list_log_entries(
            tenant_id=tenant.tenant_id, limit=lim, offset=offset,
        ),
        cursor=cursor,
        limit=limit,
    )
    return page.as_response("entries", extra={"tenant_id": tenant.tenant_id})


@router.get("/api/agent/certificates/transparency-log/verify")
async def api_verify_certificate_transparency_log(
    tenant: TenantContext = Depends(get_tenant),
):
    result = ct_log.verify_log_integrity(tenant_id=tenant.tenant_id)
    return {"tenant_id": tenant.tenant_id, "integrity": result}


@router.post("/api/agent/drift/assess")
async def api_assess_agent_drift(
    body: dict,
    tenant: TenantContext = Depends(require_feature("ent.behavioral_dna")),
):
    agent_id = str(body.get("agent_id", "")).strip()
    if not agent_id:
        raise HTTPException(status_code=400, detail="'agent_id' is required")

    attestation = None
    attestation_id = str(body.get("attestation_id", "")).strip()
    if attestation_id:
        attestation = attestation_store.get_attestation(tenant_id=tenant.tenant_id, attestation_id=attestation_id)
    else:
        attestation = attestation_store.get_latest_attestation_for_agent(tenant_id=tenant.tenant_id, agent_id=agent_id)

    if attestation is None:
        raise HTTPException(status_code=404, detail="Attestation baseline not found")

    headers = body.get("request_headers") or {}
    if not isinstance(headers, dict):
        raise HTTPException(status_code=400, detail="'request_headers' must be an object")

    observed_scope = body.get("observed_scope") or []
    if not isinstance(observed_scope, list):
        raise HTTPException(status_code=400, detail="'observed_scope' must be an array")

    assessment = assess_runtime_drift(
        attestation=attestation,
        request_headers={str(k).lower(): str(v) for k, v in headers.items()},
        observed_scope=[str(v) for v in observed_scope],
    )
    request_id = str(body.get("request_id") or str(uuid.uuid4()))
    drift_event = build_drift_event(
        tenant_id=tenant.tenant_id,
        agent_id=agent_id,
        attestation_id=attestation.get("attestation_id"),
        certificate_id=body.get("certificate_id"),
        assessment=assessment,
        request_id=request_id,
    )
    attestation_store.insert_drift_event(tenant_id=tenant.tenant_id, event=drift_event)
    return {"tenant_id": tenant.tenant_id, "drift": assessment.to_dict(), "drift_event": drift_event}


@router.get("/api/agent/drift/events",
    dependencies=[Depends(require_feature("ent.behavioral_dna"))],
)
async def api_list_agent_drift_events(
    limit: int = 100,
    agent_id: str | None = None,
    cursor: str | None = None,
    tenant: TenantContext = Depends(require_role(Role.ANALYST)),
):
    page = attestation_store.list_drift_events_paginated(
        tenant_id=tenant.tenant_id,
        page_size=min(max(limit, 1), 500),
        cursor=cursor,
        agent_id=agent_id,
    )
    return {
        "tenant_id": tenant.tenant_id,
        "count": len(page["items"]),
        "events": page["items"],
        "next_cursor": page["next_cursor"],
        "has_more": page["has_more"],
    }


@router.post("/api/agents/register")
async def api_register_agent(
    body: dict = Body(...),
    tenant: TenantContext = Depends(get_tenant),
):
    """Register a new agent in the lifecycle inventory."""
    agent_lifecycle.init_db()
    agent_id = str(body.get("agent_id", "")).strip() or None
    display_name = str(body.get("display_name", "")).strip()
    if not display_name:
        raise HTTPException(status_code=400, detail="'display_name' is required")
    try:
        agent = agent_lifecycle.register_agent(
            tenant_id=tenant.tenant_id,
            agent_id=agent_id,
            display_name=display_name,
            platform=str(body.get("platform", "unknown")),
            owner=body.get("owner"),
            credential_ids=list(body.get("credential_ids", [])),
            last_token_id=body.get("last_token_id"),
            metadata=body.get("metadata", {}),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return agent


@router.post("/api/agents/decommission/{agent_id}")
async def api_decommission_agent(
    agent_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(get_tenant),
):
    """
    Decommission an agent (terminal).  Automatically revokes credentials and
    converts the agent's token to a deception-mesh honeypot.
    """
    agent_lifecycle.init_db()
    try:
        result = agent_lifecycle.decommission_agent(
            tenant_id=tenant.tenant_id,
            agent_id=agent_id,
            actor=body.get("actor"),
            reason=body.get("reason"),
            revoke_credentials=bool(body.get("revoke_credentials", True)),
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result


@router.post("/api/agents/suspend/{agent_id}")
async def api_suspend_agent(
    agent_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(get_tenant),
):
    """Suspend an active agent (reversible)."""
    agent_lifecycle.init_db()
    try:
        return agent_lifecycle.suspend_agent(
            tenant_id=tenant.tenant_id,
            agent_id=agent_id,
            actor=body.get("actor"),
            reason=body.get("reason"),
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/agents/reactivate/{agent_id}")
async def api_reactivate_agent(
    agent_id: str,
    body: dict = Body(default={}),
    tenant: TenantContext = Depends(get_tenant),
):
    """Reactivate a suspended agent."""
    agent_lifecycle.init_db()
    try:
        return agent_lifecycle.reactivate_agent(
            tenant_id=tenant.tenant_id,
            agent_id=agent_id,
            actor=body.get("actor"),
            reason=body.get("reason"),
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/agents/heartbeat/{agent_id}")
async def api_agent_heartbeat(
    agent_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    """Record agent activity (updates last_seen_at)."""
    agent_lifecycle.init_db()
    try:
        return agent_lifecycle.record_heartbeat(
            tenant_id=tenant.tenant_id,
            agent_id=agent_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/agents/inventory")
async def api_agent_inventory(
    status: str | None = None,
    limit: int = 200,
    tenant: TenantContext = Depends(get_tenant),
):
    """Return full agent inventory for the tenant."""
    agent_lifecycle.init_db()
    try:
        return {"agents": agent_lifecycle.list_inventory(
            tenant_id=tenant.tenant_id,
            status=status,
            limit=limit,
        )}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/agents/orphans")
async def api_agent_orphans(
    orphan_days: int = 30,
    limit: int = 200,
    tenant: TenantContext = Depends(get_tenant),
):
    """Return agents with no activity in >orphan_days days."""
    agent_lifecycle.init_db()
    orphans = agent_lifecycle.list_orphans(
        tenant_id=tenant.tenant_id,
        orphan_days=max(orphan_days, 1),
        limit=limit,
    )
    return {"orphans": orphans, "count": len(orphans), "orphan_threshold_days": orphan_days}


@router.get("/api/agents/{agent_id}/events")
async def api_agent_events(
    agent_id: str,
    limit: int = 100,
    tenant: TenantContext = Depends(get_tenant),
):
    """Return lifecycle event log for a specific agent."""
    agent_lifecycle.init_db()
    try:
        events = agent_lifecycle.get_lifecycle_events(
            tenant_id=tenant.tenant_id,
            agent_id=agent_id,
            limit=limit,
        )
        return {"agent_id": agent_id, "events": events}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/api/agents/{agent_id}")
async def api_get_agent(
    agent_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    """Return a single agent record."""
    agent_lifecycle.init_db()
    try:
        return agent_lifecycle.get_agent(
            tenant_id=tenant.tenant_id,
            agent_id=agent_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


