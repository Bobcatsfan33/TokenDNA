"""
TokenDNA -- lightweight SDK wrapper helpers for OSS integrations.
"""

from __future__ import annotations

from typing import Any

from modules.identity.attestation import create_attestation_record
from modules.identity.abac import evaluate_attestation_policy
from modules.identity.uis_protocol import get_uis_spec, normalize_with_adapter
from modules.integrations.idp_events import adapt_idp_event


class SDKAdapterError(ValueError):
    """Raised when SDK wrapper inputs are invalid."""


def _ensure_dict(value: Any, field: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise SDKAdapterError(f"'{field}' must be an object")
    return value


def sdk_get_uis_spec() -> dict[str, Any]:
    return get_uis_spec()


def sdk_normalize_event(
    *,
    protocol: str,
    tenant_id: str,
    tenant_name: str,
    payload: dict[str, Any],
    request_context: dict[str, Any] | None = None,
    risk_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return sdk_normalize_uis_event(
        protocol=protocol,
        tenant_id=tenant_id,
        tenant_name=tenant_name,
        payload=payload,
        request_context=request_context,
        risk_context=risk_context,
    )


def build_adapter_normalize_request(
    *,
    protocol: str,
    payload: dict[str, Any],
    request_context: dict[str, Any] | None = None,
    risk_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise SDKAdapterError("'payload' must be an object")
    return {
        "protocol": str(protocol or "custom"),
        "payload": payload,
        "request_context": _ensure_dict(request_context, "request_context"),
        "risk_context": _ensure_dict(risk_context, "risk_context"),
    }


def build_attestation_request(
    *,
    agent_id: str,
    owner_org: str,
    created_by: str,
    soul_hash: str,
    directive_hashes: list[str] | None = None,
    model_fingerprint: str = "",
    mcp_manifest_hash: str = "",
) -> dict[str, Any]:
    return {
        "agent_id": str(agent_id),
        "owner_org": str(owner_org),
        "created_by": str(created_by),
        "soul_hash": str(soul_hash),
        "directive_hashes": [str(v) for v in (directive_hashes or [])],
        "model_fingerprint": str(model_fingerprint),
        "mcp_manifest_hash": str(mcp_manifest_hash),
    }


def sdk_normalize_uis_event(
    *,
    protocol: str,
    tenant_id: str,
    tenant_name: str,
    payload: dict[str, Any],
    request_context: dict[str, Any] | None = None,
    risk_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    req = build_adapter_normalize_request(
        protocol=protocol,
        payload=payload,
        request_context=request_context,
        risk_context=risk_context,
    )
    return normalize_with_adapter(
        protocol=req["protocol"],
        tenant_id=tenant_id,
        tenant_name=tenant_name,
        payload=req["payload"],
        request_context=req["request_context"],
        risk_context=req["risk_context"],
    )


def sdk_normalize_idp_event(*, provider: str, event: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise SDKAdapterError("'event' must be an object")
    return adapt_idp_event(provider, event)


def sdk_create_attestation(
    *,
    agent_id: str,
    owner_org: str,
    created_by: str,
    soul_hash: str,
    directive_hashes: list[str] | None = None,
    model_fingerprint: str = "",
    mcp_manifest_hash: str = "",
    auth_method: str = "token",
    dpop_bound: bool = False,
    mtls_bound: bool = False,
    behavior_confidence: float = 1.0,
    declared_purpose: str = "runtime_access",
    scope: list[str] | None = None,
    delegation_chain: list[str] | None = None,
    policy_trace_id: str | None = None,
    runtime_context: dict[str, Any] | None = None,
    behavior_features: dict[str, Any] | None = None,
) -> dict[str, Any]:
    base = build_attestation_request(
        agent_id=agent_id,
        owner_org=owner_org,
        created_by=created_by,
        soul_hash=soul_hash,
        directive_hashes=directive_hashes,
        model_fingerprint=model_fingerprint,
        mcp_manifest_hash=mcp_manifest_hash,
    )
    record = create_attestation_record(
        agent_id=base["agent_id"],
        owner_org=base["owner_org"],
        created_by=base["created_by"],
        soul_hash=base["soul_hash"],
        directive_hashes=base["directive_hashes"],
        model_fingerprint=base["model_fingerprint"],
        mcp_manifest_hash=base["mcp_manifest_hash"],
        auth_method=auth_method,
        dpop_bound=dpop_bound,
        mtls_bound=mtls_bound,
        behavior_confidence=behavior_confidence,
        declared_purpose=declared_purpose,
        scope=scope or [],
        delegation_chain=delegation_chain or [],
        policy_trace_id=policy_trace_id,
        runtime_context=runtime_context or {},
        behavior_features=behavior_features or {},
    )
    return record.to_dict()


def sdk_abac_evaluate(
    *,
    uis_event: dict[str, Any],
    attestation: dict[str, Any] | None,
    drift: dict[str, Any] | None,
    certificate_verified: bool | None,
    required_scope: list[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(uis_event, dict):
        raise SDKAdapterError("'uis_event' must be an object")
    if attestation is not None and not isinstance(attestation, dict):
        raise SDKAdapterError("'attestation' must be an object when provided")
    if drift is not None and not isinstance(drift, dict):
        raise SDKAdapterError("'drift' must be an object when provided")
    if certificate_verified is not None and not isinstance(certificate_verified, bool):
        raise SDKAdapterError("'certificate_verified' must be a boolean when provided")

    decision = evaluate_attestation_policy(
        uis_event=uis_event,
        attestation=attestation,
        drift=drift,
        certificate_verified=certificate_verified,
        required_scope=[str(v) for v in (required_scope or [])],
    )
    return decision.to_dict()

