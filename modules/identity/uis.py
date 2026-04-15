"""
TokenDNA -- Universal Identity Schema (UIS) normalization.

UIS provides a protocol-agnostic event format with eight field sets:
  - identity.*
  - auth.*
  - token.*
  - session.*
  - behavior.*
  - lifecycle.*
  - threat.*
  - binding.*

This module is intentionally lightweight and open-core friendly: adapters accept
raw protocol artifacts and normalize them into a common event shape that the
rest of the pipeline can consume.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


UIS_VERSION = "1.0"        # wire format version — unchanged for v1 events
UIS_NARRATIVE_VERSION = "1.1"  # version emitted when narrative block is attached via attach_narrative()
SUPPORTED_PROTOCOLS = {"oidc", "saml", "oauth2_opaque", "spiffe", "custom"}


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_hash(data: Any) -> str:
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass
class UISNormalizerInput:
    protocol: str
    tenant_id: str
    tenant_name: str
    subject: str
    claims: dict[str, Any]
    request_context: dict[str, Any]
    risk_context: dict[str, Any]


def normalize_identity_event(data: UISNormalizerInput) -> dict[str, Any]:
    protocol = (data.protocol or "custom").lower()
    if protocol not in SUPPORTED_PROTOCOLS:
        protocol = "custom"

    claims = data.claims or {}
    context = data.request_context or {}
    risk = data.risk_context or {}

    issued_at = claims.get("iat")
    expires_at = claims.get("exp")

    identity = {
        "entity_type": claims.get("entity_type", "machine" if claims.get("agent_id") else "human"),
        "subject": data.subject,
        "tenant_id": data.tenant_id,
        "tenant_name": data.tenant_name,
        "display_name": claims.get("name") or claims.get("preferred_username") or data.subject,
        "machine_classification": claims.get("machine_classification", "agent" if claims.get("agent_id") else "user"),
        "agent_id": claims.get("agent_id"),
    }

    auth = {
        "method": claims.get("amr", ["password"])[0] if isinstance(claims.get("amr"), list) and claims.get("amr") else claims.get("auth_method", "unknown"),
        "mfa_asserted": bool(claims.get("mfa") or (isinstance(claims.get("amr"), list) and any(m in claims["amr"] for m in ("mfa", "otp", "hwk", "swk", "fpt")))),
        "protocol": protocol,
        "credential_strength": claims.get("acr", "standard"),
    }

    token_claims_for_hash = {
        "iss": claims.get("iss"),
        "aud": claims.get("aud"),
        "sub": data.subject,
        "scope": claims.get("scope"),
        "roles": claims.get("roles"),
        "permissions": claims.get("permissions"),
    }
    token = {
        "type": claims.get("token_type", "bearer"),
        "issuer": claims.get("iss", "unknown"),
        "audience": claims.get("aud"),
        "claims_hash": _stable_hash(token_claims_for_hash),
        "dpop_bound": bool(claims.get("dpop_jkt") or claims.get("dpop_bound")),
        "expires_at": expires_at,
        "issued_at": issued_at,
        "rotation_history": claims.get("rotation_history", []),
        "jti": claims.get("jti"),
    }

    session = {
        "id": context.get("session_id"),
        "request_id": context.get("request_id"),
        "ip": context.get("ip"),
        "country": context.get("country"),
        "asn": context.get("asn"),
        "device_fingerprint": context.get("device_fingerprint"),
        "user_agent": context.get("user_agent"),
        "impossible_travel": bool(risk.get("impossible_travel", False)),
        "graph_position": context.get("graph_position"),
    }

    behavior = {
        "dna_fingerprint": context.get("dna_fingerprint"),
        "pattern_deviation_score": float(risk.get("pattern_deviation_score", 0.0)),
        "velocity_anomaly": bool(risk.get("velocity_anomaly", False)),
    }

    lifecycle = {
        "state": claims.get("lifecycle_state", "active"),
        "provisioned_at": claims.get("provisioned_at"),
        "revoked_at": claims.get("revoked_at"),
        "dormant": bool(claims.get("dormant", False)),
    }

    threat = {
        "risk_score": int(risk.get("risk_score", 0)),
        "risk_tier": risk.get("risk_tier", "unknown"),
        "indicators": risk.get("indicators", []),
        "lateral_movement": bool(risk.get("lateral_movement", False)),
    }

    binding = {
        "dpop_jkt": claims.get("dpop_jkt"),
        "mtls_subject": claims.get("mtls_subject"),
        "spiffe_id": claims.get("spiffe_id"),
        "attestation_id": claims.get("attestation_id"),
        "supply_chain_hash": claims.get("supply_chain_hash"),
    }

    return {
        "uis_version": UIS_VERSION,
        "event_id": context.get("event_id") or _stable_hash([data.tenant_id, data.subject, time.time_ns()])[:32],
        "event_timestamp": _iso_now(),
        "identity": identity,
        "auth": auth,
        "token": token,
        "session": session,
        "behavior": behavior,
        "lifecycle": lifecycle,
        "threat": threat,
        "binding": binding,
    }


def normalize_from_protocol(
    protocol: str,
    tenant_id: str,
    tenant_name: str,
    subject: str,
    claims: dict[str, Any] | None = None,
    request_context: dict[str, Any] | None = None,
    risk_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return normalize_identity_event(
        UISNormalizerInput(
            protocol=protocol,
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            subject=subject,
            claims=claims or {},
            request_context=request_context or {},
            risk_context=risk_context or {},
        )
    )
