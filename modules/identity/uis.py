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

Schema source of truth
----------------------
The canonical schema lives in ``uis_schema_v1.json`` (Draft-07). Both the
runtime validator (``uis_validator.validate``) and the human-readable spec
endpoint derive from it — there is no hand-rolled list of required fields
to drift out of sync.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from modules.identity.uis_validator import (
    schema_version as _schema_version,
    validate as _schema_validate,
)


# Version pinned to the schema artifact's declared version — single source
# of truth, no drift.
UIS_VERSION = _schema_version()

# Includes ``mcp`` because adapter inputs in uis_protocol.ADAPTER_INPUTS
# already cover MCP claims; previously the normalizer silently downgraded
# protocol="mcp" to "custom".
SUPPORTED_PROTOCOLS = {"oidc", "saml", "oauth2_opaque", "spiffe", "mcp", "custom"}


def validate_uis_event(event: dict) -> list[str]:
    """Validate a UIS event dict against the canonical JSON Schema.

    Returns a (possibly empty) list of human-readable error strings. Does
    NOT raise — callers decide what to do with the errors. Errors include
    type mismatches, enum violations, range violations, and missing
    required fields — not just field-set membership.
    """
    return _schema_validate(event)


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
        "id": context.get("session_id") or claims.get("session_id"),
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

    dpop_jkt = claims.get("dpop_jkt")
    binding = {
        "dpop_jkt": dpop_jkt,
        "dpop_bound": dpop_jkt is not None,
        "mtls_subject": claims.get("mtls_subject"),
        "spiffe_id": claims.get("spiffe_id"),
        "attestation_id": claims.get("attestation_id"),
        "supply_chain_hash": claims.get("supply_chain_hash"),
    }

    # Content-addressed event_id: stable across re-normalization with the
    # same inputs. Consumer-side dedup is meaningful only when re-running
    # the normalizer on identical input produces the same id. The previous
    # implementation hashed time.time_ns() and so produced a fresh id every
    # call, defeating dedup. Caller-supplied event_id still wins.
    event_id = context.get("event_id") or _stable_hash({
        "tenant_id": data.tenant_id,
        "subject": data.subject,
        "claims": claims,
        "request_id": context.get("request_id"),
        "session_id": context.get("session_id"),
    })[:32]

    event: dict[str, Any] = {
        "uis_version": UIS_VERSION,
        "event_id": event_id,
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

    # ── Agent behavioral DNA (non-fatal) ──────────────────────────────────────
    agent_id = identity.get("agent_id")
    if agent_id:
        try:
            from modules.identity import agent_dna as _agent_dna  # noqa: PLC0415
            baseline = _agent_dna.get_agent_dna(data.tenant_id, agent_id)
            if baseline:
                deviation_score = _agent_dna.compute_deviation_score(baseline, event)
                event["behavior"]["pattern_deviation_score"] = deviation_score
                event["behavior"]["dna_fingerprint"] = baseline.get("fingerprint_hash")
                if deviation_score > 0.6:
                    event["behavior"]["velocity_anomaly"] = True
        except Exception:  # noqa: BLE001
            pass  # DNA computation must never break the normalize flow

    return event


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
