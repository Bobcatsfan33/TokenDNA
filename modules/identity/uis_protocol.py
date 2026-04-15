"""
TokenDNA -- UIS protocol specification and adapter helpers.

This module keeps the UIS contract explicit and adapter-friendly so the
open-protocol surface is easy for external developers to consume.
"""

from __future__ import annotations

from typing import Any

from modules.identity.uis import normalize_from_protocol


UIS_FIELD_SETS = {
    "identity": {
        "description": "Core subject/entity attributes for human and machine identities",
        "required_fields": ["subject", "tenant_id", "entity_type"],
    },
    "auth": {
        "description": "Authentication context (method, protocol, MFA, credential strength)",
        "required_fields": ["protocol", "method", "mfa_asserted"],
    },
    "token": {
        "description": "Token metadata and binding state",
        "required_fields": ["issuer", "type", "claims_hash"],
    },
    "session": {
        "description": "Session and network context for risk analysis",
        "required_fields": ["request_id", "ip", "country", "asn"],
    },
    "behavior": {
        "description": "Behavioral DNA and drift/anomaly context",
        "required_fields": ["dna_fingerprint", "pattern_deviation_score", "velocity_anomaly"],
    },
    "lifecycle": {
        "description": "Identity lifecycle state transitions",
        "required_fields": ["state", "provisioned_at", "revoked_at", "dormant"],
    },
    "threat": {
        "description": "Runtime threat and risk evaluation output",
        "required_fields": ["risk_score", "risk_tier", "indicators"],
    },
    "binding": {
        "description": "Cryptographic/token/attestation bindings",
        "required_fields": ["dpop_jkt", "attestation_id"],
    },
}


ADAPTER_INPUTS = {
    "oidc": {
        "description": "OIDC/JWT claims",
        "keys": ["sub", "iss", "aud", "jti", "scope", "amr", "acr", "dpop_jkt"],
    },
    "saml": {
        "description": "SAML assertion projection",
        "keys": ["name_id", "issuer", "audience", "session_index", "authn_context_class_ref", "attributes"],
    },
    "oauth2_opaque": {
        "description": "OAuth introspection response",
        "keys": ["active", "sub", "client_id", "scope", "exp", "iat", "token_type"],
    },
    "spiffe": {
        "description": "Workload identity from SPIFFE/SVID",
        "keys": ["spiffe_id", "trust_domain", "workload", "san_uri", "issuer"],
    },
    "mcp": {
        "description": "MCP server/agent interaction metadata",
        "keys": ["agent_id", "mcp_server_id", "mcp_manifest_hash", "tool_name", "tool_scope"],
    },
}


def _adapt_saml(payload: dict[str, Any]) -> dict[str, Any]:
    attributes = payload.get("attributes", {}) or {}
    return {
        "sub": payload.get("name_id"),
        "iss": payload.get("issuer"),
        "aud": payload.get("audience"),
        "jti": payload.get("session_index"),
        "amr": [payload.get("authn_context_class_ref")] if payload.get("authn_context_class_ref") else [],
        "scope": attributes.get("scope", []),
        "roles": attributes.get("roles", []),
        "entity_type": attributes.get("entity_type", "human"),
    }


def _adapt_oauth_introspection(payload: dict[str, Any]) -> dict[str, Any]:
    scope = payload.get("scope")
    normalized_scope = scope.split() if isinstance(scope, str) else (scope or [])
    return {
        "sub": payload.get("sub") or payload.get("client_id"),
        "iss": payload.get("iss", "oauth-introspection"),
        "aud": payload.get("aud"),
        "jti": payload.get("jti"),
        "scope": normalized_scope,
        "exp": payload.get("exp"),
        "iat": payload.get("iat"),
        "token_type": payload.get("token_type", "bearer"),
        "entity_type": "machine" if payload.get("client_id") else "human",
    }


def _adapt_spiffe(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "sub": payload.get("spiffe_id") or payload.get("san_uri"),
        "iss": payload.get("issuer", payload.get("trust_domain")),
        "aud": payload.get("aud"),
        "jti": payload.get("jti"),
        "spiffe_id": payload.get("spiffe_id") or payload.get("san_uri"),
        "machine_classification": payload.get("workload", "workload"),
        "entity_type": "machine",
        "auth_method": "mtls",
        "token_type": "x509",
        "mfa": False,
    }


def _adapt_mcp(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "sub": payload.get("agent_id") or payload.get("subject"),
        "agent_id": payload.get("agent_id"),
        "iss": payload.get("issuer", "mcp"),
        "aud": payload.get("aud"),
        "scope": payload.get("tool_scope", []),
        "mcp_manifest_hash": payload.get("mcp_manifest_hash"),
        "entity_type": "machine",
        "machine_classification": "agent",
        "token_type": payload.get("token_type", "agent-token"),
    }


def adapt_claims_for_protocol(protocol: str, payload: dict[str, Any]) -> dict[str, Any]:
    p = (protocol or "custom").lower()
    if p == "saml":
        return _adapt_saml(payload)
    if p == "oauth2_opaque":
        return _adapt_oauth_introspection(payload)
    if p == "spiffe":
        return _adapt_spiffe(payload)
    if p == "mcp":
        return _adapt_mcp(payload)
    return payload


def normalize_with_adapter(
    *,
    protocol: str,
    tenant_id: str,
    tenant_name: str,
    payload: dict[str, Any],
    request_context: dict[str, Any] | None = None,
    risk_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    claims = adapt_claims_for_protocol(protocol, payload or {})
    subject = str(claims.get("sub") or payload.get("subject") or "unknown")
    normalized_protocol = protocol if protocol in {"oidc", "saml", "oauth2_opaque", "spiffe", "mcp", "custom"} else "custom"
    return normalize_from_protocol(
        protocol=normalized_protocol,
        tenant_id=tenant_id,
        tenant_name=tenant_name,
        subject=subject,
        claims=claims,
        request_context=request_context or {},
        risk_context=risk_context or {},
    )


def get_uis_spec() -> dict[str, Any]:
    return {
        "version": "1.0",
        "field_sets": UIS_FIELD_SETS,
        "adapters": ADAPTER_INPUTS,
        "notes": [
            "UIS is protocol-agnostic and vendor-neutral.",
            "Adapters translate source protocol artifacts into normalized claims.",
            "The spec is designed for open ecosystem adoption with managed-cloud graduation.",
        ],
    }

