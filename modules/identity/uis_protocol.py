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


# SAML authn_context_class_ref → auth method string
_SAML_AUTHN_METHOD_MAP: dict[str, str] = {
    "PasswordProtectedTransport": "password",
    "Password": "password",
    "X509": "certificate",
    "X509Certificate": "certificate",
    "SmartCard": "smartcard",
    "SmartCardPKI": "smartcard",
    "Kerberos": "kerberos",
    "InternetProtocolPassword": "password",
    "TLSClient": "certificate",
}

_SAML_STRONG_AUTHN_CONTEXTS = frozenset({"X509", "X509Certificate", "SmartCard", "SmartCardPKI"})


def _saml_map_authn_context(ctx: str | None) -> tuple[str, str, bool]:
    """Return (auth_method, credential_strength, mfa_asserted) for a SAML authn context."""
    if not ctx:
        return "unknown", "standard", False

    # MFA detection: case-insensitive substring match
    mfa_asserted = "multifactor" in ctx.lower() or "mfa" in ctx.lower()

    # Map to method string — check for substring matches so URN forms also match
    auth_method = "unknown"
    for key, method in _SAML_AUTHN_METHOD_MAP.items():
        if key.lower() in ctx.lower():
            auth_method = method
            break

    # Credential strength
    credential_strength = "standard"
    for strong_ctx in _SAML_STRONG_AUTHN_CONTEXTS:
        if strong_ctx.lower() in ctx.lower():
            credential_strength = "strong"
            break

    return auth_method, credential_strength, mfa_asserted


def _adapt_saml(payload: dict[str, Any]) -> dict[str, Any]:
    attributes = payload.get("attributes", {}) or {}
    authn_ctx = payload.get("authn_context_class_ref")
    auth_method, credential_strength, mfa_asserted = _saml_map_authn_context(authn_ctx)

    # Build display_name from SAML attributes (email > upn > subject)
    display_name = (
        attributes.get("email")
        or attributes.get("upn")
        or payload.get("name_id")
    )
    groups = attributes.get("groups", [])

    return {
        "sub": payload.get("name_id"),
        "iss": payload.get("issuer"),
        "aud": payload.get("audience"),
        # session_index maps to session.id via claims.session_id fallback in uis.py
        "session_id": payload.get("session_index"),
        # keep jti for backward compatibility
        "jti": payload.get("session_index"),
        # amr uses the mapped method so normalize_identity_event picks it up correctly
        "amr": [auth_method] if auth_method and auth_method != "unknown" else [],
        "auth_method": auth_method,
        "acr": credential_strength,
        "mfa": mfa_asserted,
        "scope": attributes.get("scope", []),
        "roles": attributes.get("roles", []),
        "entity_type": attributes.get("entity_type", "human"),
        "name": display_name,
        "groups": groups,
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
    # Count total required fields across all field sets
    field_count = sum(len(fs["required_fields"]) for fs in UIS_FIELD_SETS.values())

    # Build supported_protocols list with adapter input key mappings
    supported_protocols = [
        {
            "protocol": protocol,
            "description": adapter["description"],
            "adapter_input_keys": adapter["keys"],
        }
        for protocol, adapter in ADAPTER_INPUTS.items()
    ]

    return {
        "version": "1.0",
        "status": "GA",
        "release_date": "2026-04-16",
        "field_sets": UIS_FIELD_SETS,
        "adapters": ADAPTER_INPUTS,
        "supported_protocols": supported_protocols,
        "field_count": field_count,
        "schema_url": "/api/schema/uis.json",
        "changelog": [
            {
                "version": "1.0",
                "date": "2026-04-16",
                "notes": "Initial GA release. 8 field sets, 5 protocol adapters, DPoP binding, SAML completion.",
            }
        ],
        "notes": [
            "UIS is protocol-agnostic and vendor-neutral.",
            "Adapters translate source protocol artifacts into normalized claims.",
            "The spec is designed for open ecosystem adoption with managed-cloud graduation.",
        ],
    }

