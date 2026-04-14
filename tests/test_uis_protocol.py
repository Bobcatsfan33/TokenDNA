from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity.uis_protocol import adapt_claims_for_protocol, get_uis_spec, normalize_with_adapter


def test_get_uis_spec_contains_fields_and_adapters():
    spec = get_uis_spec()
    assert spec["version"] == "1.0"
    assert "identity" in spec["field_sets"]
    assert "oidc" in spec["adapters"]


def test_adapt_claims_for_protocol_saml_maps_nameid():
    claims = adapt_claims_for_protocol(
        "saml",
        {
            "name_id": "alice@example.com",
            "issuer": "saml-idp",
            "audience": "tokendna",
            "session_index": "sess-1",
            "attributes": {"roles": ["admin"]},
        },
    )
    assert claims["sub"] == "alice@example.com"
    assert claims["iss"] == "saml-idp"


def test_normalize_with_adapter_for_mcp_yields_machine_identity():
    event = normalize_with_adapter(
        protocol="mcp",
        tenant_id="tenant-1",
        tenant_name="Acme",
        payload={
            "agent_id": "agent-1",
            "issuer": "mcp-gateway",
            "tool_scope": ["read:orders"],
            "mcp_manifest_hash": "mcp-hash",
        },
        request_context={"request_id": "r1", "ip": "1.1.1.1"},
        risk_context={"risk_score": 10, "risk_tier": "allow"},
    )
    assert event["identity"]["entity_type"] == "machine"
    assert event["identity"]["agent_id"] == "agent-1"
    assert event["auth"]["protocol"] == "custom"

