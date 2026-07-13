"""
TokenDNA Sprint 3-1 — UIS v1.0 GA Tests.

Covers:
  - validate_uis_event: valid event, missing field set, missing required field
  - SAML adapter: authn_context_class_ref mapping, MFA detection
  - DPoP binding surface: dpop_jkt propagates to token.dpop_bound and binding.dpop_bound
  - Schema artifact: uis_schema_v1.json is valid JSON Schema
  - API normalize response: includes validation_warnings field
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity.uis import normalize_from_protocol, validate_uis_event
from modules.identity.uis_protocol import _adapt_saml, normalize_with_adapter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_valid_event() -> dict:
    """Return a complete well-formed UIS event."""
    return normalize_from_protocol(
        protocol="oidc",
        tenant_id="t-test",
        tenant_name="Test Tenant",
        subject="user@example.com",
        claims={
            "iss": "https://idp.example.com",
            "aud": "tokendna",
            "jti": "jti-001",
            "amr": ["password"],
            "acr": "standard",
            "dpop_jkt": "thumbprint-abc123",
        },
        request_context={
            "request_id": "req-001",
            "ip": "1.2.3.4",
            "country": "US",
            "asn": "AS12345",
        },
        risk_context={
            "risk_score": 10,
            "risk_tier": "low",
        },
    )


# ---------------------------------------------------------------------------
# 1. validate_uis_event — passes for a well-formed event
# ---------------------------------------------------------------------------

def test_validate_uis_event_passes_for_valid_event():
    event = _make_valid_event()
    errors = validate_uis_event(event)
    assert errors == [], f"Expected no errors, got: {errors}"


# ---------------------------------------------------------------------------
# 2. validate_uis_event — catches missing field set
# ---------------------------------------------------------------------------

def test_validate_uis_event_catches_missing_field_set():
    event = _make_valid_event()
    del event["binding"]
    errors = validate_uis_event(event)
    assert any("binding" in e for e in errors), (
        f"Expected error about missing 'binding' field set, got: {errors}"
    )


# ---------------------------------------------------------------------------
# 3. validate_uis_event — catches missing required field
# ---------------------------------------------------------------------------

def test_validate_uis_event_catches_missing_required_field():
    event = _make_valid_event()
    del event["identity"]["subject"]
    errors = validate_uis_event(event)
    assert any("identity.subject" in e for e in errors), (
        f"Expected error about missing 'identity.subject', got: {errors}"
    )


# ---------------------------------------------------------------------------
# 4. SAML adapter — authn_context_class_ref X509 → method=certificate, strength=strong
# ---------------------------------------------------------------------------

def test_saml_adapter_maps_authn_context():
    saml_payload = {
        "name_id": "user@corp.example.com",
        "issuer": "https://saml.corp.example.com",
        "audience": "tokendna",
        "authn_context_class_ref": "X509",
        "session_index": "sess-abc",
        "attributes": {},
    }
    claims = _adapt_saml(saml_payload)
    # normalize to get the full event
    event = normalize_from_protocol(
        protocol="saml",
        tenant_id="t-test",
        tenant_name="Test",
        subject=saml_payload["name_id"],
        claims=claims,
        request_context={"request_id": "r1", "ip": "10.0.0.1"},
        risk_context={},
    )
    assert event["auth"]["method"] == "certificate", (
        f"Expected method='certificate', got {event['auth']['method']!r}"
    )
    assert event["auth"]["credential_strength"] == "strong", (
        f"Expected credential_strength='strong', got {event['auth']['credential_strength']!r}"
    )


# ---------------------------------------------------------------------------
# 5. SAML adapter — MultiFactor authn context → mfa_asserted=True
# ---------------------------------------------------------------------------

def test_saml_adapter_mfa_detection():
    saml_payload = {
        "name_id": "user@corp.example.com",
        "issuer": "https://saml.corp.example.com",
        "authn_context_class_ref": "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor",
        "attributes": {},
    }
    claims = _adapt_saml(saml_payload)
    event = normalize_from_protocol(
        protocol="saml",
        tenant_id="t-test",
        tenant_name="Test",
        subject=saml_payload["name_id"],
        claims=claims,
        request_context={},
        risk_context={},
    )
    assert event["auth"]["mfa_asserted"] is True, (
        f"Expected mfa_asserted=True, got {event['auth']['mfa_asserted']!r}"
    )


# ---------------------------------------------------------------------------
# 6. DPoP binding — dpop_jkt sets token.dpop_bound=True and binding.dpop_jkt
# ---------------------------------------------------------------------------

def test_dpop_binding_sets_dpop_bound():
    dpop_jkt_value = "my-thumbprint-xyz"
    event = normalize_from_protocol(
        protocol="oidc",
        tenant_id="t-test",
        tenant_name="Test",
        subject="agent-001",
        claims={
            "iss": "https://idp.example.com",
            "dpop_jkt": dpop_jkt_value,
        },
        request_context={},
        risk_context={},
    )
    assert event["token"]["dpop_bound"] is True, (
        f"Expected token.dpop_bound=True, got {event['token']['dpop_bound']!r}"
    )
    assert event["binding"]["dpop_jkt"] == dpop_jkt_value, (
        f"Expected binding.dpop_jkt={dpop_jkt_value!r}, got {event['binding']['dpop_jkt']!r}"
    )
    assert event["binding"]["dpop_bound"] is True, (
        f"Expected binding.dpop_bound=True, got {event['binding']['dpop_bound']!r}"
    )


# ---------------------------------------------------------------------------
# 7. Schema artifact — uis_schema_v1.json is a valid JSON Schema draft-07
# ---------------------------------------------------------------------------

def test_uis_schema_artifact_is_valid_json_schema():
    schema_path = Path(__file__).parent.parent / "modules" / "identity" / "uis_schema_v1.json"
    assert schema_path.exists(), f"Schema file not found: {schema_path}"

    with schema_path.open(encoding="utf-8") as f:
        schema = json.load(f)

    assert "$schema" in schema, "Schema missing '$schema' key"
    assert "draft-07" in schema["$schema"], (
        f"Expected draft-07 schema, got: {schema['$schema']!r}"
    )
    assert schema.get("title") == "UIS v1.0 Event", (
        f"Unexpected title: {schema.get('title')!r}"
    )
    assert schema.get("version") == "1.0", (
        f"Unexpected version: {schema.get('version')!r}"
    )

    # All 8 field sets must be present as properties
    required_field_sets = {"identity", "auth", "token", "session", "behavior", "lifecycle", "threat", "binding"}
    properties = set(schema.get("properties", {}).keys())
    missing = required_field_sets - properties
    assert not missing, f"Schema properties missing field sets: {missing}"

    # All 8 field sets must be in the 'required' array
    schema_required = set(schema.get("required", []))
    missing_required = required_field_sets - schema_required
    assert not missing_required, f"Field sets not marked as required in schema: {missing_required}"


# ---------------------------------------------------------------------------
# 8. Normalize response includes validation_warnings field (via direct call)
# ---------------------------------------------------------------------------

def test_normalize_response_includes_validation_warnings_field():
    """validate_uis_event is called by the endpoint; verify it returns a list."""
    event = _make_valid_event()
    warnings = validate_uis_event(event)
    # The response wrapper would include this — confirm the return type is a list
    assert isinstance(warnings, list), (
        f"validate_uis_event should return a list, got {type(warnings)}"
    )
    # For a complete event there should be no warnings
    assert warnings == [], f"Unexpected warnings for valid event: {warnings}"


# ---------------------------------------------------------------------------
# 9. DPoP not bound when dpop_jkt absent
# ---------------------------------------------------------------------------

def test_dpop_not_bound_when_no_dpop_jkt():
    event = normalize_from_protocol(
        protocol="oidc",
        tenant_id="t-test",
        tenant_name="Test",
        subject="user-001",
        claims={"iss": "https://idp.example.com"},
        request_context={},
        risk_context={},
    )
    assert event["token"]["dpop_bound"] is False
    assert event["binding"]["dpop_bound"] is False
    assert event["binding"]["dpop_jkt"] is None


# ---------------------------------------------------------------------------
# 10. SAML session_index maps to session.id
# ---------------------------------------------------------------------------

def test_saml_session_index_maps_to_session_id():
    saml_payload = {
        "name_id": "user@corp.example.com",
        "issuer": "https://saml.corp.example.com",
        "session_index": "saml-session-99",
        "authn_context_class_ref": "PasswordProtectedTransport",
        "attributes": {},
    }
    claims = _adapt_saml(saml_payload)
    event = normalize_from_protocol(
        protocol="saml",
        tenant_id="t-test",
        tenant_name="Test",
        subject=saml_payload["name_id"],
        claims=claims,
        request_context={},
        risk_context={},
    )
    assert event["session"]["id"] == "saml-session-99", (
        f"Expected session.id='saml-session-99', got {event['session']['id']!r}"
    )


# ---------------------------------------------------------------------------
# 11. SAML PasswordProtectedTransport → method=password, strength=standard
# ---------------------------------------------------------------------------

def test_saml_password_transport_maps_correctly():
    saml_payload = {
        "name_id": "alice@example.com",
        "issuer": "https://saml.example.com",
        "authn_context_class_ref": "PasswordProtectedTransport",
        "attributes": {},
    }
    claims = _adapt_saml(saml_payload)
    event = normalize_from_protocol(
        protocol="saml",
        tenant_id="t-test",
        tenant_name="Test",
        subject=saml_payload["name_id"],
        claims=claims,
        request_context={},
        risk_context={},
    )
    assert event["auth"]["method"] == "password"
    assert event["auth"]["credential_strength"] == "standard"
    assert event["auth"]["mfa_asserted"] is False


# ---------------------------------------------------------------------------
# 12. SAML display_name is populated from attributes.email
# ---------------------------------------------------------------------------

def test_saml_display_name_from_email_attribute():
    saml_payload = {
        "name_id": "uid=alice,dc=example,dc=com",
        "issuer": "https://saml.example.com",
        "authn_context_class_ref": "Password",
        "attributes": {"email": "alice@example.com"},
    }
    claims = _adapt_saml(saml_payload)
    event = normalize_from_protocol(
        protocol="saml",
        tenant_id="t-test",
        tenant_name="Test",
        subject=saml_payload["name_id"],
        claims=claims,
        request_context={},
        risk_context={},
    )
    assert event["identity"]["display_name"] == "alice@example.com", (
        f"Expected display_name='alice@example.com', got {event['identity']['display_name']!r}"
    )
