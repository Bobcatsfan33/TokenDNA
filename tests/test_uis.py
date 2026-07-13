from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity.uis import SUPPORTED_PROTOCOLS, UIS_VERSION, normalize_from_protocol


def test_uis_supported_protocols_contains_core_adapters():
    assert "oidc" in SUPPORTED_PROTOCOLS
    assert "saml" in SUPPORTED_PROTOCOLS
    assert "spiffe" in SUPPORTED_PROTOCOLS


def test_normalize_from_protocol_builds_all_uis_field_sets():
    event = normalize_from_protocol(
        protocol="oidc",
        tenant_id="tenant-1",
        tenant_name="Acme",
        subject="user-123",
        claims={
            "iss": "https://issuer.example.com",
            "aud": "tokendna",
            "sub": "user-123",
            "jti": "abc-123",
            "amr": ["mfa"],
            "scope": ["read", "write"],
            "dpop_bound": True,
        },
        request_context={
            "session_id": "sess-1",
            "ip": "10.0.0.1",
            "country": "US",
            "asn": "AS123",
            "dna_fingerprint": "dna-1",
        },
        risk_context={
            "risk_score": 22,
            "risk_tier": "step_up",
            "impossible_travel": False,
            "indicators": ["vpn_or_proxy"],
        },
    )

    assert event["uis_version"] == UIS_VERSION
    for field_set in ("identity", "auth", "token", "session", "behavior", "lifecycle", "threat", "binding"):
        assert field_set in event

    assert event["identity"]["subject"] == "user-123"
    assert event["auth"]["protocol"] == "oidc"
    assert event["auth"]["mfa_asserted"] is True
    assert event["token"]["dpop_bound"] is True
    assert event["threat"]["risk_score"] == 22


def test_normalize_from_protocol_falls_back_to_custom_protocol():
    event = normalize_from_protocol(
        protocol="nonexistent-protocol",
        tenant_id="tenant-1",
        tenant_name="Acme",
        subject="svc-1",
    )
    assert event["auth"]["protocol"] == "custom"
