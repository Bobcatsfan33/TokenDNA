from __future__ import annotations

import os
import sys
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity.attestation_certificates import issue_certificate, verify_certificate


def test_issue_and_verify_certificate_success():
    cert = issue_certificate(
        tenant_id="tenant-1",
        attestation_id="att-1",
        subject="agent-1",
        issuer="TokenDNA Trust Authority",
        claims={"integrity_digest": "abc"},
        ttl_hours=1,
        secret="test-secret",
    )
    result = verify_certificate(cert, secret="test-secret")
    assert result["valid"] is True
    assert result["reason"] == "ok"
    assert result["attestation_id"] == "att-1"


def test_verify_certificate_detects_tamper():
    cert = issue_certificate(
        tenant_id="tenant-1",
        attestation_id="att-2",
        subject="agent-2",
        issuer="TokenDNA Trust Authority",
        claims={"integrity_digest": "abc"},
        ttl_hours=1,
        secret="test-secret",
    )
    cert["subject"] = "tampered-agent"
    result = verify_certificate(cert, secret="test-secret")
    assert result["valid"] is False
    assert result["reason"] == "invalid_signature"


def test_verify_certificate_detects_expiry():
    cert = issue_certificate(
        tenant_id="tenant-1",
        attestation_id="att-3",
        subject="agent-3",
        issuer="TokenDNA Trust Authority",
        claims={"integrity_digest": "abc"},
        ttl_hours=1,
        secret="test-secret",
    )
    result = verify_certificate(
        cert,
        secret="test-secret",
        now=(__import__("datetime").datetime.fromisoformat(cert["expires_at"]) + timedelta(seconds=1)),
    )
    assert result["valid"] is False
    assert result["reason"] == "expired"


def test_verify_certificate_missing_fields():
    result = verify_certificate({"certificate_id": "x"}, secret="test-secret")
    assert result["valid"] is False
    assert result["reason"].startswith("missing_fields:")

