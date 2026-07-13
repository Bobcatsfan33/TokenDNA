from __future__ import annotations

from modules.identity.certificate_status import build_crl, certificate_status_payload


def test_certificate_status_good_payload():
    cert = {
        "certificate_id": "cert-1",
        "attestation_id": "att-1",
        "issuer": "issuer",
        "subject": "agent-1",
        "expires_at": "2026-01-02T00:00:00+00:00",
        "signature_alg": "HS256",
        "ca_key_id": "k1",
    }
    verification = {"valid": True, "reason": "ok"}
    status = certificate_status_payload(certificate=cert, verification=verification)
    assert status["status"] == "good"
    assert status["certificate_id"] == "cert-1"
    assert status["ca_key_id"] == "k1"


def test_certificate_status_unknown_for_missing_certificate():
    status = certificate_status_payload(certificate=None, verification=None)
    assert status["status"] == "unknown"
    assert status["reason"] == "not_found"


def test_certificate_status_revoked_payload():
    cert = {
        "certificate_id": "cert-2",
        "attestation_id": "att-2",
        "issuer": "issuer",
        "subject": "agent-2",
        "revoked_at": "2026-01-01T00:00:00+00:00",
        "revocation_reason": "compromised",
        "expires_at": "2026-01-02T00:00:00+00:00",
    }
    verification = {"valid": False, "reason": "revoked"}
    status = certificate_status_payload(certificate=cert, verification=verification)
    assert status["status"] == "revoked"
    assert status["revocation_reason"] == "compromised"


def test_build_crl_shapes_revoked_certificates():
    revoked = [
        {
            "certificate_id": "cert-1",
            "attestation_id": "att-1",
            "revoked_at": "2026-01-01T00:00:00+00:00",
            "revocation_reason": "manual",
            "issuer": "issuer",
            "subject": "agent-1",
        }
    ]
    crl = build_crl(tenant_id="tenant-1", revoked_certificates=revoked)
    assert crl["tenant_id"] == "tenant-1"
    assert len(crl["revoked_certificates"]) == 1
    assert crl["revoked_certificates"][0]["certificate_id"] == "cert-1"
