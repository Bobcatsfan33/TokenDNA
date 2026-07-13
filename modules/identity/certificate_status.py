"""
TokenDNA -- Certificate status and revocation index helpers.

Provides OCSP-like status responses and lightweight CRL exports for runtime
enforcement callers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def certificate_status_payload(
    *,
    certificate: dict[str, Any] | None,
    verification: dict[str, Any] | None,
) -> dict[str, Any]:
    if certificate is None:
        return {
            "status": "unknown",
            "reason": "not_found",
            "checked_at": _iso_now(),
            "certificate_id": None,
            "attestation_id": None,
        }

    verification = verification or {}
    if not verification.get("valid", False):
        reason = str(verification.get("reason", "invalid"))
        if reason == "revoked":
            status = "revoked"
        elif reason == "expired":
            status = "expired"
        else:
            status = "invalid"
        return {
            "status": status,
            "reason": reason,
            "checked_at": _iso_now(),
            "certificate_id": certificate.get("certificate_id"),
            "attestation_id": certificate.get("attestation_id"),
            "issuer": certificate.get("issuer"),
            "subject": certificate.get("subject"),
            "revoked_at": certificate.get("revoked_at"),
            "revocation_reason": certificate.get("revocation_reason"),
            "expires_at": certificate.get("expires_at"),
        }

    return {
        "status": "good",
        "reason": "ok",
        "checked_at": _iso_now(),
        "certificate_id": certificate.get("certificate_id"),
        "attestation_id": certificate.get("attestation_id"),
        "issuer": certificate.get("issuer"),
        "subject": certificate.get("subject"),
        "expires_at": certificate.get("expires_at"),
        "signature_alg": certificate.get("signature_alg"),
        "ca_key_id": certificate.get("ca_key_id"),
    }


def build_crl(
    *,
    tenant_id: str,
    revoked_certificates: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "tenant_id": tenant_id,
        "generated_at": _iso_now(),
        "revoked_certificates": [
            {
                "certificate_id": cert.get("certificate_id"),
                "attestation_id": cert.get("attestation_id"),
                "revoked_at": cert.get("revoked_at"),
                "revocation_reason": cert.get("revocation_reason"),
                "issuer": cert.get("issuer"),
                "subject": cert.get("subject"),
            }
            for cert in revoked_certificates
        ],
    }

