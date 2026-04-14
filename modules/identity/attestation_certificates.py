"""
TokenDNA -- Agent attestation certificate issuance and verification.

Supports two signing modes selected by ATTESTATION_CA_ALG:
  - HS256 (default): HMAC signing
  - RS256: RSA private/public key signing

This lets us ship a practical trust-authority flow now while keeping the
certificate interface compatible with stronger asymmetric deployments.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from modules.identity.trust_authority import build_signer


DEFAULT_TTL_HOURS = 24
DEFAULT_SIGNING_ALG = "HS256"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _secret() -> str:
    return os.getenv("ATTESTATION_CA_SECRET", "dev-attestation-secret-change-me")


def _signing_alg() -> str:
    alg = os.getenv("ATTESTATION_CA_ALG", DEFAULT_SIGNING_ALG).upper()
    if alg not in {"HS256", "RS256"}:
        return DEFAULT_SIGNING_ALG
    return alg


def _canonical_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def issue_certificate(
    *,
    tenant_id: str,
    attestation_id: str,
    subject: str,
    issuer: str,
    claims: dict[str, Any],
    ttl_hours: int = DEFAULT_TTL_HOURS,
    secret: str | None = None,
) -> dict[str, Any]:
    now = _utc_now()
    expires = now + timedelta(hours=max(1, int(ttl_hours)))
    certificate_id = uuid.uuid4().hex
    signer = build_signer()
    signing_alg = _signing_alg()
    ca_key_id = os.getenv("ATTESTATION_CA_KEY_ID", "tokendna-ca-default")

    payload = {
        "certificate_id": certificate_id,
        "tenant_id": tenant_id,
        "attestation_id": attestation_id,
        "issuer": issuer,
        "subject": subject,
        "issued_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "claims": claims,
        "signature_alg": signing_alg,
        "ca_key_id": ca_key_id,
        "status": "active",
        "revoked_at": None,
        "revocation_reason": None,
    }
    sign_result = signer.sign(payload)
    payload["signature_alg"] = sign_result.algorithm
    payload["ca_key_id"] = sign_result.key_id
    signature = signer.sign(payload).signature
    return {**payload, "signature": signature}


def revoke_certificate(certificate: dict[str, Any], reason: str, *, secret: str | None = None) -> dict[str, Any]:
    updated = dict(certificate)
    updated["status"] = "revoked"
    updated["revoked_at"] = _utc_now().isoformat()
    updated["revocation_reason"] = reason or "unspecified"
    # Lifecycle metadata is part of the signed payload; re-sign after mutation.
    payload = dict(updated)
    payload.pop("signature", None)
    signer = build_signer()
    sign_result = signer.sign(payload)
    updated["signature_alg"] = sign_result.algorithm
    updated["ca_key_id"] = sign_result.key_id
    payload["signature_alg"] = sign_result.algorithm
    payload["ca_key_id"] = sign_result.key_id
    updated["signature"] = signer.sign(payload).signature
    return updated


def verify_certificate(
    certificate: dict[str, Any],
    *,
    secret: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    required_fields = {
        "certificate_id",
        "tenant_id",
        "attestation_id",
        "issuer",
        "subject",
        "issued_at",
        "expires_at",
        "claims",
        "signature",
    }
    missing = sorted(required_fields - set(certificate.keys()))
    if missing:
        return {"valid": False, "reason": f"missing_fields:{','.join(missing)}"}

    payload = dict(certificate)
    provided_sig = payload.pop("signature")
    alg = str(certificate.get("signature_alg", DEFAULT_SIGNING_ALG)).upper()

    sig_ok = build_signer().verify(payload, provided_sig)

    if not sig_ok:
        return {"valid": False, "reason": "invalid_signature"}

    current = now or _utc_now()
    try:
        expires_at = datetime.fromisoformat(certificate["expires_at"])
    except Exception:
        return {"valid": False, "reason": "invalid_expiry_format"}
    if current > expires_at:
        return {"valid": False, "reason": "expired"}
    if certificate.get("status") == "revoked":
        return {
            "valid": False,
            "reason": "revoked",
            "revoked_at": certificate.get("revoked_at"),
            "revocation_reason": certificate.get("revocation_reason"),
        }

    return {
        "valid": True,
        "reason": "ok",
        "certificate_id": certificate["certificate_id"],
        "attestation_id": certificate["attestation_id"],
        "tenant_id": certificate["tenant_id"],
        "subject": certificate["subject"],
        "issuer": certificate["issuer"],
        "expires_at": certificate["expires_at"],
        "signature_alg": alg,
        "status": certificate.get("status", "active"),
    }
