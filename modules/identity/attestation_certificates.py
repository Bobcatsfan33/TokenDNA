"""
TokenDNA -- Agent attestation certificate issuance and verification.

Implements a lightweight certificate authority flow using HMAC signatures:
  - issue_certificate(): signs attestation claims into a certificate envelope
  - verify_certificate(): verifies signature and expiry

This is a practical intermediate step toward a dedicated PKI-backed trust
authority while keeping interfaces stable for future upgrades.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any


DEFAULT_TTL_HOURS = 24


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _secret() -> str:
    return os.getenv("ATTESTATION_CA_SECRET", "dev-attestation-secret-change-me")


def _canonical_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _sign(payload: dict[str, Any], secret: str) -> str:
    message = _canonical_payload(payload).encode("utf-8")
    key = secret.encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


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

    payload = {
        "certificate_id": certificate_id,
        "tenant_id": tenant_id,
        "attestation_id": attestation_id,
        "issuer": issuer,
        "subject": subject,
        "issued_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "claims": claims,
    }
    signature = _sign(payload, secret or _secret())
    return {**payload, "signature": signature}


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
    expected_sig = _sign(payload, secret or _secret())
    if not hmac.compare_digest(provided_sig, expected_sig):
        return {"valid": False, "reason": "invalid_signature"}

    current = now or _utc_now()
    try:
        expires_at = datetime.fromisoformat(certificate["expires_at"])
    except Exception:
        return {"valid": False, "reason": "invalid_expiry_format"}
    if current > expires_at:
        return {"valid": False, "reason": "expired"}

    return {
        "valid": True,
        "reason": "ok",
        "certificate_id": certificate["certificate_id"],
        "attestation_id": certificate["attestation_id"],
        "tenant_id": certificate["tenant_id"],
        "subject": certificate["subject"],
        "issuer": certificate["issuer"],
        "expires_at": certificate["expires_at"],
    }
