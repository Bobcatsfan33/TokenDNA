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
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime, timedelta, timezone
from typing import Any


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


def _b64url_encode(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("utf-8")


def _b64url_decode(value: str) -> bytes:
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    return urlsafe_b64decode(padded.encode("utf-8"))


def _rsa_private_key_pem() -> str | None:
    pem = os.getenv("ATTESTATION_CA_PRIVATE_KEY_PEM", "").strip()
    return pem or None


def _rsa_public_key_pem() -> str | None:
    pem = os.getenv("ATTESTATION_CA_PUBLIC_KEY_PEM", "").strip()
    return pem or None


def _canonical_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _sign_hs256(payload: dict[str, Any], secret: str) -> str:
    message = _canonical_payload(payload).encode("utf-8")
    key = secret.encode("utf-8")
    digest = hmac.new(key, message, hashlib.sha256).digest()
    return _b64url_encode(digest)


def _sign_rs256(payload: dict[str, Any], private_key_pem: str) -> str:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None,
    )
    signature = private_key.sign(
        _canonical_payload(payload).encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return _b64url_encode(signature)


def _verify_hs256(payload: dict[str, Any], signature: str, secret: str) -> bool:
    expected = _sign_hs256(payload, secret)
    return hmac.compare_digest(signature, expected)


def _verify_rs256(payload: dict[str, Any], signature: str, public_key_pem: str | None, private_key_pem: str | None) -> bool:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    key_pem = public_key_pem or private_key_pem
    if not key_pem:
        return False

    loaded_key = serialization.load_pem_private_key(
        key_pem.encode("utf-8"), password=None
    ) if "PRIVATE KEY" in key_pem else serialization.load_pem_public_key(key_pem.encode("utf-8"))

    public_key = loaded_key.public_key() if hasattr(loaded_key, "public_key") else loaded_key

    try:
        public_key.verify(
            _b64url_decode(signature),
            _canonical_payload(payload).encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


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
    if signing_alg == "RS256":
        private_pem = _rsa_private_key_pem()
        if not private_pem:
            # Safe fallback for environments that have not yet provisioned RSA keys.
            payload["signature_alg"] = "HS256"
            signature = _sign_hs256(payload, secret or _secret())
        else:
            signature = _sign_rs256(payload, private_pem)
    else:
        signature = _sign_hs256(payload, secret or _secret())
    return {**payload, "signature": signature}


def revoke_certificate(certificate: dict[str, Any], reason: str, *, secret: str | None = None) -> dict[str, Any]:
    updated = dict(certificate)
    updated["status"] = "revoked"
    updated["revoked_at"] = _utc_now().isoformat()
    updated["revocation_reason"] = reason or "unspecified"
    # Lifecycle metadata is part of the signed payload; re-sign after mutation.
    payload = dict(updated)
    payload.pop("signature", None)
    alg = str(payload.get("signature_alg", DEFAULT_SIGNING_ALG)).upper()
    if alg == "RS256":
        private_pem = _rsa_private_key_pem()
        if private_pem:
            updated["signature"] = _sign_rs256(payload, private_pem)
        else:
            payload["signature_alg"] = "HS256"
            updated["signature_alg"] = "HS256"
            updated["signature"] = _sign_hs256(payload, secret or _secret())
    else:
        updated["signature"] = _sign_hs256(payload, secret or _secret())
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

    if alg == "RS256":
        sig_ok = _verify_rs256(
            payload,
            provided_sig,
            _rsa_public_key_pem(),
            _rsa_private_key_pem(),
        )
    else:
        sig_ok = _verify_hs256(payload, provided_sig, secret or _secret())

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
