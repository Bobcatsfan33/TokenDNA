"""
TokenDNA -- Trust authority signer abstraction.

Provides a pluggable signing interface so certificate issuance can move from
local software keys to HSM-backed key operations without changing callers.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Any

from base64 import urlsafe_b64decode, urlsafe_b64encode


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64url_encode(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("utf-8")


def _b64url_decode(value: str) -> bytes:
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    return urlsafe_b64decode(padded.encode("utf-8"))


@dataclass
class SignResult:
    signature: str
    algorithm: str
    key_id: str


class TrustSigner:
    def sign(self, payload: dict[str, Any]) -> SignResult:
        raise NotImplementedError

    def verify(self, payload: dict[str, Any], signature: str) -> bool:
        raise NotImplementedError


class HMACTrustSigner(TrustSigner):
    def __init__(self, secret: str, key_id: str = "tokendna-hmac-default"):
        self._secret = secret
        self._key_id = key_id

    def sign(self, payload: dict[str, Any]) -> SignResult:
        digest = hmac.new(
            self._secret.encode("utf-8"),
            _canonical(payload),
            hashlib.sha256,
        ).digest()
        return SignResult(signature=_b64url_encode(digest), algorithm="HS256", key_id=self._key_id)

    def verify(self, payload: dict[str, Any], signature: str) -> bool:
        expected = self.sign(payload).signature
        return hmac.compare_digest(expected, signature)


class RSATrustSigner(TrustSigner):
    def __init__(self, private_key_pem: str, public_key_pem: str | None = None, key_id: str = "tokendna-rsa-default"):
        self._private_key_pem = private_key_pem
        self._public_key_pem = public_key_pem
        self._key_id = key_id

    def sign(self, payload: dict[str, Any]) -> SignResult:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        private_key = serialization.load_pem_private_key(
            self._private_key_pem.encode("utf-8"),
            password=None,
        )
        signature = private_key.sign(
            _canonical(payload),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return SignResult(signature=_b64url_encode(signature), algorithm="RS256", key_id=self._key_id)

    def verify(self, payload: dict[str, Any], signature: str) -> bool:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        try:
            key_pem = self._public_key_pem or self._private_key_pem
            loaded_key = (
                serialization.load_pem_private_key(key_pem.encode("utf-8"), password=None)
                if "PRIVATE KEY" in key_pem
                else serialization.load_pem_public_key(key_pem.encode("utf-8"))
            )
            public_key = loaded_key.public_key() if hasattr(loaded_key, "public_key") else loaded_key
            public_key.verify(
                _b64url_decode(signature),
                _canonical(payload),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False


class MockHSMTrustSigner(TrustSigner):
    """
    Mock HSM adapter for development.

    In production this class can call vendor SDKs (CloudHSM/KMS/HSM appliance)
    while preserving the same interface.
    """

    def __init__(self, backing_signer: TrustSigner):
        self._backing = backing_signer

    def sign(self, payload: dict[str, Any]) -> SignResult:
        return self._backing.sign(payload)

    def verify(self, payload: dict[str, Any], signature: str) -> bool:
        return self._backing.verify(payload, signature)


def build_signer() -> TrustSigner:
    preferred_alg = os.getenv("ATTESTATION_CA_ALG", "HS256").upper()
    return build_signer_for_algorithm(preferred_alg)


def build_signer_for_algorithm(algorithm: str) -> TrustSigner:
    key_id = os.getenv("ATTESTATION_CA_KEY_ID", "tokendna-ca-default")
    preferred_alg = (algorithm or "HS256").upper()
    hsm_mode = os.getenv("ATTESTATION_KEY_BACKEND", "software").lower() == "hsm"

    if preferred_alg == "RS256":
        private_pem = os.getenv("ATTESTATION_CA_PRIVATE_KEY_PEM", "").strip()
        public_pem = os.getenv("ATTESTATION_CA_PUBLIC_KEY_PEM", "").strip() or None
        if private_pem:
            signer: TrustSigner = RSATrustSigner(private_pem, public_pem, key_id=key_id)
        else:
            # Fall back to HS256 when no RSA material is available.
            secret = os.getenv("ATTESTATION_CA_SECRET", "dev-attestation-secret-change-me")
            signer = HMACTrustSigner(secret=secret, key_id=key_id)
    else:
        secret = os.getenv("ATTESTATION_CA_SECRET", "dev-attestation-secret-change-me")
        signer = HMACTrustSigner(secret=secret, key_id=key_id)

    if hsm_mode:
        return MockHSMTrustSigner(signer)
    return signer

