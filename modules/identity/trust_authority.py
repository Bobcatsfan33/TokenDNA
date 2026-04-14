"""
TokenDNA -- Trust authority signer abstraction.

Provides pluggable signing backends so certificate issuance can move from local
software keys to KMS/HSM-backed operations without changing callers.
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


class AWSKMSTrustSigner(TrustSigner):
    """
    AWS KMS-backed RSA signer.

    Requires:
      - boto3 installed
      - IAM permissions for kms:Sign and kms:Verify
      - a SIGN_VERIFY asymmetric KMS key (typically RSA_2048/3072/4096)
    """

    def __init__(self, kms_key_id: str, key_id: str):
        self._kms_key_id = kms_key_id
        self._key_id = key_id
        self._algorithm = "RS256"

    def sign(self, payload: dict[str, Any]) -> SignResult:
        import boto3

        kms = boto3.client("kms")
        resp = kms.sign(
            KeyId=self._kms_key_id,
            Message=_canonical(payload),
            MessageType="RAW",
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
        )
        signature = _b64url_encode(resp["Signature"])
        return SignResult(signature=signature, algorithm=self._algorithm, key_id=self._key_id)

    def verify(self, payload: dict[str, Any], signature: str) -> bool:
        import boto3

        kms = boto3.client("kms")
        try:
            resp = kms.verify(
                KeyId=self._kms_key_id,
                Message=_canonical(payload),
                MessageType="RAW",
                Signature=_b64url_decode(signature),
                SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
            )
            return bool(resp.get("SignatureValid"))
        except Exception:
            return False


@dataclass
class KeyConfig:
    key_id: str
    algorithm: str
    backend: str
    kms_key_id: str | None = None


def _default_key_config(algorithm: str) -> KeyConfig:
    alg = (algorithm or "HS256").upper()
    return KeyConfig(
        key_id=os.getenv("ATTESTATION_CA_KEY_ID", "tokendna-ca-default"),
        algorithm=alg,
        backend=os.getenv("ATTESTATION_KEY_BACKEND", "software").lower(),
        kms_key_id=os.getenv("ATTESTATION_KMS_KEY_ID", "").strip() or None,
    )


def _load_keyring() -> dict[str, KeyConfig]:
    """
    Parse optional keyring env var.

    Example:
    [
      {"key_id":"k1","algorithm":"RS256","backend":"aws_kms","kms_key_id":"arn:aws:kms:..."},
      {"key_id":"k2","algorithm":"HS256","backend":"software"}
    ]
    """
    raw = os.getenv("ATTESTATION_KEYRING_JSON", "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, list):
            return {}
        out: dict[str, KeyConfig] = {}
        for item in parsed:
            if not isinstance(item, dict):
                continue
            key_id = str(item.get("key_id", "")).strip()
            if not key_id:
                continue
            out[key_id] = KeyConfig(
                key_id=key_id,
                algorithm=str(item.get("algorithm", "HS256")).upper(),
                backend=str(item.get("backend", "software")).lower(),
                kms_key_id=(str(item.get("kms_key_id", "")).strip() or None),
            )
        return out
    except Exception:
        return {}


def build_signer(*, secret_override: str | None = None) -> TrustSigner:
    preferred_alg = os.getenv("ATTESTATION_CA_ALG", "HS256").upper()
    active_key_id = os.getenv("ATTESTATION_ACTIVE_KEY_ID", "").strip()
    if active_key_id:
        return build_signer_for_key(active_key_id, preferred_alg, secret_override=secret_override)
    return build_signer_for_algorithm(preferred_alg, secret_override=secret_override)


def _build_from_key_config(cfg: KeyConfig, *, secret_override: str | None = None) -> TrustSigner:
    key_id = cfg.key_id
    preferred_alg = cfg.algorithm
    preferred_alg = (preferred_alg or "HS256").upper()
    backend = cfg.backend

    if backend == "aws_kms":
        if cfg.kms_key_id:
            return AWSKMSTrustSigner(kms_key_id=cfg.kms_key_id, key_id=key_id)
        # Fall back to software if KMS key id missing.
        backend = "software"

    if preferred_alg == "RS256" and backend != "aws_kms":
        private_pem = os.getenv("ATTESTATION_CA_PRIVATE_KEY_PEM", "").strip()
        public_pem = os.getenv("ATTESTATION_CA_PUBLIC_KEY_PEM", "").strip() or None
        if private_pem:
            signer: TrustSigner = RSATrustSigner(private_pem, public_pem, key_id=key_id)
        else:
            # Fall back to HS256 when no RSA material is available.
            secret = secret_override or os.getenv("ATTESTATION_CA_SECRET", "dev-attestation-secret-change-me")
            signer = HMACTrustSigner(secret=secret, key_id=key_id)
    else:
        secret = secret_override or os.getenv("ATTESTATION_CA_SECRET", "dev-attestation-secret-change-me")
        signer = HMACTrustSigner(secret=secret, key_id=key_id)

    if backend == "hsm":
        return MockHSMTrustSigner(signer)
    return signer


def build_signer_for_algorithm(algorithm: str, *, secret_override: str | None = None) -> TrustSigner:
    cfg = _default_key_config(algorithm)
    return _build_from_key_config(cfg, secret_override=secret_override)


def build_signer_for_key(
    key_id: str,
    algorithm: str | None = None,
    *,
    secret_override: str | None = None,
) -> TrustSigner:
    keyring = _load_keyring()
    cfg = keyring.get(key_id)
    if cfg is None:
        cfg = _default_key_config(algorithm or os.getenv("ATTESTATION_CA_ALG", "HS256"))
        cfg.key_id = key_id
    if algorithm:
        cfg.algorithm = algorithm.upper()
    return _build_from_key_config(cfg, secret_override=secret_override)


def list_key_configs() -> list[dict[str, str]]:
    keyring = _load_keyring()
    if not keyring:
        cfg = _default_key_config(os.getenv("ATTESTATION_CA_ALG", "HS256"))
        return [{"key_id": cfg.key_id, "algorithm": cfg.algorithm, "backend": cfg.backend}]
    return [
        {"key_id": cfg.key_id, "algorithm": cfg.algorithm, "backend": cfg.backend}
        for cfg in keyring.values()
    ]

