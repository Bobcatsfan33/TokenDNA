"""
TokenDNA -- Trust authority signer abstraction.

Provides pluggable signing backends so certificate issuance can move from local
software keys to KMS/HSM-backed operations without changing callers.

Backends
--------
- ``software`` — HMAC (HS256) or RSA (RS256) keys read from environment.
  Default for development. Not acceptable for production cryptographic
  authority (no hardware boundary).

- ``aws_kms`` — AWS KMS asymmetric (SIGN_VERIFY) key. Per-call ``KeyId`` may
  be a key ARN, key UUID, or alias (e.g. ``alias/tokendna-ca``). Caches the
  KMS client per backend instance to avoid signature handshake overhead. The
  KMS service is FIPS 140-2 Level 2 validated; for Level 3 use ``cloudhsm``.

- ``cloudhsm`` — KMS Custom Key Store backed by AWS CloudHSM, providing
  FIPS 140-2 Level 3 isolation. The signer uses the same KMS Sign/Verify API
  as ``aws_kms``; the FIPS-3 boundary is established by the CMK's CustomKey
  StoreId pointing at a CloudHSM cluster. The signer marks issued
  ``SignResult.algorithm`` with the ``+CHSM`` suffix so downstream auditors
  can identify FIPS-3-issued certificates.

Key rotation
------------
Each issued certificate carries a ``ca_key_id`` field. ``verify_certificate``
in attestation_certificates.py resolves the appropriate signer for that
``ca_key_id`` from the keyring (``ATTESTATION_KEYRING_JSON``), so rotating
the active key (``ATTESTATION_ACTIVE_KEY_ID``) does not invalidate existing
certs as long as their key entry remains in the keyring. ``rotate_active_key``
below is the helper that adds a new key + flips the active pointer in one
operation.

Configuration
-------------
- ``ATTESTATION_KEY_BACKEND``      software | aws_kms | cloudhsm | hsm
- ``ATTESTATION_ACTIVE_KEY_ID``    keyring entry id used for new issuance
- ``ATTESTATION_KEYRING_JSON``     JSON list of {key_id, algorithm, backend, kms_key_id}
- ``ATTESTATION_KMS_KEY_ID`` /
  ``AWS_KMS_KEY_ID``               KMS key id / alias when no keyring entry applies
- ``ATTESTATION_AWS_REGION`` /
  ``AWS_REGION``                   AWS region for the KMS client
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
from dataclasses import dataclass
from typing import Any

from base64 import urlsafe_b64decode, urlsafe_b64encode

logger = logging.getLogger(__name__)


class TrustSignerError(Exception):
    """Raised when a signer backend cannot complete a sign or verify operation."""


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
    AWS KMS-backed RSA signer (FIPS 140-2 Level 2).

    Requires:
      - boto3 installed
      - IAM permissions for kms:Sign and kms:Verify on the KMS key
      - a SIGN_VERIFY asymmetric KMS key (typically RSA_2048/3072/4096)

    The ``kms_key_id`` may be a key ARN, key UUID, or alias path
    (``alias/tokendna-ca``) — KMS resolves all three.

    The boto3 client is cached on the instance so subsequent sign/verify
    calls don't re-handshake. Override ``client_factory`` for testing
    (the test suite injects a stub that records calls).
    """

    SIGNING_ALGORITHM = "RSASSA_PKCS1_V1_5_SHA_256"
    ALGORITHM_LABEL = "RS256"

    def __init__(
        self,
        kms_key_id: str,
        key_id: str,
        *,
        region_name: str | None = None,
        client_factory=None,
    ):
        self._kms_key_id = kms_key_id
        self._key_id = key_id
        self._region_name = region_name or os.getenv("ATTESTATION_AWS_REGION") or os.getenv("AWS_REGION")
        self._algorithm = self.ALGORITHM_LABEL
        self._client_factory = client_factory
        self._client = None
        self._client_lock = threading.Lock()

    # ── Client management ──────────────────────────────────────────────────
    def _get_client(self):
        if self._client is not None:
            return self._client
        with self._client_lock:
            if self._client is not None:
                return self._client
            if self._client_factory is not None:
                self._client = self._client_factory()
            else:
                try:
                    import boto3  # noqa: PLC0415
                except ImportError as exc:
                    raise TrustSignerError(
                        "boto3 is required for AWSKMSTrustSigner; install boto3>=1.42"
                    ) from exc
                kwargs: dict[str, Any] = {}
                if self._region_name:
                    kwargs["region_name"] = self._region_name
                self._client = boto3.client("kms", **kwargs)
            return self._client

    # ── TrustSigner interface ──────────────────────────────────────────────
    def sign(self, payload: dict[str, Any]) -> SignResult:
        kms = self._get_client()
        try:
            resp = kms.sign(
                KeyId=self._kms_key_id,
                Message=_canonical(payload),
                MessageType="RAW",
                SigningAlgorithm=self.SIGNING_ALGORITHM,
            )
        except Exception as exc:
            logger.error("KMS sign failed for key_id=%s: %s", self._key_id, exc)
            raise TrustSignerError(f"kms_sign_failed:{exc}") from exc
        signature = resp.get("Signature")
        if not signature:
            raise TrustSignerError("kms_sign_returned_empty_signature")
        return SignResult(
            signature=_b64url_encode(signature),
            algorithm=self._algorithm,
            key_id=self._key_id,
        )

    def verify(self, payload: dict[str, Any], signature: str) -> bool:
        kms = self._get_client()
        try:
            resp = kms.verify(
                KeyId=self._kms_key_id,
                Message=_canonical(payload),
                MessageType="RAW",
                Signature=_b64url_decode(signature),
                SigningAlgorithm=self.SIGNING_ALGORITHM,
            )
            return bool(resp.get("SignatureValid"))
        except Exception as exc:
            # KMS raises on signature mismatch; treat as a verify failure.
            logger.debug("KMS verify failed for key_id=%s: %s", self._key_id, exc)
            return False


class CloudHSMTrustSigner(AWSKMSTrustSigner):
    """
    CloudHSM-backed signer for FIPS 140-2 Level 3 deployments (IL5/IL6).

    Operationally identical to AWSKMSTrustSigner but the underlying KMS CMK
    must be provisioned in a CloudHSM Custom Key Store
    (https://docs.aws.amazon.com/kms/latest/developerguide/keystore-cloudhsm.html).
    The CMK type is ``CustomerManagedKey`` with ``Origin=AWS_CLOUDHSM`` and
    ``CustomKeyStoreId`` pointing at a CloudHSM cluster — KMS proxies the
    sign/verify call into the HSM cluster, where the private key never leaves
    the FIPS 140-2 Level 3 boundary.

    The ``algorithm`` field on issued ``SignResult``s carries a ``+CHSM``
    suffix (e.g. ``RS256+CHSM``) so downstream auditors and the cert
    transparency log can identify FIPS-3-issued certificates from FIPS-2 ones.
    """

    ALGORITHM_LABEL = "RS256+CHSM"


@dataclass
class KeyConfig:
    key_id: str
    algorithm: str
    backend: str
    kms_key_id: str | None = None
    region_name: str | None = None


def _resolve_kms_key_id() -> str | None:
    """Look up KMS key id from either the TokenDNA-specific or AWS-standard env var."""
    return (
        os.getenv("ATTESTATION_KMS_KEY_ID", "").strip()
        or os.getenv("AWS_KMS_KEY_ID", "").strip()
        or None
    )


def _default_key_config(algorithm: str) -> KeyConfig:
    alg = (algorithm or "HS256").upper()
    return KeyConfig(
        key_id=os.getenv("ATTESTATION_CA_KEY_ID", "tokendna-ca-default"),
        algorithm=alg,
        backend=os.getenv("ATTESTATION_KEY_BACKEND", "software").lower(),
        kms_key_id=_resolve_kms_key_id(),
        region_name=os.getenv("ATTESTATION_AWS_REGION") or os.getenv("AWS_REGION"),
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
                region_name=(str(item.get("region_name", "")).strip() or None),
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
    preferred_alg = (cfg.algorithm or "HS256").upper()
    backend = cfg.backend

    # ── Hardware-backed signers ───────────────────────────────────────────
    if backend in ("aws_kms", "cloudhsm"):
        kms_key_id = cfg.kms_key_id or _resolve_kms_key_id()
        if kms_key_id:
            cls = CloudHSMTrustSigner if backend == "cloudhsm" else AWSKMSTrustSigner
            return cls(
                kms_key_id=kms_key_id,
                key_id=key_id,
                region_name=cfg.region_name,
            )
        logger.warning(
            "ATTESTATION_KEY_BACKEND=%s but no KMS key id available "
            "(set AWS_KMS_KEY_ID or ATTESTATION_KMS_KEY_ID, or include "
            "kms_key_id in the keyring entry); falling back to software backend.",
            backend,
        )
        backend = "software"

    # ── Software signers (HS256 / RS256) ─────────────────────────────────
    if preferred_alg == "RS256":
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


# ── Key rotation helpers ──────────────────────────────────────────────────────


def _serialize_keyring(keyring: dict[str, KeyConfig]) -> str:
    """Serialize a keyring dict back to the JSON shape used by ATTESTATION_KEYRING_JSON."""
    out = []
    for cfg in keyring.values():
        entry: dict[str, Any] = {
            "key_id": cfg.key_id,
            "algorithm": cfg.algorithm,
            "backend": cfg.backend,
        }
        if cfg.kms_key_id:
            entry["kms_key_id"] = cfg.kms_key_id
        if cfg.region_name:
            entry["region_name"] = cfg.region_name
        out.append(entry)
    return json.dumps(out, separators=(",", ":"))


def rotate_active_key(
    new_key_id: str,
    *,
    algorithm: str = "RS256",
    backend: str = "aws_kms",
    kms_key_id: str | None = None,
    region_name: str | None = None,
    apply: bool = True,
) -> dict[str, str]:
    """
    Add ``new_key_id`` to the keyring and (when ``apply=True``) flip the
    active pointer so subsequent issuance uses the new key.

    Existing certificates remain verifiable as long as their ``ca_key_id``
    entry stays in the keyring — this helper never removes entries.

    Returns a dict with the previous active key id and the new active key id,
    plus the updated keyring JSON (caller is responsible for persisting it
    to the secret store / env / config-management system that backs the
    process's environment variables).

    Set ``apply=False`` to compute the rotation plan without actually
    mutating ``os.environ`` — useful when integrating with an external
    secret manager that handles the env update out-of-band.
    """
    keyring = _load_keyring()
    previous_active = os.getenv("ATTESTATION_ACTIVE_KEY_ID", "").strip() or None

    if new_key_id in keyring:
        raise TrustSignerError(
            f"key_id_already_in_keyring:{new_key_id}; rotation must use a fresh id"
        )

    keyring[new_key_id] = KeyConfig(
        key_id=new_key_id,
        algorithm=algorithm.upper(),
        backend=backend.lower(),
        kms_key_id=kms_key_id,
        region_name=region_name,
    )
    serialized = _serialize_keyring(keyring)

    if apply:
        os.environ["ATTESTATION_KEYRING_JSON"] = serialized
        os.environ["ATTESTATION_ACTIVE_KEY_ID"] = new_key_id

    return {
        "previous_active_key_id": previous_active or "",
        "new_active_key_id": new_key_id,
        "keyring_json": serialized,
        "applied": str(bool(apply)).lower(),
    }

