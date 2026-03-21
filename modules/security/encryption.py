"""
TokenDNA — Encryption at Rest  (v2.8.0)
========================================
Field-level, envelope encryption for all sensitive data stored in ClickHouse,
SQLite (tenant store), and Redis (baseline profiles, rate counters).

Architecture
------------
Envelope encryption pattern (standard for IL4/IL5):

  1. Each plaintext value is encrypted with a unique 256-bit Data Encryption
     Key (DEK) using AES-256-GCM.
  2. The DEK itself is wrapped (encrypted) by a Key Encryption Key (KEK)
     sourced from a configurable key provider.
  3. The ciphertext blob stored in the DB contains:
       - IV (12 bytes) | auth tag (16 bytes) | ciphertext | wrapped DEK

Key Providers (priority order):
  1. AWS KMS  — ENC_PROVIDER=aws   + ENC_KMS_KEY_ID (ARN or alias)
  2. Azure Key Vault — ENC_PROVIDER=azure + ENC_AZURE_VAULT_URL + ENC_AZURE_KEY_NAME
  3. HashiCorp Vault — ENC_PROVIDER=vault + VAULT_ADDR + VAULT_TOKEN + ENC_VAULT_KEY
  4. Local env var   — ENC_PROVIDER=env   + ENC_MASTER_KEY (32-byte hex; DEV ONLY)

NIST 800-53 Rev5 Controls
-------------------------
  SC-28    Protection of Information at Rest
  SC-28(1) Cryptographic Protection (AES-256-GCM, FIPS 140-2)
  SC-12    Cryptographic Key Establishment and Management
  SC-12(1) Availability (envelope encryption with KMS-managed KEK)
  SC-17    Public Key Infrastructure Certificates (KMS key policy)
  AU-9(3)  Protection of Audit Information (audit log fields encrypted)
  CM-6     Configuration Settings (key IDs stored, not key material)

DISA STIG References
--------------------
  SRG-APP-000231  Protection of information at rest
  SRG-APP-000514  Use of FIPS-validated cryptography
  SRG-APP-000516  Encryption of sensitive configuration data

Usage
-----
    from modules.security.encryption import encrypt_field, decrypt_field, EncryptedColumn

    # Direct use (returns base64-encoded ciphertext blob)
    ciphertext = encrypt_field("user@agency.mil")
    plaintext  = decrypt_field(ciphertext)

    # SQLite column wrapper (transparent encode/decode)
    class Tenant(Base):
        email = EncryptedColumn()

    # ClickHouse insertion (encrypt before write)
    row = {"uid": uid, "ip": encrypt_field(ip), "ua": encrypt_field(ua)}

    # Batch key rotation (re-encrypts all values under new DEK/KEK)
    from modules.security.encryption import KeyRotator
    rotator = KeyRotator()
    count   = rotator.rotate_table("sessions", ["ip", "ua", "email"])
"""

from __future__ import annotations

import base64
import logging
import os
import secrets
import struct
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────

ENC_PROVIDER        = os.getenv("ENC_PROVIDER", "env").lower()
ENC_KMS_KEY_ID      = os.getenv("ENC_KMS_KEY_ID", "")
ENC_AZURE_VAULT_URL = os.getenv("ENC_AZURE_VAULT_URL", "")
ENC_AZURE_KEY_NAME  = os.getenv("ENC_AZURE_KEY_NAME", "")
ENC_VAULT_KEY       = os.getenv("ENC_VAULT_KEY", "tokendna/encryption")
ENC_MASTER_KEY_HEX  = os.getenv("ENC_MASTER_KEY", "")  # 64-char hex = 32 bytes

# Blob format version tag (1 byte) — allows future format migration
_BLOB_VERSION = b"\x01"
# AES-GCM nonce size and tag size (standard)
_IV_SIZE      = 12
_TAG_SIZE     = 16
# DEK size
_DEK_SIZE     = 32  # 256-bit

# Sentinel for null/None values (encrypted form of empty)
_NULL_SENTINEL = b""


class EncryptionError(RuntimeError):
    """Raised when encryption / decryption fails."""


class KeyProviderError(EncryptionError):
    """Raised when the key provider is unavailable or returns an error."""


# ── Key provider abstraction ───────────────────────────────────────────────────

class _KeyProvider:
    """Abstract key provider interface."""

    def wrap_dek(self, dek: bytes) -> bytes:
        """Encrypt (wrap) a 32-byte DEK with the KEK. Returns opaque wrapped bytes."""
        raise NotImplementedError

    def unwrap_dek(self, wrapped: bytes) -> bytes:
        """Decrypt (unwrap) a wrapped DEK. Returns 32-byte plaintext DEK."""
        raise NotImplementedError

    def provider_name(self) -> str:
        raise NotImplementedError


class _EnvKeyProvider(_KeyProvider):
    """
    Local master key provider — reads ENC_MASTER_KEY from environment.

    DEVELOPMENT / EMERGENCY FALLBACK ONLY.
    Not suitable for production: key material in env var is readable by any
    process on the host. Use AWS KMS or Vault for production.
    """

    def __init__(self) -> None:
        hex_key = ENC_MASTER_KEY_HEX
        if not hex_key:
            # Generate an ephemeral key for this process lifetime (not persistent)
            logger.warning(
                "ENC_MASTER_KEY not set — using ephemeral key. "
                "Data encrypted this session CANNOT be decrypted after restart. "
                "Set ENC_MASTER_KEY=<64-char hex> for production."
            )
            self._kek = secrets.token_bytes(_DEK_SIZE)
        else:
            try:
                self._kek = bytes.fromhex(hex_key)
                if len(self._kek) != _DEK_SIZE:
                    raise ValueError(f"ENC_MASTER_KEY must be 64 hex chars (32 bytes), got {len(self._kek)}")
            except ValueError as exc:
                raise KeyProviderError(f"Invalid ENC_MASTER_KEY: {exc}") from exc

    def wrap_dek(self, dek: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        iv = secrets.token_bytes(_IV_SIZE)
        aes = AESGCM(self._kek)
        wrapped_body = aes.encrypt(iv, dek, None)  # wrapped_body = ciphertext + tag
        return iv + wrapped_body

    def unwrap_dek(self, wrapped: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        iv, wrapped_body = wrapped[:_IV_SIZE], wrapped[_IV_SIZE:]
        aes = AESGCM(self._kek)
        try:
            return aes.decrypt(iv, wrapped_body, None)
        except Exception as exc:
            raise EncryptionError(f"DEK unwrap failed (env provider): {exc}") from exc

    def provider_name(self) -> str:
        return "env"


class _AWSKMSProvider(_KeyProvider):
    """
    AWS KMS key provider — uses boto3 GenerateDataKey + Decrypt.

    Requires:
      ENC_KMS_KEY_ID = arn:aws:kms:<region>:<account>:key/<uuid>
                     | alias/<alias-name>
      Standard AWS credential chain (IAM role, env vars, instance profile)
    """

    def __init__(self) -> None:
        if not ENC_KMS_KEY_ID:
            raise KeyProviderError("ENC_KMS_KEY_ID must be set for AWS KMS provider")
        try:
            import boto3
            self._kms = boto3.client("kms")
            self._key_id = ENC_KMS_KEY_ID
        except ImportError:
            raise KeyProviderError("boto3 not installed — run: pip install boto3")

    def wrap_dek(self, dek: bytes) -> bytes:
        """Encrypt DEK using KMS Encrypt (caller-provided plaintext)."""
        try:
            resp = self._kms.encrypt(KeyId=self._key_id, Plaintext=dek)
            return resp["CiphertextBlob"]
        except Exception as exc:
            raise KeyProviderError(f"KMS Encrypt failed: {exc}") from exc

    def unwrap_dek(self, wrapped: bytes) -> bytes:
        """Decrypt KMS-wrapped DEK."""
        try:
            resp = self._kms.decrypt(KeyId=self._key_id, CiphertextBlob=wrapped)
            return resp["Plaintext"]
        except Exception as exc:
            raise KeyProviderError(f"KMS Decrypt failed: {exc}") from exc

    def provider_name(self) -> str:
        return f"aws-kms:{self._key_id}"


class _AzureKeyVaultProvider(_KeyProvider):
    """
    Azure Key Vault key provider — uses WRAP/UNWRAP with RSA-OAEP or AES-256.

    Requires:
      ENC_AZURE_VAULT_URL  = https://<vault-name>.vault.azure.net
      ENC_AZURE_KEY_NAME   = <key-name>
      Standard Azure DefaultAzureCredential (managed identity, env, CLI)
    """

    def __init__(self) -> None:
        if not ENC_AZURE_VAULT_URL or not ENC_AZURE_KEY_NAME:
            raise KeyProviderError("ENC_AZURE_VAULT_URL and ENC_AZURE_KEY_NAME required for Azure provider")
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.keys.crypto import CryptographyClient, KeyWrapAlgorithm
            credential = DefaultAzureCredential()
            from azure.keyvault.keys import KeyClient
            key_client = KeyClient(vault_url=ENC_AZURE_VAULT_URL, credential=credential)
            key = key_client.get_key(ENC_AZURE_KEY_NAME)
            self._crypto = CryptographyClient(key, credential=credential)
            self._algo = KeyWrapAlgorithm.aes_256  # AES-256 key wrap
        except ImportError:
            raise KeyProviderError(
                "azure-keyvault-keys and azure-identity not installed. "
                "Run: pip install azure-keyvault-keys azure-identity"
            )

    def wrap_dek(self, dek: bytes) -> bytes:
        try:
            result = self._crypto.wrap_key(self._algo, dek)
            return result.encrypted_key
        except Exception as exc:
            raise KeyProviderError(f"Azure Key Vault wrap failed: {exc}") from exc

    def unwrap_dek(self, wrapped: bytes) -> bytes:
        try:
            result = self._crypto.unwrap_key(self._algo, wrapped)
            return result.key
        except Exception as exc:
            raise KeyProviderError(f"Azure Key Vault unwrap failed: {exc}") from exc

    def provider_name(self) -> str:
        return f"azure-kv:{ENC_AZURE_VAULT_URL}/{ENC_AZURE_KEY_NAME}"


class _HashiCorpVaultProvider(_KeyProvider):
    """
    HashiCorp Vault Transit key provider — uses transit/encrypt and transit/decrypt.

    Requires:
      VAULT_ADDR   = https://vault.yourdomain.mil
      VAULT_TOKEN  = s.xxxxx  (or use VAULT_ROLE_ID / VAULT_SECRET_ID for AppRole)
      ENC_VAULT_KEY = transit key name (default: "tokendna/encryption")
    """

    def __init__(self) -> None:
        self._addr  = os.getenv("VAULT_ADDR", "https://127.0.0.1:8200")
        self._token = os.getenv("VAULT_TOKEN", "")
        self._key   = ENC_VAULT_KEY
        if not self._token:
            role_id   = os.getenv("VAULT_ROLE_ID", "")
            secret_id = os.getenv("VAULT_SECRET_ID", "")
            if role_id and secret_id:
                self._token = self._approle_login(role_id, secret_id)
            else:
                raise KeyProviderError(
                    "Vault provider requires VAULT_TOKEN or (VAULT_ROLE_ID + VAULT_SECRET_ID)"
                )
        try:
            import requests as _req
            self._req = _req
        except ImportError:
            raise KeyProviderError("requests not installed — run: pip install requests")

    def _approle_login(self, role_id: str, secret_id: str) -> str:
        import requests as _req
        resp = _req.post(
            f"{self._addr}/v1/auth/approle/login",
            json={"role_id": role_id, "secret_id": secret_id},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()["auth"]["client_token"]

    def _headers(self) -> dict[str, str]:
        return {"X-Vault-Token": self._token}

    def wrap_dek(self, dek: bytes) -> bytes:
        plaintext_b64 = base64.b64encode(dek).decode()
        resp = self._req.post(
            f"{self._addr}/v1/transit/encrypt/{self._key}",
            json={"plaintext": plaintext_b64},
            headers=self._headers(),
            timeout=10,
        )
        if resp.status_code != 200:
            raise KeyProviderError(f"Vault encrypt failed: {resp.status_code} {resp.text}")
        # Return ciphertext as UTF-8 bytes (vault:v1:xxx format)
        return resp.json()["data"]["ciphertext"].encode()

    def unwrap_dek(self, wrapped: bytes) -> bytes:
        resp = self._req.post(
            f"{self._addr}/v1/transit/decrypt/{self._key}",
            json={"ciphertext": wrapped.decode()},
            headers=self._headers(),
            timeout=10,
        )
        if resp.status_code != 200:
            raise KeyProviderError(f"Vault decrypt failed: {resp.status_code} {resp.text}")
        return base64.b64decode(resp.json()["data"]["plaintext"])

    def provider_name(self) -> str:
        return f"vault:{self._addr}/transit/{self._key}"


# ── Provider factory ───────────────────────────────────────────────────────────

_provider_cache: Optional[_KeyProvider] = None


def _get_provider() -> _KeyProvider:
    """Return the configured key provider (singleton, thread-safe for reads)."""
    global _provider_cache
    if _provider_cache is not None:
        return _provider_cache

    provider_map: dict[str, type[_KeyProvider]] = {
        "aws":   _AWSKMSProvider,
        "azure": _AzureKeyVaultProvider,
        "vault": _HashiCorpVaultProvider,
        "env":   _EnvKeyProvider,
    }

    cls = provider_map.get(ENC_PROVIDER)
    if cls is None:
        raise KeyProviderError(
            f"Unknown ENC_PROVIDER={ENC_PROVIDER!r}. "
            "Valid options: aws, azure, vault, env"
        )

    try:
        _provider_cache = cls()
        logger.info("Encryption at rest: provider=%s", _provider_cache.provider_name())
    except KeyProviderError:
        logger.warning(
            "Encryption provider '%s' failed to initialize — falling back to 'env' provider",
            ENC_PROVIDER,
        )
        _provider_cache = _EnvKeyProvider()

    return _provider_cache


# ── Core encrypt / decrypt ────────────────────────────────────────────────────

@dataclass
class _EncBlob:
    """
    Parsed encryption blob layout:

      [version:1][iv:12][wrapped_dek_len:4][wrapped_dek:N][ciphertext_with_tag:M]

    AES-GCM includes the 16-byte auth tag appended to ciphertext by cryptography lib.
    """
    version:     bytes
    iv:          bytes
    wrapped_dek: bytes
    ciphertext:  bytes  # includes GCM auth tag (last 16 bytes)


def _pack_blob(iv: bytes, wrapped_dek: bytes, ciphertext: bytes) -> bytes:
    """Serialize an encryption blob to bytes."""
    wrapped_len = len(wrapped_dek)
    header = _BLOB_VERSION + iv + struct.pack(">I", wrapped_len)
    return header + wrapped_dek + ciphertext


def _unpack_blob(blob: bytes) -> _EncBlob:
    """Deserialize an encryption blob. Raises EncryptionError on bad format."""
    if len(blob) < 1 + _IV_SIZE + 4:
        raise EncryptionError("Ciphertext blob too short to be valid")
    version  = blob[:1]
    if version != _BLOB_VERSION:
        raise EncryptionError(f"Unsupported blob version: {version!r}")
    iv       = blob[1: 1 + _IV_SIZE]
    wlen,    = struct.unpack(">I", blob[1 + _IV_SIZE: 1 + _IV_SIZE + 4])
    offset   = 1 + _IV_SIZE + 4
    if len(blob) < offset + wlen + _TAG_SIZE:
        raise EncryptionError("Ciphertext blob truncated (wrapped_dek + ciphertext too short)")
    wrapped_dek = blob[offset: offset + wlen]
    ciphertext  = blob[offset + wlen:]
    return _EncBlob(version=version, iv=iv, wrapped_dek=wrapped_dek, ciphertext=ciphertext)


def encrypt_field(plaintext: Optional[str], context: Optional[bytes] = None) -> str:
    """
    Encrypt a plaintext string value using AES-256-GCM with envelope encryption.

    Args:
        plaintext: The string to encrypt. None → returns empty string.
        context:   Optional authenticated additional data (AAD) bound to this
                   ciphertext — used for context-binding (e.g., tenant_id bytes).
                   Decryption must provide the same context.

    Returns:
        Base64url-encoded ciphertext blob (safe for storage in any string column).

    Raises:
        EncryptionError: if encryption fails.
    """
    if plaintext is None:
        return ""

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    provider = _get_provider()

    # 1. Generate a fresh 256-bit DEK for this record
    dek = secrets.token_bytes(_DEK_SIZE)

    # 2. Encrypt plaintext with DEK (AES-256-GCM)
    iv  = secrets.token_bytes(_IV_SIZE)
    aes = AESGCM(dek)
    ciphertext = aes.encrypt(iv, plaintext.encode("utf-8"), context)

    # 3. Wrap DEK with KEK (provider-specific)
    wrapped_dek = provider.wrap_dek(dek)

    # 4. Pack and base64url-encode the blob
    blob = _pack_blob(iv, wrapped_dek, ciphertext)
    return base64.urlsafe_b64encode(blob).decode("ascii")


def decrypt_field(ciphertext_b64: Optional[str], context: Optional[bytes] = None) -> Optional[str]:
    """
    Decrypt a ciphertext blob produced by encrypt_field().

    Args:
        ciphertext_b64: Base64url-encoded blob from encrypt_field(). Empty/None → None.
        context:        Must match the context passed to encrypt_field().

    Returns:
        Decrypted plaintext string, or None if input was empty.

    Raises:
        EncryptionError: if decryption or authentication fails.
    """
    if not ciphertext_b64:
        return None

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    provider = _get_provider()

    try:
        blob_bytes = base64.urlsafe_b64decode(ciphertext_b64 + "==")
    except Exception as exc:
        raise EncryptionError(f"Failed to base64-decode ciphertext: {exc}") from exc

    blob = _unpack_blob(blob_bytes)

    # 1. Unwrap DEK using the provider (KMS / Vault / env)
    dek = provider.unwrap_dek(blob.wrapped_dek)

    # 2. Decrypt plaintext with DEK
    aes = AESGCM(dek)
    try:
        plaintext_bytes = aes.decrypt(blob.iv, blob.ciphertext, context)
    except Exception as exc:
        raise EncryptionError(
            f"AES-GCM decryption failed (authentication tag mismatch or corrupt data): {exc}"
        ) from exc

    return plaintext_bytes.decode("utf-8")


def is_encrypted(value: str) -> bool:
    """
    Heuristic check whether a string value appears to be an encrypt_field() blob.

    Uses blob version byte after base64 decode. Non-destructive; returns False
    if the value is plaintext or cannot be decoded.
    """
    if not value:
        return False
    try:
        raw = base64.urlsafe_b64decode(value + "==")
        return raw[:1] == _BLOB_VERSION and len(raw) > 1 + _IV_SIZE + 4
    except Exception:
        return False


# ── EncryptedColumn — transparent SQLAlchemy / SQLite column wrapper ───────────

class EncryptedColumn:
    """
    Descriptor that transparently encrypts on set and decrypts on get.

    Usage (plain-Python dataclass style; does not require SQLAlchemy):

        class TenantRecord:
            def __init__(self):
                self.email = EncryptedColumn()

        t = TenantRecord()
        t.email = "ryan@agency.mil"  # stored encrypted
        print(t.email)               # returns plaintext

    For SQLAlchemy TypeDecorator integration, see EncryptedType below.
    """

    def __set_name__(self, owner: type, name: str) -> None:
        self._attr = f"_enc_{name}"

    def __get__(self, obj: Any, objtype: Any = None) -> Optional[str]:
        if obj is None:
            return self  # type: ignore
        raw = getattr(obj, self._attr, None)
        if raw is None:
            return None
        if is_encrypted(raw):
            try:
                return decrypt_field(raw)
            except EncryptionError as exc:
                logger.error("EncryptedColumn decrypt failed: %s", exc)
                return None
        return raw  # fallback: return raw value if not encrypted (migration path)

    def __set__(self, obj: Any, value: Optional[str]) -> None:
        if value is None:
            setattr(obj, self._attr, None)
        else:
            setattr(obj, self._attr, encrypt_field(value))


# ── EncryptedType — SQLAlchemy TypeDecorator ──────────────────────────────────

def make_encrypted_type() -> Any:
    """
    Return a SQLAlchemy TypeDecorator that transparently encrypts/decrypts.

    Requires SQLAlchemy. If not installed, returns None.

    Usage:
        from sqlalchemy import Column
        EncryptedType = make_encrypted_type()

        class User(Base):
            __tablename__ = "users"
            email = Column(EncryptedType())
    """
    try:
        from sqlalchemy import String
        from sqlalchemy.types import TypeDecorator

        class _EncryptedString(TypeDecorator):
            impl = String
            cache_ok = True

            def process_bind_param(self, value: Optional[str], dialect: Any) -> Optional[str]:
                if value is None:
                    return None
                return encrypt_field(value)

            def process_result_value(self, value: Optional[str], dialect: Any) -> Optional[str]:
                if value is None:
                    return None
                if is_encrypted(value):
                    return decrypt_field(value)
                return value  # migration: return plaintext if not yet encrypted

        return _EncryptedString

    except ImportError:
        return None


# ── Key rotation ───────────────────────────────────────────────────────────────

class KeyRotator:
    """
    Re-encrypts stored ciphertext blobs under a new DEK (and optionally new KEK).

    Key rotation workflow (SC-12, SC-12(1)):
      1. New KMS key / Vault key version configured
      2. KeyRotator.rotate_values() re-encrypts each blob:
         decrypt with old provider → plaintext → encrypt with new provider
      3. Rotation is idempotent — safe to re-run on failure
      4. Rotation count and errors logged for audit (AU-2)

    For ClickHouse tables, use rotate_clickhouse() (pulls batches, re-encrypts in-process).
    For SQLite tenant store, use rotate_sqlite().
    """

    def __init__(
        self,
        old_provider: Optional[_KeyProvider] = None,
        new_provider: Optional[_KeyProvider] = None,
    ):
        # Default: use configured provider for both (rotates DEK only, same KEK)
        self._old = old_provider or _get_provider()
        self._new = new_provider or _get_provider()

    def rotate_value(self, ciphertext_b64: str, context: Optional[bytes] = None) -> str:
        """
        Decrypt with old provider, re-encrypt with new provider.
        Returns new ciphertext blob (base64url).
        """
        plaintext = self._decrypt_with(ciphertext_b64, self._old, context)
        return self._encrypt_with(plaintext, self._new, context)

    @staticmethod
    def _decrypt_with(
        ciphertext_b64: str,
        provider: _KeyProvider,
        context: Optional[bytes],
    ) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        blob_bytes = base64.urlsafe_b64decode(ciphertext_b64 + "==")
        blob = _unpack_blob(blob_bytes)
        dek  = provider.unwrap_dek(blob.wrapped_dek)
        aes  = AESGCM(dek)
        plaintext_bytes = aes.decrypt(blob.iv, blob.ciphertext, context)
        return plaintext_bytes.decode("utf-8")

    @staticmethod
    def _encrypt_with(
        plaintext: str,
        provider: _KeyProvider,
        context: Optional[bytes],
    ) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        dek        = secrets.token_bytes(_DEK_SIZE)
        iv         = secrets.token_bytes(_IV_SIZE)
        aes        = AESGCM(dek)
        ciphertext = aes.encrypt(iv, plaintext.encode("utf-8"), context)
        wrapped_dek = provider.wrap_dek(dek)
        blob        = _pack_blob(iv, wrapped_dek, ciphertext)
        return base64.urlsafe_b64encode(blob).decode("ascii")

    def rotate_values(
        self,
        values: list[str],
        context: Optional[bytes] = None,
    ) -> tuple[list[str], int]:
        """
        Rotate a list of ciphertext values. Returns (rotated_list, error_count).
        Non-encrypted values (plaintext in DB before encryption was enabled) are
        re-encrypted on first encounter.
        """
        rotated: list[str] = []
        errors = 0
        for val in values:
            if not val:
                rotated.append(val)
                continue
            try:
                if is_encrypted(val):
                    rotated.append(self.rotate_value(val, context))
                else:
                    # Plaintext column not yet encrypted — encrypt now
                    rotated.append(encrypt_field(val, context))
            except EncryptionError as exc:
                logger.error("KeyRotator: rotation failed for value (truncated): %s — %s",
                             val[:20], exc)
                errors += 1
                rotated.append(val)  # keep old value on failure
        return rotated, errors

    def rotate_clickhouse(
        self,
        table: str,
        columns: list[str],
        batch_size: int = 1000,
    ) -> dict[str, Any]:
        """
        Rotate encrypted columns in a ClickHouse table.

        Reads rows in batches, re-encrypts all specified columns,
        and inserts replacement rows. (ClickHouse is append-only;
        uses ALTER TABLE DELETE to remove old rows after replacement.)

        Returns: {"rotated": N, "errors": M, "batches": K}
        """
        try:
            from modules.identity import clickhouse_client as _ch
        except ImportError:
            return {"error": "ClickHouse client not available"}

        if not _ch.is_available():
            return {"error": "ClickHouse unreachable"}

        total_rotated = 0
        total_errors  = 0
        batches       = 0
        offset        = 0

        while True:
            try:
                col_list = ", ".join(["rowid", *columns])
                rows = _ch.query(
                    f"SELECT {col_list} FROM {table} LIMIT {batch_size} OFFSET {offset}"
                )
            except Exception as exc:
                logger.error("KeyRotator ClickHouse query error: %s", exc)
                break

            if not rows:
                break

            for row in rows:
                row_id = row.get("rowid")
                updates: dict[str, str] = {}
                for col in columns:
                    old_val = row.get(col, "")
                    if not old_val:
                        continue
                    try:
                        if is_encrypted(old_val):
                            updates[col] = self.rotate_value(old_val)
                            total_rotated += 1
                        else:
                            updates[col] = encrypt_field(old_val)
                            total_rotated += 1
                    except EncryptionError as exc:
                        logger.error("KeyRotator column %s row %s: %s", col, row_id, exc)
                        total_errors += 1

                if updates and row_id:
                    try:
                        set_clause = ", ".join(f"{k}=%(v_{k})s" for k in updates)
                        params     = {f"v_{k}": v for k, v in updates.items()}
                        _ch.execute(
                            f"ALTER TABLE {table} UPDATE {set_clause} WHERE rowid=%(rowid)s",
                            {**params, "rowid": row_id},
                        )
                    except Exception as exc:
                        logger.error("KeyRotator ClickHouse update error: %s", exc)
                        total_errors += 1

            batches += 1
            offset  += batch_size
            if len(rows) < batch_size:
                break

        result = {"rotated": total_rotated, "errors": total_errors, "batches": batches}
        logger.info("KeyRotator ClickHouse rotation complete: %s", result)
        return result


# ── Startup check ──────────────────────────────────────────────────────────────

def check_encryption_config() -> dict[str, Any]:
    """
    Validate encryption-at-rest configuration at startup.

    Returns a summary dict for the startup audit event.
    Non-fatal: warns on misconfiguration but does not raise.
    """
    summary: dict[str, Any] = {
        "provider":    ENC_PROVIDER,
        "kms_key_set": bool(ENC_KMS_KEY_ID),
        "vault_key":   ENC_VAULT_KEY,
        "master_key_set": bool(ENC_MASTER_KEY_HEX),
    }

    if ENC_PROVIDER == "env":
        if ENC_MASTER_KEY_HEX:
            logger.info("Encryption at rest: provider=env (ENC_MASTER_KEY set)")
        else:
            logger.warning(
                "Encryption at rest: provider=env with EPHEMERAL key. "
                "Set ENC_MASTER_KEY (64-char hex) or use ENC_PROVIDER=aws|azure|vault "
                "for production IL4/IL5 deployments (SC-28 / SRG-APP-000231)."
            )
    elif ENC_PROVIDER == "aws":
        if not ENC_KMS_KEY_ID:
            logger.warning("Encryption at rest: ENC_PROVIDER=aws but ENC_KMS_KEY_ID not set")
        else:
            logger.info("Encryption at rest: provider=aws-kms key=%s", ENC_KMS_KEY_ID)
    elif ENC_PROVIDER == "azure":
        if not ENC_AZURE_VAULT_URL:
            logger.warning("Encryption at rest: ENC_PROVIDER=azure but ENC_AZURE_VAULT_URL not set")
        else:
            logger.info("Encryption at rest: provider=azure-kv vault=%s key=%s",
                        ENC_AZURE_VAULT_URL, ENC_AZURE_KEY_NAME)
    elif ENC_PROVIDER == "vault":
        vault_addr = os.getenv("VAULT_ADDR", "")
        if not vault_addr:
            logger.warning("Encryption at rest: ENC_PROVIDER=vault but VAULT_ADDR not set")
        else:
            logger.info("Encryption at rest: provider=vault addr=%s key=%s",
                        vault_addr, ENC_VAULT_KEY)

    # Warm up provider connection (fails gracefully)
    try:
        _get_provider()
        summary["provider_ready"] = True
    except Exception as exc:
        logger.error("Encryption at rest: provider initialization failed: %s", exc)
        summary["provider_ready"] = False

    return summary
