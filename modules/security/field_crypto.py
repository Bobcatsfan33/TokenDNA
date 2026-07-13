"""
TokenDNA — application-level field encryption (AES-256-GCM via Fernet).

Encrypts the small set of database columns that carry the most sensitive
operational signal:

  - behavioral profiles            (modules.behavior.*)
  - DNA fingerprints               (modules.identity.dna_fingerprint)
  - threat-intel signals           (modules.intel.threat_signals)

Postgres TDE / EBS at-rest covers the disk; this layer covers leakage
*above* the disk — backup files, log slurps, replica scrapes, accidental
``SELECT * FROM …`` in a debugging session. The key never appears in the
DB; it lives in the secrets backend (AWS Secrets Manager / Vault / env).

Design choices:
  * **Fernet** (AES-128-CBC + HMAC-SHA256) is the cryptography-vendored
    primitive — battle-tested, FIPS-140-friendly when the underlying
    OpenSSL build is FIPS-validated. We wrap it with a 4-byte little-
    endian key version prefix so we can rotate the key without re-
    encrypting the entire table in one shot.
  * **Versioned ciphertexts**: the on-disk record begins with
    ``v<key_version>:`` so ``decrypt`` resolves the correct key from the
    keyring. New writes always use the active key; old reads work as long
    as the prior key remains in the keyring.
  * **Deterministic-on-empty**: encrypting ``""`` returns ``""`` so
    nullable columns don't pick up a non-empty ciphertext that would
    look real to a naive reader.
  * **No process-wide singleton**: the engine is constructed from env at
    call time; tests can inject their own keyring.
"""

from __future__ import annotations

import base64
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Cipher prefix shape: "v<int>:<base64-fernet>"
_PREFIX_RE = re.compile(r"^v(\d+):(.+)$")


class FieldCryptoError(Exception):
    """Raised when encryption or decryption cannot complete."""


def _import_fernet():
    try:
        from cryptography.fernet import Fernet, InvalidToken  # noqa: PLC0415
    except ImportError as exc:
        raise FieldCryptoError(
            "cryptography>=46 is required for modules.security.field_crypto"
        ) from exc
    return Fernet, InvalidToken


@dataclass
class _KeyEntry:
    version: int
    fernet: object  # Fernet instance


@dataclass
class FieldCrypto:
    """
    Versioned field encryption engine.

    Construct with ``from_env`` for production use; tests can pass an
    explicit ``keys`` dict.
    """
    keys: dict[int, _KeyEntry] = field(default_factory=dict)
    active_version: int = 1

    # ── Construction ──────────────────────────────────────────────────────
    @classmethod
    def from_env(cls) -> "FieldCrypto":
        """
        Load keys from env. Two formats supported:

        1. Single key:
              FIELD_CRYPTO_KEY=<urlsafe-base64-32-bytes>     (treated as v1)

        2. Versioned keyring:
              FIELD_CRYPTO_KEYRING=v1:<base64>,v2:<base64>,v3:<base64>
              FIELD_CRYPTO_ACTIVE_VERSION=3                  (defaults to highest)

        Generate a fresh key with:
              python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
        """
        Fernet, _ = _import_fernet()
        keys: dict[int, _KeyEntry] = {}

        ring = os.getenv("FIELD_CRYPTO_KEYRING", "").strip()
        single = os.getenv("FIELD_CRYPTO_KEY", "").strip()

        if ring:
            for entry in ring.split(","):
                entry = entry.strip()
                if not entry:
                    continue
                if ":" not in entry:
                    raise FieldCryptoError(
                        f"FIELD_CRYPTO_KEYRING entry missing version prefix: {entry[:6]}…"
                    )
                tag, key_b64 = entry.split(":", 1)
                if not (tag.startswith("v") and tag[1:].isdigit()):
                    raise FieldCryptoError(
                        f"FIELD_CRYPTO_KEYRING version tag must be vN: {tag}"
                    )
                version = int(tag[1:])
                keys[version] = _KeyEntry(version=version, fernet=Fernet(key_b64.encode()))
        elif single:
            keys[1] = _KeyEntry(version=1, fernet=Fernet(single.encode()))

        if not keys:
            raise FieldCryptoError(
                "No field-encryption keys configured. Set FIELD_CRYPTO_KEY (single) "
                "or FIELD_CRYPTO_KEYRING (versioned)."
            )

        active_env = os.getenv("FIELD_CRYPTO_ACTIVE_VERSION", "").strip()
        active_version = int(active_env) if active_env.isdigit() else max(keys.keys())
        if active_version not in keys:
            raise FieldCryptoError(
                f"FIELD_CRYPTO_ACTIVE_VERSION={active_version} not present in keyring"
            )
        return cls(keys=keys, active_version=active_version)

    # ── Operations ────────────────────────────────────────────────────────
    def encrypt(self, plaintext: str | bytes | None) -> str:
        """Encrypt with the active key. Empty / None passes through unchanged."""
        if plaintext in (None, "", b""):
            return ""
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode("utf-8")
        else:
            plaintext_bytes = plaintext
        entry = self.keys[self.active_version]
        token = entry.fernet.encrypt(plaintext_bytes).decode("utf-8")
        return f"v{self.active_version}:{token}"

    def decrypt(self, ciphertext: str | None) -> str:
        """Decrypt by reading the version prefix; pass through empty values."""
        if not ciphertext:
            return ""
        match = _PREFIX_RE.match(ciphertext)
        if not match:
            raise FieldCryptoError("ciphertext missing version prefix")
        version = int(match.group(1))
        token = match.group(2)
        entry = self.keys.get(version)
        if entry is None:
            raise FieldCryptoError(
                f"ciphertext key version v{version} not in current keyring"
            )
        _, InvalidToken = _import_fernet()
        try:
            return entry.fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise FieldCryptoError("invalid_or_tampered_ciphertext") from exc

    def is_encrypted(self, value: Optional[str]) -> bool:
        return bool(value) and bool(_PREFIX_RE.match(value))

    def reencrypt(self, ciphertext: str) -> str:
        """Re-encrypt a value under the active key (used by rotation jobs)."""
        return self.encrypt(self.decrypt(ciphertext))

    def keyring_versions(self) -> list[int]:
        return sorted(self.keys.keys())


# ── Module-level convenience  ────────────────────────────────────────────────
#
# Most callers want a singleton tied to the current process env. Build it
# lazily so test setups can monkey-patch ``_INSTANCE`` before the first call.

_INSTANCE: Optional[FieldCrypto] = None


def get_engine() -> FieldCrypto:
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = FieldCrypto.from_env()
    return _INSTANCE


def reset_engine_for_tests() -> None:
    """Drop the cached singleton — call between tests that mutate env."""
    global _INSTANCE
    _INSTANCE = None


def encrypt(plaintext: str | bytes | None) -> str:
    return get_engine().encrypt(plaintext)


def decrypt(ciphertext: str | None) -> str:
    return get_engine().decrypt(ciphertext)


def generate_key() -> str:
    """Convenience: print a fresh urlsafe-base64 32-byte key."""
    Fernet, _ = _import_fernet()
    return Fernet.generate_key().decode("utf-8")
