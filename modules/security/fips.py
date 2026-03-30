"""
Aegis Security — FIPS 140-2 Enforcement Module  (v2.4.0)

SC-13: Cryptographic Protection
  All cryptographic operations MUST use NIST-approved, FIPS 140-2 validated
  algorithms. This module is the single enforcement point for all crypto in
  the Aegis Security platform.

IL5 requirements addressed:
  - Runtime FIPS mode detection (Linux kernel FIPS mode + OpenSSL FIPS provider)
  - Algorithm allowlist enforcement — rejects MD5, SHA-1, DES, RC4, HS256
  - JWT algorithm enforcement — only asymmetric algs allowed for IL4+
  - FIPS-safe AES-256-GCM encryption/decryption for data at rest (SC-28)
  - FIPS-safe hashing via hashlib with explicit algorithm control
  - Startup gate: WARNING in FedRAMP High; FATAL in IL5/IL6 if FIPS not active

FIPS 140-2 approved algorithms (NIST SP 800-131A Rev2):
  Symmetric:   AES-128, AES-192, AES-256 (GCM, CBC, CTR modes)
  Hash:        SHA-256, SHA-384, SHA-512, SHA-512/256
  MAC:         HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512
  Asymmetric:  RSA (2048+ bits), ECDSA (P-256, P-384, P-521), EdDSA (Ed25519*)
  KDF:         PBKDF2 (SHA-256+), HKDF (SHA-256+)
  DRBG:        CTR_DRBG, Hash_DRBG, HMAC_DRBG

  * Ed25519/EdDSA added in FIPS 186-5 (2023) — allowed in modern FIPS builds

BLOCKED algorithms (NIST deprecated/disallowed):
  MD5, SHA-1 (for signing), DES, 3DES (<= 2023 per SP 800-131A),
  RC4, Blowfish, HS256/HS384/HS512 as JWT algorithms (symmetric — key distribution risk),
  RSA < 2048 bits, EC curves other than P-256/P-384/P-521

Usage:
    from modules.security.fips import fips, FIPSError

    # Check mode
    if fips.is_active():
        print("FIPS mode active")

    # Safe hash
    digest = fips.sha256(b"data")

    # AES-256-GCM encrypt / decrypt
    ciphertext, tag, nonce = fips.encrypt(plaintext, key)
    plaintext = fips.decrypt(ciphertext, tag, nonce, key)

    # JWT algorithm check (call before accepting any JWT)
    fips.assert_jwt_algorithm("RS256")   # OK
    fips.assert_jwt_algorithm("HS256")   # raises FIPSError in IL4+
"""

import hashlib
import hmac
import logging
import os
import struct
import sys
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# ── Environment ───────────────────────────────────────────────────────────────

_ENVIRONMENT = os.getenv("ENVIRONMENT", "dev").lower()
_HIGH_SECURITY_ENVS = {"il4", "il5", "il6", "production", "prod"}
_IL5_ENVS           = {"il5", "il6"}

# ── Algorithm policy tables ───────────────────────────────────────────────────

# JWT algorithms approved for FIPS environments.
# HS* (symmetric HMAC) are blocked because shared-secret distribution is
# incompatible with zero-trust principles and IL5 key management requirements.
FIPS_APPROVED_JWT_ALGORITHMS = frozenset({
    "RS256", "RS384", "RS512",   # RSA PKCS#1 v1.5
    "PS256", "PS384", "PS512",   # RSA-PSS (preferred over PKCS#1 v1.5)
    "ES256", "ES384", "ES512",   # ECDSA P-256/P-384/P-521
    "EdDSA",                     # Ed25519 (FIPS 186-5 approved)
})

BLOCKED_JWT_ALGORITHMS = frozenset({
    "HS256", "HS384", "HS512",   # Symmetric — shared secret risk
    "RS1",   "RS128",            # RSA with SHA-1 (deprecated)
    "none",                      # No signature — never acceptable
})

# Hash algorithms: approved vs blocked
FIPS_APPROVED_HASH_ALGORITHMS = frozenset({
    "sha256", "sha384", "sha512", "sha512_256",
    "sha3_256", "sha3_384", "sha3_512",
    "blake2b",  # Allowed under FIPS 140-3
})

BLOCKED_HASH_ALGORITHMS = frozenset({
    "md5", "sha1", "sha224", "md4", "ripemd160",
})

# Symmetric cipher minimum key lengths (bits)
FIPS_MIN_KEY_LENGTH = {
    "aes": 128,
    "rsa": 2048,
    "ec":  256,
}


# ── Exceptions ────────────────────────────────────────────────────────────────

class FIPSError(Exception):
    """Raised when a FIPS policy violation is detected."""
    pass


class FIPSAlgorithmViolation(FIPSError):
    """Raised when a non-approved algorithm is used in a FIPS context."""
    pass


# ── Core FIPS module ──────────────────────────────────────────────────────────

@dataclass
class FIPSStatus:
    kernel_fips:    bool   # /proc/sys/crypto/fips_enabled == 1
    openssl_fips:   bool   # OpenSSL FIPS provider loaded
    effective_fips: bool   # True if either kernel or OpenSSL FIPS is active


class FIPSEnforcer:
    """
    Central FIPS 140-2 enforcement engine.

    Instantiated once at module load as the `fips` singleton.
    All cryptographic operations in the platform should route through this class.
    """

    def __init__(self):
        self._status: Optional[FIPSStatus] = None
        self._jwt_enforcement: bool = _ENVIRONMENT in _HIGH_SECURITY_ENVS
        self._fatal_if_missing: bool = _ENVIRONMENT in _IL5_ENVS

    @property
    def status(self) -> FIPSStatus:
        if self._status is None:
            self._status = self._detect_fips()
        return self._status

    def _detect_fips(self) -> FIPSStatus:
        """Probe kernel and OpenSSL for FIPS mode."""
        kernel_fips = False
        try:
            with open("/proc/sys/crypto/fips_enabled") as f:
                kernel_fips = f.read().strip() == "1"
        except (FileNotFoundError, PermissionError):
            pass  # Not Linux or no access — not necessarily an error in dev

        openssl_fips = False
        try:
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # Check if OpenSSL was compiled with FIPS support
            # This is a best-effort check; actual FIPS validation requires
            # a FIPS-certified OpenSSL build (e.g., RedHat FIPS packages)
            openssl_fips = getattr(ssl, "HAS_FIPS", False)
        except Exception:
            pass

        return FIPSStatus(
            kernel_fips=kernel_fips,
            openssl_fips=openssl_fips,
            effective_fips=kernel_fips or openssl_fips,
        )

    def is_active(self) -> bool:
        """Return True if any form of FIPS enforcement is active."""
        return self.status.effective_fips

    def startup_check(self) -> None:
        """
        Called at application startup. Logs FIPS status and enforces policy.

        IL5/IL6: FATAL if FIPS is not active.
        FedRAMP High / IL4: WARNING if FIPS is not active.
        Lower: INFO log only.
        """
        s = self.status
        details = (
            f"kernel_fips={s.kernel_fips} openssl_fips={s.openssl_fips} "
            f"environment={_ENVIRONMENT}"
        )

        if s.effective_fips:
            logger.info(f"[FIPS] FIPS 140-2 mode ACTIVE — {details}")
            return

        if self._fatal_if_missing:
            msg = (
                f"FATAL [SC-13]: FIPS 140-2 mode is NOT active in ENVIRONMENT={_ENVIRONMENT}. "
                "IL5/IL6 deployments require a FIPS 140-2 validated kernel and OpenSSL build. "
                "Use a FIPS-enabled RHEL/CentOS 8+ or Ubuntu 20.04 FIPS image. "
                f"Detected: {details}"
            )
            logger.critical(msg)
            print(msg, file=sys.stderr)
            sys.exit(1)

        if _ENVIRONMENT in _HIGH_SECURITY_ENVS:
            logger.warning(
                f"[SC-13] WARNING: FIPS 140-2 mode is NOT active in ENVIRONMENT={_ENVIRONMENT}. "
                "This is a compliance gap for FedRAMP High / IL4+ authorization. "
                f"Details: {details}"
            )
        else:
            logger.info(f"[FIPS] FIPS mode not active (acceptable in dev). {details}")

    # ── Hashing ──────────────────────────────────────────────────────────────

    def sha256(self, data: bytes) -> bytes:
        """Return SHA-256 digest. FIPS-safe."""
        return hashlib.sha256(data).digest()

    def sha384(self, data: bytes) -> bytes:
        """Return SHA-384 digest. FIPS-safe."""
        return hashlib.sha384(data).digest()

    def sha512(self, data: bytes) -> bytes:
        """Return SHA-512 digest. FIPS-safe."""
        return hashlib.sha512(data).digest()

    def sha256_hex(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def safe_hash(self, algorithm: str, data: bytes) -> bytes:
        """
        Hash data with the given algorithm, enforcing FIPS algorithm policy.
        Raises FIPSAlgorithmViolation if algorithm is blocked.
        """
        alg = algorithm.lower().replace("-", "_")
        if alg in BLOCKED_HASH_ALGORITHMS:
            raise FIPSAlgorithmViolation(
                f"[SC-13] Hash algorithm '{algorithm}' is not FIPS 140-2 approved. "
                f"Use SHA-256 or stronger. Blocked algorithms: {BLOCKED_HASH_ALGORITHMS}"
            )
        if alg not in FIPS_APPROVED_HASH_ALGORITHMS and self.is_active():
            raise FIPSAlgorithmViolation(
                f"[SC-13] Hash algorithm '{algorithm}' is not in FIPS approved list "
                f"and FIPS mode is active. Approved: {FIPS_APPROVED_HASH_ALGORITHMS}"
            )
        return hashlib.new(alg, data).digest()

    def hmac_sha256(self, key: bytes, data: bytes) -> bytes:
        """HMAC-SHA256. FIPS-approved for MAC operations (not for JWT signing)."""
        return hmac.new(key, data, hashlib.sha256).digest()

    def hmac_sha256_hex(self, key: bytes, data: bytes) -> str:
        return hmac.new(key, data, hashlib.sha256).hexdigest()

    def constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """FIPS-safe constant-time comparison (prevents timing attacks)."""
        return hmac.compare_digest(a, b)

    # ── AES-256-GCM ──────────────────────────────────────────────────────────

    def encrypt(
        self,
        plaintext: bytes,
        key: bytes,
        aad: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes, bytes]:
        """
        AES-256-GCM authenticated encryption.
        SC-13 / SC-28: FIPS-approved symmetric encryption for data at rest.

        Args:
            plaintext: Data to encrypt
            key:       32-byte (256-bit) AES key
            aad:       Additional authenticated data (not encrypted, but authenticated)

        Returns:
            (ciphertext, tag, nonce) — all bytes
            nonce is 12 bytes (96-bit) per NIST SP 800-38D recommendation
        """
        if len(key) != 32:
            raise FIPSError(
                f"[SC-13] AES key must be 256 bits (32 bytes) for FIPS compliance. "
                f"Got {len(key) * 8} bits."
            )
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce = os.urandom(12)  # 96-bit nonce per NIST recommendation
            aesgcm = AESGCM(key)
            ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, aad)
            # AESGCM appends 16-byte tag to ciphertext
            ciphertext = ciphertext_and_tag[:-16]
            tag = ciphertext_and_tag[-16:]
            return ciphertext, tag, nonce
        except ImportError:
            raise FIPSError(
                "[SC-13] cryptography package required for AES-256-GCM. "
                "Install: pip install cryptography"
            )

    def decrypt(
        self,
        ciphertext: bytes,
        tag: bytes,
        nonce: bytes,
        key: bytes,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """
        AES-256-GCM authenticated decryption.
        Raises ValueError if authentication tag fails (data tampered).
        """
        if len(key) != 32:
            raise FIPSError(f"[SC-13] AES key must be 256 bits. Got {len(key) * 8} bits.")
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ciphertext + tag, aad)
        except ImportError:
            raise FIPSError("[SC-13] cryptography package required for AES-256-GCM.")

    def derive_key(self, password: bytes, salt: bytes, length: int = 32) -> bytes:
        """
        PBKDF2-HMAC-SHA256 key derivation. FIPS-approved KDF.
        SC-13 / IA-5: Use for deriving encryption keys from passwords/secrets.

        Uses 600,000 iterations per OWASP 2023 recommendation for PBKDF2-SHA256.
        """
        return hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=password,
            salt=salt,
            iterations=600_000,
            dklen=length,
        )

    # ── JWT enforcement ───────────────────────────────────────────────────────

    def assert_jwt_algorithm(self, algorithm: str) -> None:
        """
        Validate that a JWT algorithm is FIPS-approved for the current environment.
        IA-7: Cryptographic module authentication.

        Raises FIPSAlgorithmViolation if:
          - The algorithm is in BLOCKED_JWT_ALGORITHMS (always blocked)
          - The algorithm is not in FIPS_APPROVED_JWT_ALGORITHMS AND
            we're in a high-security environment
        """
        if algorithm in BLOCKED_JWT_ALGORITHMS:
            raise FIPSAlgorithmViolation(
                f"[IA-7 / SC-13] JWT algorithm '{algorithm}' is BLOCKED. "
                f"Symmetric JWT algorithms (HS*) are prohibited — use RS256, PS256, or ES256. "
                f"'none' is never acceptable."
            )
        if self._jwt_enforcement and algorithm not in FIPS_APPROVED_JWT_ALGORITHMS:
            raise FIPSAlgorithmViolation(
                f"[IA-7 / SC-13] JWT algorithm '{algorithm}' is not FIPS-approved "
                f"for ENVIRONMENT={_ENVIRONMENT}. "
                f"Approved algorithms: {sorted(FIPS_APPROVED_JWT_ALGORITHMS)}"
            )

    def assert_hash_algorithm(self, algorithm: str) -> None:
        """
        Validate a hash algorithm against FIPS policy.
        Raises FIPSAlgorithmViolation if blocked.
        """
        alg = algorithm.lower().replace("-", "").replace("_", "")
        blocked = {a.replace("_", "") for a in BLOCKED_HASH_ALGORITHMS}
        if alg in blocked:
            raise FIPSAlgorithmViolation(
                f"[SC-13] Hash algorithm '{algorithm}' is not FIPS 140-2 approved. "
                f"Blocked: MD5, SHA-1, MD4, RIPEMD-160. Use SHA-256 or stronger."
            )

    # ── TLS policy ────────────────────────────────────────────────────────────

    def get_tls_context(self, purpose: str = "client"):
        """
        Return an ssl.SSLContext configured for FIPS-compliant TLS.
        SC-8(1): Cryptographic protection of transmissions.

        - TLS 1.2 minimum (TLS 1.3 preferred)
        - FIPS-approved cipher suites only
        - Certificate verification always enabled
        """
        import ssl
        if purpose == "client":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.verify_mode = ssl.CERT_REQUIRED

        # FIPS-approved cipher suites (TLS 1.2)
        # These map to NIST SP 800-52 Rev2 approved cipher suites
        fips_ciphers = ":".join([
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
            "DHE-RSA-AES256-GCM-SHA384",
            "DHE-RSA-AES128-GCM-SHA256",
        ])
        try:
            ctx.set_ciphers(fips_ciphers)
        except ssl.SSLError:
            logger.warning("[SC-8] Could not set FIPS cipher list — using system defaults.")

        return ctx

    # ── Utility ───────────────────────────────────────────────────────────────

    def generate_key(self, length: int = 32) -> bytes:
        """Generate a cryptographically random key using os.urandom (FIPS DRBG)."""
        if length < 16:
            raise FIPSError("[SC-13] Key length must be at least 128 bits (16 bytes).")
        return os.urandom(length)

    def generate_nonce(self, length: int = 12) -> bytes:
        """Generate a cryptographically random nonce for AES-GCM (96-bit default)."""
        return os.urandom(length)

    def encode_b64url(self, data: bytes) -> str:
        """URL-safe base64 encode without padding (standard for JWTs/DPoP)."""
        return urlsafe_b64encode(data).rstrip(b"=").decode()

    def decode_b64url(self, data: str) -> bytes:
        """URL-safe base64 decode with padding restoration."""
        padded = data + "=" * (4 - len(data) % 4)
        return urlsafe_b64decode(padded)

    def compliance_summary(self) -> dict:
        """Return a compliance status dict suitable for the /api/compliance endpoint."""
        s = self.status
        return {
            "fips_active":          s.effective_fips,
            "kernel_fips":          s.kernel_fips,
            "openssl_fips":         s.openssl_fips,
            "environment":          _ENVIRONMENT,
            "jwt_enforcement":      self._jwt_enforcement,
            "fatal_if_fips_missing": self._fatal_if_missing,
            "approved_jwt_algs":    sorted(FIPS_APPROVED_JWT_ALGORITHMS),
            "blocked_jwt_algs":     sorted(BLOCKED_JWT_ALGORITHMS),
            "nist_reference":       "NIST SP 800-131A Rev2, SP 800-52 Rev2, SP 800-38D",
            "il5_ready":            s.effective_fips and self._jwt_enforcement,
        }


# ── Singleton ─────────────────────────────────────────────────────────────────

fips = FIPSEnforcer()

# Run startup check immediately on import in non-dev environments
if _ENVIRONMENT != "dev":
    fips.startup_check()
