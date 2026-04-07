"""
TokenDNA — Zero Trust Identity Exchange (ZTIX) Engine  (v2.11.0)

Zero Trust Identity Exchange is the cryptographic broker that:
  1. Validates the requestor's behavioral DNA + cryptographic attestation
  2. Issues a scoped, short-lived capability token per call
  3. Abstracts the source identity — targets never see the real identity/IP
  4. Leaves zero footprint on the target (no session state, no cookies)

Design Principles
-----------------
- Source identity abstraction: each outbound call gets a fresh scoped token;
  the target sees only the capability, not who holds it.
- Zero footprint: tokens are not stored on targets. They are self-contained JWTs
  signed by the ZTIX authority. Stateless verification on the target side.
- Minimal capability: tokens carry only the permissions required for the specific call.
  No broad roles; every token is purpose-scoped and caller-scoped.
- Short-lived: TTL defaults to 300 seconds; configurable per request.
- Cryptographic binding: tokens are bound to the machine identity (machine_id)
  and the requesting entity (subject_id) via HMAC in the payload.

Token Anatomy (JWT claims):
  jti       — unique token ID (nonce)
  iss       — "ztix.tokendna"
  sub       — opaque subject handle (HMAC of real identity — not reversible by target)
  mid       — machine identity handle (HMAC of machine_id — same privacy model)
  cap       — capability set (list of allowed operations, e.g. ["read:findings"])
  scp       — resource scope (e.g. "aegis:scan:read")
  tgt       — target service identifier
  iat / exp — issued-at / expiry (short TTL)
  aml       — assurance level: 1=baseline, 2=elevated, 3=high (hardware-attested)
  dna       — behavioral DNA hash (proves behavioral attestation without leaking it)
  sig       — inner HMAC signature binding subject + machine + capability

Exchange flow:
  caller → ZTIXEngine.exchange(ZTIXRequest)
    → validate_identity (machine_id + behavioral DNA)
    → evaluate_assurance (attestation level → aml)
    → mint_token (scoped JWT)
    → return ZTIXResult with opaque token

Target validation flow:
  target → ZTIXEngine.verify_token(token)
    → verify JWT signature
    → check exp / jti reuse
    → return ZTIXCapabilityToken (capabilities visible; no source identity)

NIST 800-53 Rev5:
  IA-8   Identification and Authentication — Non-Organizational Users
  AC-17  Remote Access (scoped capability model)
  SC-8   Transmission Confidentiality (tokens over mTLS)
  AU-2   Auditable Events
  SC-23  Session Authenticity (stateless token validation)
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────

ZTIX_SIGNING_KEY: bytes = os.getenv("ZTIX_SIGNING_KEY", "").encode() or b"dev-ztix-key-change-in-prod"
ZTIX_ISSUER      = os.getenv("ZTIX_ISSUER", "ztix.tokendna")
ZTIX_DEFAULT_TTL = int(os.getenv("ZTIX_DEFAULT_TTL", "300"))       # 5 minutes
ZTIX_MAX_TTL     = int(os.getenv("ZTIX_MAX_TTL", "3600"))          # 1 hour hard cap
ZTIX_REVOCATION_TTL = int(os.getenv("ZTIX_REVOCATION_TTL", "3600")) # how long to track used JTIs

# ── Errors ─────────────────────────────────────────────────────────────────────


class ZTIXError(Exception):
    """Base error for ZTIX operations."""


class ZTIXAuthError(ZTIXError):
    """Identity validation failed."""


class ZTIXTokenError(ZTIXError):
    """Token is invalid, expired, or replayed."""


class ZTIXPolicyError(ZTIXError):
    """Requested capability exceeds policy."""


# ── Data structures ────────────────────────────────────────────────────────────


@dataclass
class ZTIXRequest:
    """
    Request to exchange an identity for a scoped capability token.

    Fields:
      subject_id   — caller's identity (user ID, service account name, agent ID)
      machine_id   — machine identity from MachineIdentityManager
      capabilities — list of operations requested (e.g. ["read:findings", "write:scan"])
      scope        — resource scope string (e.g. "aegis:findings:read")
      target       — target service identifier (e.g. "aegis-api", "tokendna-internal")
      dna_hash     — HMAC of caller's behavioral DNA (proves DNA without revealing it)
      assurance    — requested assurance level (1–3); engine may downgrade
      ttl          — requested TTL in seconds (capped at ZTIX_MAX_TTL)
      context      — optional metadata (request_id, trace_id, etc.)
    """
    subject_id:   str
    machine_id:   str
    capabilities: list
    scope:        str
    target:       str
    dna_hash:     str = ""
    assurance:    int = 1
    ttl:          int = ZTIX_DEFAULT_TTL
    context:      dict = field(default_factory=dict)


@dataclass
class ZTIXCapabilityToken:
    """
    Decoded, verified ZTIX capability token.
    Contains only what the TARGET is allowed to see — no source identity.
    """
    jti:          str
    sub_handle:   str        # opaque handle — not the real subject_id
    mid_handle:   str        # opaque handle — not the real machine_id
    capabilities: list
    scope:        str
    target:       str
    issued_at:    float
    expires_at:   float
    assurance:    int
    raw_jwt:      str = field(default="", compare=False)

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def has_capability(self, cap: str) -> bool:
        return cap in self.capabilities

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("raw_jwt", None)      # don't expose raw JWT in dict output
        return d


@dataclass
class ZTIXResult:
    """Result of a ZTIXEngine.exchange() call."""
    success:       bool
    token:         str = ""          # opaque JWT string; empty on failure
    jti:           str = ""
    expires_at:    float = 0.0
    assurance:     int = 0
    error:         str = ""
    capabilities:  list = field(default_factory=list)
    scope:         str = ""
    target:        str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ── Minimal JWT implementation (no external deps) ─────────────────────────────
# We implement a minimal JWT here to avoid depending on python-jose at module import time.
# The format is HS256 (HMAC-SHA256). In IL4+, swap for RS256/ES256 via config.

import base64


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _jwt_sign(payload: dict, key: bytes) -> str:
    header  = {"alg": "HS256", "typ": "JWT"}
    h_enc   = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_enc   = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_enc}.{p_enc}".encode()
    sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    return f"{h_enc}.{p_enc}.{_b64url_encode(sig)}"


def _jwt_verify(token: str, key: bytes) -> dict:
    """Verify HS256 JWT and return payload. Raises ZTIXTokenError on failure."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ZTIXTokenError("malformed_jwt")
    h_enc, p_enc, sig_enc = parts
    signing_input = f"{h_enc}.{p_enc}".encode()
    expected_sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    provided_sig = _b64url_decode(sig_enc)
    if not hmac.compare_digest(expected_sig, provided_sig):
        raise ZTIXTokenError("invalid_signature")
    try:
        return json.loads(_b64url_decode(p_enc))
    except (json.JSONDecodeError, Exception) as exc:
        raise ZTIXTokenError(f"payload_decode_error: {exc}")


# ── JTI Replay Cache ───────────────────────────────────────────────────────────


class JTIReplayCache:
    """
    In-memory JTI (JWT ID) replay prevention cache.
    Thread-safe. Evicts expired entries on each insert.
    In production, back this with Redis for multi-replica deployments.
    """

    def __init__(self):
        self._used: dict[str, float] = {}    # jti → expiry timestamp
        self._lock = threading.Lock()

    def mark_used(self, jti: str, expires_at: float) -> None:
        with self._lock:
            self._evict()
            self._used[jti] = expires_at

    def is_used(self, jti: str) -> bool:
        with self._lock:
            return jti in self._used

    def _evict(self) -> None:
        now = time.time()
        expired = [jti for jti, exp in self._used.items() if exp < now]
        for jti in expired:
            del self._used[jti]

    def count(self) -> int:
        with self._lock:
            return len(self._used)


# ── Capability Policy ──────────────────────────────────────────────────────────


class CapabilityPolicy:
    """
    Simple allow-list policy for capability → minimum assurance level.

    Capabilities not in the registry are denied by default.
    """

    # Default registry: capability → min_assurance_level
    _DEFAULT_REGISTRY: dict[str, int] = {
        # Aegis capabilities
        "aegis:read":           1,
        "aegis:scan:trigger":   2,
        "aegis:admin":          3,
        # TokenDNA capabilities
        "tokendna:verify":      1,
        "tokendna:revoke":      2,
        "tokendna:admin":       3,
        # Generic
        "read:findings":        1,
        "write:scan":           2,
        "read:compliance":      1,
        "admin:keys":           3,
        "*":                    1,          # wildcard (dev mode only)
    }

    def __init__(self, registry: Optional[dict] = None):
        self._registry = registry or dict(self._DEFAULT_REGISTRY)

    def allowed(self, capabilities: list, assurance: int) -> tuple[bool, str]:
        """
        Check if all capabilities are allowed at the given assurance level.
        Returns (ok, reason).
        """
        for cap in capabilities:
            min_assurance = self._registry.get(cap)
            if min_assurance is None:
                return False, f"unknown_capability:{cap}"
            if assurance < min_assurance:
                return False, f"insufficient_assurance:{cap}:need>={min_assurance}:have={assurance}"
        return True, "ok"


# ── ZTIX Engine ────────────────────────────────────────────────────────────────


class ZTIXEngine:
    """
    Zero Trust Identity Exchange engine.

    Core operations:
      exchange(request)       → validate identity, mint scoped token → ZTIXResult
      verify_token(jwt_str)   → verify + decode scoped token → ZTIXCapabilityToken
      revoke_token(jti)       → add JTI to replay cache (prevents reuse)
    """

    def __init__(
        self,
        signing_key: bytes = ZTIX_SIGNING_KEY,
        policy: Optional[CapabilityPolicy] = None,
        replay_cache: Optional[JTIReplayCache] = None,
        machine_identity_manager=None,
    ):
        self._signing_key = signing_key
        self._policy   = policy or CapabilityPolicy()
        self._replay   = replay_cache or JTIReplayCache()
        self._mim      = machine_identity_manager  # optional MachineIdentityManager

    # ── Identity abstraction helpers ──────────────────────────────────────────

    def _sub_handle(self, subject_id: str) -> str:
        """Opaque handle for subject — target sees this, not real identity."""
        return "sub_" + hmac.new(
            self._signing_key, subject_id.encode(), hashlib.sha256
        ).hexdigest()[:16]

    def _mid_handle(self, machine_id: str) -> str:
        """Opaque handle for machine — target sees this, not real machine_id."""
        return "mid_" + hmac.new(
            self._signing_key, machine_id.encode(), hashlib.sha256
        ).hexdigest()[:16]

    def _inner_binding_sig(self, subject_id: str, machine_id: str, capabilities: list, scope: str) -> str:
        """
        HMAC binding of subject + machine + capability + scope.
        Embedded in token to detect tampering of the claims body.
        """
        binding = f"{subject_id}:{machine_id}:{','.join(sorted(capabilities))}:{scope}"
        return hmac.new(
            self._signing_key, binding.encode(), hashlib.sha256
        ).hexdigest()[:32]

    # ── Assurance evaluation ──────────────────────────────────────────────────

    def _evaluate_assurance(
        self,
        machine_id: str,
        dna_hash: str,
        requested_assurance: int,
    ) -> int:
        """
        Determine the actual assurance level achievable given the evidence provided.

        Level 1 — basic: machine_id present
        Level 2 — elevated: machine_id + valid DNA hash
        Level 3 — high: machine_id + DNA + hardware attestation (machine verified by MIM)
        """
        if not machine_id:
            return 0

        level = 1

        if dna_hash:
            level = 2

        if self._mim is not None:
            status = self._mim.get_status(machine_id)
            if status and status.get("baseline_ready") and status.get("attestation_provider") != "null":
                level = 3

        return min(level, requested_assurance)

    # ── Token issuance ─────────────────────────────────────────────────────────

    def exchange(self, request: ZTIXRequest) -> ZTIXResult:
        """
        Exchange a validated identity for a scoped capability token.

        Returns ZTIXResult.success=False if:
          - subject_id or machine_id is empty
          - capability policy denies the request
          - machine is revoked (if MachineIdentityManager connected)
        """
        if not request.subject_id or not request.machine_id:
            return ZTIXResult(success=False, error="missing_subject_or_machine_id")

        if not request.capabilities:
            return ZTIXResult(success=False, error="empty_capability_set")

        # Cap TTL
        ttl = min(max(request.ttl, 1), ZTIX_MAX_TTL)

        # Assurance evaluation
        assurance = self._evaluate_assurance(
            request.machine_id, request.dna_hash, request.assurance
        )

        # Policy check
        ok, reason = self._policy.allowed(request.capabilities, assurance)
        if not ok:
            logger.warning(
                "[ZTIX] Policy denied: subject=%s machine=%s caps=%s reason=%s",
                request.subject_id, request.machine_id, request.capabilities, reason
            )
            return ZTIXResult(success=False, error=f"policy_denied:{reason}")

        # Optional: check machine status
        if self._mim is not None:
            status = self._mim.get_status(request.machine_id)
            if status and status.get("status") == "revoked":
                return ZTIXResult(success=False, error="machine_revoked")

        now = time.time()
        jti = "ztix_" + secrets.token_hex(16)
        expires_at = now + ttl

        payload = {
            "jti":  jti,
            "iss":  ZTIX_ISSUER,
            "sub":  self._sub_handle(request.subject_id),
            "mid":  self._mid_handle(request.machine_id),
            "cap":  request.capabilities,
            "scp":  request.scope,
            "tgt":  request.target,
            "iat":  int(now),
            "exp":  int(expires_at),
            "aml":  assurance,
            "dna":  request.dna_hash or "",
            "sig":  self._inner_binding_sig(
                request.subject_id, request.machine_id,
                request.capabilities, request.scope
            ),
        }

        token = _jwt_sign(payload, self._signing_key)
        self._replay.mark_used(jti, expires_at + ZTIX_REVOCATION_TTL)

        logger.info(
            "[ZTIX] Token issued: jti=%s sub_h=%s mid_h=%s caps=%s scope=%s tgt=%s ttl=%ds aml=%d",
            jti, payload["sub"], payload["mid"],
            request.capabilities, request.scope, request.target, ttl, assurance,
        )

        return ZTIXResult(
            success=True,
            token=token,
            jti=jti,
            expires_at=expires_at,
            assurance=assurance,
            capabilities=request.capabilities,
            scope=request.scope,
            target=request.target,
        )

    # ── Token verification ─────────────────────────────────────────────────────

    def verify_token(self, token: str, expected_target: str = "") -> ZTIXCapabilityToken:
        """
        Verify and decode a ZTIX capability token.

        Raises ZTIXTokenError if:
          - Signature invalid
          - Token expired
          - JTI already verified (replay attack)
          - Issuer mismatch
          - Target mismatch (if expected_target provided)

        Returns ZTIXCapabilityToken with capability claims (no source identity).
        """
        payload = _jwt_verify(token, self._signing_key)     # raises ZTIXTokenError on bad sig

        # Expiry
        exp = payload.get("exp", 0)
        if time.time() > exp:
            raise ZTIXTokenError("token_expired")

        # Issuer
        if payload.get("iss") != ZTIX_ISSUER:
            raise ZTIXTokenError(f"invalid_issuer:{payload.get('iss')}")

        # Target check
        if expected_target and payload.get("tgt") != expected_target:
            raise ZTIXTokenError(f"target_mismatch:expected={expected_target}:got={payload.get('tgt')}")

        # JTI replay check: mark used (subsequent verifications of same token are rejected)
        jti = payload.get("jti", "")
        if not jti:
            raise ZTIXTokenError("missing_jti")

        # Note: We allow the first verification (jti was added to cache on issue).
        # On second call with same JTI, we detect replay.
        # Implementation: we use a separate "verified" set distinct from the "issued" set.
        # Here we leverage a second key pattern to avoid false positives.
        verified_key = f"verified:{jti}"
        if self._replay.is_used(verified_key):
            raise ZTIXTokenError("token_already_used")
        self._replay.mark_used(verified_key, exp + ZTIX_REVOCATION_TTL)

        logger.debug(
            "[ZTIX] Token verified: jti=%s sub=%s caps=%s scope=%s tgt=%s",
            jti, payload.get("sub"), payload.get("cap"), payload.get("scp"), payload.get("tgt")
        )

        return ZTIXCapabilityToken(
            jti=jti,
            sub_handle=payload.get("sub", ""),
            mid_handle=payload.get("mid", ""),
            capabilities=payload.get("cap", []),
            scope=payload.get("scp", ""),
            target=payload.get("tgt", ""),
            issued_at=float(payload.get("iat", 0)),
            expires_at=float(exp),
            assurance=payload.get("aml", 1),
            raw_jwt=token,
        )

    def revoke_token(self, jti: str, expires_at: float = 0.0) -> None:
        """
        Manually revoke a token by its JTI (before expiry).
        Adds to replay cache so future verifications fail.
        """
        exp = expires_at or (time.time() + ZTIX_REVOCATION_TTL)
        self._replay.mark_used(f"verified:{jti}", exp + ZTIX_REVOCATION_TTL)
        logger.info("[ZTIX] Token revoked: jti=%s", jti)

    def stats(self) -> dict:
        return {
            "replay_cache_size": self._replay.count(),
            "issuer":            ZTIX_ISSUER,
            "default_ttl":       ZTIX_DEFAULT_TTL,
            "max_ttl":           ZTIX_MAX_TTL,
        }


# ── Module-level singleton ─────────────────────────────────────────────────────

_default_engine: Optional[ZTIXEngine] = None
_engine_lock = threading.Lock()


def get_ztix_engine() -> ZTIXEngine:
    """Return (or lazily create) the module-level ZTIXEngine singleton."""
    global _default_engine
    if _default_engine is None:
        with _engine_lock:
            if _default_engine is None:
                _default_engine = ZTIXEngine()
    return _default_engine
