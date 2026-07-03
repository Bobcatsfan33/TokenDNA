"""
TokenDNA — Signed license keys (the open-core entitlement boundary).

Why this exists
---------------
TokenDNA's repository is public. ``modules.product.commercial_tiers`` gates
the ``ent.*`` enterprise features (Blast Radius, enforcement plane, intent
correlation, MCP gateway, behavioral DNA) by the tenant's billing plan — but
in a self-hosted deployment the tenant database belongs to the operator, so a
DB row saying ``plan='enterprise'`` proves nothing. The real entitlement
boundary is a cryptographically signed license key:

* Licenses are issued by the (private) TokenDNA license service, driven by
  Stripe subscription events. Only the Ed25519 *public* key ships here.
* A license is a compact signed string::

      TDNA1.<base64url(payload JSON)>.<base64url(Ed25519 signature)>

  signed over the bytes of ``"TDNA1." + <base64url payload>``.
* Verification is fully offline — no phone-home. (The license service exposes
  an optional ``/v1/licenses/validate`` revocation check for operators who
  want it.)

Payload fields
--------------
``lid`` license id · ``sub`` Stripe customer id · ``org`` display name ·
``tier`` community|pro|enterprise · ``features`` optional list of à-la-carte
``ent.*`` keys · ``iat`` issued-at (unix) · ``exp`` expiry (unix).

Enforcement modes — ``TOKENDNA_LICENSE_ENFORCEMENT``
----------------------------------------------------
``off``     (default) plan-based gating only; behavior identical to pre-license
            builds. Keeps dev, CI, and the 10-minute demo friction-free.
``warn``    log when the DB plan exceeds the license, but allow.
``enforce`` the license caps the effective commercial tier. Production mode.

This gate is a compliance boundary, not DRM: the repo is public, so the check
is patchable by a determined operator. Commercial use without a license is
governed by the BUSL-1.1 terms; the signed key is what makes honest
commercial use frictionless and auditable.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

LICENSE_PREFIX = "TDNA1"

# Ed25519 public key (hex). Injected by ``scripts/generate_license_keys.py
# --inject``. The corresponding private key is held offline by the vendor and
# never enters this repository.
LICENSE_PUBLIC_KEY_HEX = "7f06dedb75af0a37d93ac3e0d05e16020040ddf7fbcc97703884c194fe277fd4"

_VALID_TIERS = {"community", "pro", "enterprise"}
_CACHE_TTL_SECONDS = 60.0


class LicenseError(Exception):
    """Raised when a license key is malformed, unsigned, or expired."""


@dataclass(frozen=True)
class License:
    license_id: str
    customer: str
    org: str
    tier: str
    issued_at: int
    expires_at: int
    features: tuple[str, ...] = field(default_factory=tuple)

    def is_expired(self, now: Optional[float] = None) -> bool:
        return (now if now is not None else time.time()) >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "license_id": self.license_id,
            "customer": self.customer,
            "org": self.org,
            "tier": self.tier,
            "features": list(self.features),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


# ── base64url helpers ────────────────────────────────────────────────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


# ── Verification ─────────────────────────────────────────────────────────────

def parse_and_verify(
    raw: str,
    *,
    public_key_hex: Optional[str] = None,
    now: Optional[float] = None,
) -> License:
    """Parse a raw license string, verify its signature, and check expiry.

    Raises ``LicenseError`` on any failure. Never raises anything else for
    malformed input.
    """
    pub_hex = public_key_hex if public_key_hex is not None else LICENSE_PUBLIC_KEY_HEX
    if not pub_hex or pub_hex.startswith("__"):
        raise LicenseError("license public key not configured in this build")

    raw = (raw or "").strip()
    parts = raw.split(".")
    if len(parts) != 3 or parts[0] != LICENSE_PREFIX:
        raise LicenseError("malformed license key (expected TDNA1.<payload>.<sig>)")

    payload_b64, sig_b64 = parts[1], parts[2]
    try:
        payload_bytes = _b64url_decode(payload_b64)
        signature = _b64url_decode(sig_b64)
    except Exception as exc:  # noqa: BLE001
        raise LicenseError("license key is not valid base64url") from exc

    try:
        from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
            Ed25519PublicKey,
        )

        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        message = f"{LICENSE_PREFIX}.{payload_b64}".encode("ascii")
        try:
            public_key.verify(signature, message)
        except InvalidSignature as exc:
            raise LicenseError("license signature verification failed") from exc
    except LicenseError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise LicenseError(f"license verification unavailable: {exc}") from exc

    try:
        payload = json.loads(payload_bytes)
    except Exception as exc:  # noqa: BLE001
        raise LicenseError("license payload is not valid JSON") from exc

    tier = str(payload.get("tier", "")).lower()
    if tier not in _VALID_TIERS:
        raise LicenseError(f"license tier {tier!r} is not recognized")

    lic = License(
        license_id=str(payload.get("lid", "")),
        customer=str(payload.get("sub", "")),
        org=str(payload.get("org", "")),
        tier=tier,
        issued_at=int(payload.get("iat", 0)),
        expires_at=int(payload.get("exp", 0)),
        features=tuple(str(f) for f in payload.get("features", []) or ()),
    )
    if lic.is_expired(now):
        raise LicenseError("license has expired")
    return lic


# ── Loading + caching ────────────────────────────────────────────────────────

def _license_file_path() -> str:
    return os.getenv("TOKENDNA_LICENSE_FILE", "") or "./license.key"


def _load_raw_license() -> Optional[str]:
    raw = (os.getenv("TOKENDNA_LICENSE_KEY") or "").strip()
    if raw:
        return raw
    path = _license_file_path()
    try:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                content = fh.read().strip()
            return content or None
    except OSError as exc:
        logger.warning("license file %s unreadable: %s", path, exc)
    return None


_lock = threading.Lock()
_state: dict[str, Any] = {"license": None, "error": None, "loaded_at": None, "present": False}


def reload() -> None:
    """Force a re-read of the license from env/file on next access."""
    with _lock:
        _state["loaded_at"] = None


def _is_stale_locked() -> bool:
    """True when the cached license must be re-read from env/file.

    ``loaded_at`` is ``None`` before the first load and after ``reload()``.
    ``time.monotonic()`` has an undefined reference point (it can start near
    zero at process launch), so ``0.0`` must NOT be treated as "long ago" —
    only an explicit ``None`` forces a refresh.
    """
    loaded_at = _state["loaded_at"]
    return loaded_at is None or (time.monotonic() - float(loaded_at)) > _CACHE_TTL_SECONDS


def _refresh_locked() -> None:
    raw = _load_raw_license()
    _state["present"] = raw is not None
    if raw is None:
        _state["license"], _state["error"] = None, None
    else:
        try:
            _state["license"], _state["error"] = parse_and_verify(raw), None
        except LicenseError as exc:
            _state["license"], _state["error"] = None, str(exc)
            logger.warning("license rejected: %s", exc)
    _state["loaded_at"] = time.monotonic()


def get_license() -> Optional[License]:
    """Return the currently valid license, or ``None``. Never raises."""
    with _lock:
        if _is_stale_locked():
            _refresh_locked()
        lic = _state["license"]
    if lic is not None and lic.is_expired():
        return None
    return lic


# ── Entitlement surface consumed by commercial_tiers ─────────────────────────

def enforcement_mode() -> str:
    """``off`` | ``warn`` | ``enforce`` — driven by env, default ``off``."""
    mode = (os.getenv("TOKENDNA_LICENSE_ENFORCEMENT") or "off").strip().lower()
    return mode if mode in {"off", "warn", "enforce"} else "off"


def licensed_tier() -> str:
    """Tier granted by the current license, or ``community`` when absent."""
    lic = get_license()
    return lic.tier if lic is not None else "community"


def feature_granted(feature_key: str) -> bool:
    """True when the license grants ``feature_key`` à la carte."""
    lic = get_license()
    return lic is not None and feature_key in lic.features


def status() -> dict[str, Any]:
    """Structured license status for the ``/api/license/status`` endpoint."""
    with _lock:
        if _is_stale_locked():
            _refresh_locked()
        lic, error, present = _state["license"], _state["error"], _state["present"]
    if lic is not None and lic.is_expired():
        lic, error = None, "license has expired"
    if lic is not None:
        state = "valid"
    elif not present:
        state = "missing"
    else:
        state = "invalid"
    out: dict[str, Any] = {
        "state": state,
        "enforcement": enforcement_mode(),
        "tier": lic.tier if lic else "community",
    }
    if lic is not None:
        out["license"] = lic.to_dict()
    if error:
        out["error"] = error
    return out


def activate(raw: str) -> License:
    """Verify ``raw`` and persist it to the license file. Raises LicenseError."""
    lic = parse_and_verify(raw)
    path = _license_file_path()
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(raw.strip() + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    reload()
    logger.info("license %s activated (tier=%s, org=%s)", lic.license_id, lic.tier, lic.org)
    return lic
