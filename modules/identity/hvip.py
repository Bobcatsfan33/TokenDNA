"""
TokenDNA -- HVIP (High-Value Identity Profile) Enforcer
========================================================
IL5 / NIST IA-2, IA-3, IA-5, AC-6 compliance.

HVIP applies stepped-up authentication and binding requirements to
high-privilege identities (OWNER and ADMIN roles). An HVIP profile
captures the device fingerprint, geo-anchor, and MFA state at first
authentication, then enforces consistency on subsequent requests.

For IL5 environments:
  - OWNER/ADMIN tokens must carry DPoP binding
  - MFA must be asserted in the token (amr claim)
  - Device DNA must match the enrolled profile within tolerance
  - Geo-anchor enforced: requests outside the enrolled region require
    step-up (configurable: WARN / STEP_UP / BLOCK)

NIST 800-53 Rev5 controls:
  IA-2(1): MFA for privileged accounts
  IA-2(6): MFA for non-privileged network access (ADMIN)
  IA-3: Device identification and authentication
  IA-5(1): Authenticator management
  AC-6(5): Least privilege -- OWNER/ADMIN access restricted to enrolled devices
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)

HVIP_PROFILE_TTL_SECONDS = 86400 * 7
HVIP_GEO_TOLERANCE_KM = 200
HVIP_DISTANCE_TOLERANCE = 0.15


class HVIPRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    READONLY = "readonly"


class HVIPAction(str, Enum):
    ALLOW = "allow"
    STEP_UP = "step_up"
    BLOCK = "block"
    WARN = "warn"


class HVIPError(Exception):
    pass

class HVIPMFARequired(HVIPError):
    pass

class HVIPDeviceMismatch(HVIPError):
    pass

class HVIPDPoPRequired(HVIPError):
    pass


@dataclass
class HVIPProfile:
    uid: str
    role: HVIPRole
    enrolled_at: int
    enrolled_dna: str
    enrolled_country: Optional[str]
    enrolled_asn: Optional[str]
    mfa_method: Optional[str]
    dpop_jwk_thumbprint: Optional[str]
    geo_policy: HVIPAction = HVIPAction.STEP_UP
    last_seen: int = field(default_factory=lambda: int(time.time()))

    def to_dict(self) -> dict:
        return {
            "uid": self.uid,
            "role": self.role.value,
            "enrolled_at": self.enrolled_at,
            "enrolled_dna": self.enrolled_dna,
            "enrolled_country": self.enrolled_country,
            "enrolled_asn": self.enrolled_asn,
            "mfa_method": self.mfa_method,
            "dpop_jwk_thumbprint": self.dpop_jwk_thumbprint,
            "geo_policy": self.geo_policy.value,
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "HVIPProfile":
        return cls(
            uid=d["uid"],
            role=HVIPRole(d["role"]),
            enrolled_at=d["enrolled_at"],
            enrolled_dna=d["enrolled_dna"],
            enrolled_country=d.get("enrolled_country"),
            enrolled_asn=d.get("enrolled_asn"),
            mfa_method=d.get("mfa_method"),
            dpop_jwk_thumbprint=d.get("dpop_jwk_thumbprint"),
            geo_policy=HVIPAction(d.get("geo_policy", "step_up")),
            last_seen=d.get("last_seen", int(time.time())),
        )


@dataclass
class HVIPCheckResult:
    action: HVIPAction
    uid: str
    role: HVIPRole
    reason: str
    mfa_asserted: bool = False
    dpop_bound: bool = False
    device_match: Optional[bool] = None
    geo_match: Optional[bool] = None


class HVIPEnforcer:
    """HVIP enforcement engine for high-value identities (OWNER/ADMIN)."""

    PRIVILEGED_ROLES = {HVIPRole.OWNER, HVIPRole.ADMIN}

    def __init__(self, redis_client=None, il_environment: str = "dev"):
        self.redis = redis_client
        self.il_env = il_environment.lower()
        self._strict = self.il_env in {"il5", "il6"}

    def _redis_key(self, uid: str) -> str:
        return f"hvip:profile:{uid}"

    def get_profile(self, uid: str) -> Optional[HVIPProfile]:
        if self.redis is None:
            return None
        try:
            raw = self.redis.get(self._redis_key(uid))
            if raw:
                return HVIPProfile.from_dict(json.loads(raw))
        except Exception as e:
            logger.warning("HVIP profile load failed for %s: %s", uid, e)
        return None

    def save_profile(self, profile: HVIPProfile) -> None:
        if self.redis is None:
            logger.warning("HVIP: Redis not available, profile not persisted for %s", profile.uid)
            return
        try:
            self.redis.set(
                self._redis_key(profile.uid),
                json.dumps(profile.to_dict()),
                ex=HVIP_PROFILE_TTL_SECONDS,
            )
        except Exception as e:
            logger.error("HVIP profile save failed for %s: %s", profile.uid, e)

    def enroll(
        self,
        uid: str,
        role: HVIPRole,
        device_dna: str,
        country: Optional[str] = None,
        asn: Optional[str] = None,
        mfa_method: Optional[str] = None,
        dpop_jwk_thumbprint: Optional[str] = None,
    ) -> HVIPProfile:
        profile = HVIPProfile(
            uid=uid,
            role=role,
            enrolled_at=int(time.time()),
            enrolled_dna=device_dna,
            enrolled_country=country,
            enrolled_asn=asn,
            mfa_method=mfa_method,
            dpop_jwk_thumbprint=dpop_jwk_thumbprint,
        )
        self.save_profile(profile)
        logger.info("HVIP enrolled: uid=%s role=%s", uid, role.value)
        return profile

    def check(
        self,
        uid: str,
        role: HVIPRole,
        device_dna: str,
        country: Optional[str] = None,
        mfa_asserted: bool = False,
        dpop_bound: bool = False,
        amr_claims: Optional[list] = None,
    ) -> HVIPCheckResult:
        """Perform HVIP enforcement check for a request."""
        if role not in self.PRIVILEGED_ROLES:
            return HVIPCheckResult(
                action=HVIPAction.ALLOW,
                uid=uid,
                role=role,
                reason="non-privileged role -- HVIP not required",
                mfa_asserted=mfa_asserted,
                dpop_bound=dpop_bound,
            )

        _mfa_ok = mfa_asserted or (amr_claims and any(
            m in amr_claims for m in ("mfa", "otp", "hwk", "swk", "fpt", "kba")
        ))

        if not _mfa_ok:
            if self._strict:
                raise HVIPMFARequired(
                    f"IL5: MFA required for {role.value} but not asserted in token"
                )
            return HVIPCheckResult(
                action=HVIPAction.STEP_UP,
                uid=uid,
                role=role,
                reason=f"MFA not asserted for {role.value} identity",
                mfa_asserted=False,
                dpop_bound=dpop_bound,
            )

        if not dpop_bound:
            if self._strict:
                raise HVIPDPoPRequired(
                    f"IL5: DPoP token binding required for {role.value}"
                )
            return HVIPCheckResult(
                action=HVIPAction.WARN,
                uid=uid,
                role=role,
                reason=f"DPoP not bound for {role.value} identity (required in IL5)",
                mfa_asserted=_mfa_ok,
                dpop_bound=False,
            )

        profile = self.get_profile(uid)

        if profile is None:
            self.enroll(uid=uid, role=role, device_dna=device_dna, country=country)
            return HVIPCheckResult(
                action=HVIPAction.ALLOW,
                uid=uid,
                role=role,
                reason="HVIP profile created -- first-time enrollment",
                mfa_asserted=_mfa_ok,
                dpop_bound=dpop_bound,
            )

        device_match = (device_dna == profile.enrolled_dna)
        if not device_match:
            if self._strict:
                raise HVIPDeviceMismatch(
                    f"IL5: Device DNA mismatch for {role.value} uid={uid}"
                )
            return HVIPCheckResult(
                action=HVIPAction.STEP_UP,
                uid=uid,
                role=role,
                reason="Device DNA does not match enrolled HVIP profile",
                mfa_asserted=_mfa_ok,
                dpop_bound=dpop_bound,
                device_match=False,
            )

        geo_match = True
        if profile.enrolled_country and country:
            geo_match = (country == profile.enrolled_country)
            if not geo_match:
                return HVIPCheckResult(
                    action=profile.geo_policy,
                    uid=uid,
                    role=role,
                    reason=f"Geo mismatch: enrolled={profile.enrolled_country} current={country}",
                    mfa_asserted=_mfa_ok,
                    dpop_bound=dpop_bound,
                    device_match=True,
                    geo_match=False,
                )

        profile.last_seen = int(time.time())
        self.save_profile(profile)

        return HVIPCheckResult(
            action=HVIPAction.ALLOW,
            uid=uid,
            role=role,
            reason="HVIP check passed",
            mfa_asserted=_mfa_ok,
            dpop_bound=dpop_bound,
            device_match=device_match,
            geo_match=geo_match,
        )
