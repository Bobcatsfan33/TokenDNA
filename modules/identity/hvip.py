"""
Aegis Security — High-Value Identity Hardening Profiles (HVIP)  (v2.4.0)

AC-2 / AC-5 / AC-6 / IA-2(1) / IA-2(3) / IA-11

Admins, executives, SREs, security personnel, and finance users are
disproportionately targeted for token theft and credential abuse.
A single compromised OWNER or ADMIN token can grant full platform access.

HVIP automatically applies stricter behavioral and cryptographic controls
to high-value identities without requiring code changes in each endpoint.

How it works:
  1. Operator creates an HVIPConfig for a user_id (via PUT /admin/hvip/{uid})
  2. HVIPRegistry stores profiles in Redis (persistent) and local LRU cache
  3. On every authenticated request, HVIPEnforcer.evaluate() checks if the
     requesting identity has a profile and whether the request satisfies it
  4. If a policy constraint is violated, the enforcer returns STEP_UP or REVOKE
     even if the base ML risk score would have returned ALLOW

Automatic HVIP application:
  OWNER and ADMIN role tokens are automatically subject to default HVIP
  baseline controls (configurable via HVIP_AUTO_ADMIN=true, default true).

IL5 alignment:
  - IA-2(1): Multi-factor authentication enforced at privilege boundary
  - IA-2(3): Hardware-based MFA (FIDO2 / PIV / CAC) required for OWNER
  - IA-11: Re-authentication triggered after token age or anomaly threshold
  - AC-6: Least privilege — geo-lock and ASN allowlists limit attack surface
"""

import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from functools import lru_cache
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

_HVIP_AUTO_ADMIN: bool     = os.getenv("HVIP_AUTO_ADMIN", "true").lower() == "true"
_HVIP_CACHE_SIZE: int      = int(os.getenv("HVIP_CACHE_SIZE", "512"))
_HVIP_REDIS_TTL: int       = int(os.getenv("HVIP_REDIS_TTL_SECONDS", str(86400 * 30)))  # 30 days


class PolicyDecision(str, Enum):
    """Risk-adaptive decision returned by HVIP evaluation."""
    ALLOW    = "allow"
    STEP_UP  = "step_up"   # Trigger MFA challenge
    BLOCK    = "block"     # Hard reject (temporary — allow retry)
    REVOKE   = "revoke"    # Revoke token and force re-authentication


class HVIPViolationType(str, Enum):
    """Classification of what constraint was violated."""
    GEO_LOCK         = "geo_lock"
    ASN_RESTRICTION  = "asn_restriction"
    TOKEN_AGE        = "token_age"
    DPOP_REQUIRED    = "dpop_required"
    HARDWARE_MFA     = "hardware_mfa"
    ANOMALY_OVERRIDE = "anomaly_override"
    TIME_OF_DAY      = "time_of_day"
    IP_ALLOWLIST     = "ip_allowlist"


@dataclass
class HVIPViolation:
    """A single policy violation detected during HVIP evaluation."""
    violation_type:  HVIPViolationType
    description:     str
    recommended_action: PolicyDecision
    details:         dict = field(default_factory=dict)


@dataclass
class HVIPEvaluationResult:
    """Full result of evaluating a request against an HVIP."""
    decision:         PolicyDecision
    violations:       List[HVIPViolation]
    profile_applied:  bool     # False if no HVIP profile exists for this identity
    auto_applied:     bool     # True if default admin baseline was applied
    evaluation_ms:    float    # Evaluation latency in milliseconds
    step_up_reason:   Optional[str] = None
    revoke_reason:    Optional[str] = None


@dataclass
class HVIPConfig:
    """
    Security hardening profile for a high-value identity.

    All fields are optional — only set constraints relevant to the identity.
    Unset fields inherit platform defaults or base ML scoring.
    """
    user_id:              str
    tenant_id:            str

    # Geographic restriction — ISO 3166-1 alpha-2 country codes
    # Empty list = no geo restriction (use base ML scoring)
    geo_lock:             List[str] = field(default_factory=list)

    # ASN allowlist — only allow traffic from these Autonomous System Numbers
    # Useful for restricting government-network-only identities
    allowed_asns:         List[int] = field(default_factory=list)

    # IP allowlist — CIDR ranges or exact IPs (empty = no restriction)
    allowed_ips:          List[str] = field(default_factory=list)

    # Token age policy — force re-auth after this many seconds regardless of activity
    # None = use platform default (OIDC token expiry)
    max_token_age_seconds: Optional[int] = None  # e.g. 7200 for 2-hour sessions

    # DPoP requirement — if True, all requests must present a valid DPoP proof
    # Overrides DPOP_REQUIRED env var for this specific identity
    require_dpop:         bool = False

    # Hardware MFA requirement — if True, amr claim must contain "hwk" or "fido"
    # or CAC/PIV-equivalent. Rejects software TOTP alone for this identity.
    require_hardware_mfa: bool = False

    # Anomaly override — if True, ANY anomaly signal triggers STEP_UP regardless
    # of the base ML score. Highly sensitive identities never silently ALLOW
    # when something looks off.
    step_up_on_any_anomaly: bool = False

    # Revoke override — if True, HIGH-severity anomalies (Tor, impossible travel)
    # immediately REVOKE rather than STEP_UP
    revoke_on_high_anomaly: bool = False

    # Risk score threshold — override platform default ALLOW threshold for this identity
    # None = use platform SCORE_THRESHOLD_ALLOW
    min_allow_score:      Optional[int] = None   # e.g. 90 for ultra-sensitive identities

    # Time-of-day restriction — block access outside normal working hours
    # Format: [start_hour, end_hour] in 24h UTC (e.g. [8, 20] = 8am–8pm UTC)
    allowed_hours_utc:    Optional[List[int]] = None  # [8, 20]

    # Allowed days of week (0=Monday, 6=Sunday). Empty = all days.
    allowed_days_of_week: List[int] = field(default_factory=list)

    # Profile metadata
    label:                str = ""          # Human-readable label (e.g. "Executive", "CISO")
    created_at:           float = field(default_factory=time.time)
    updated_at:           float = field(default_factory=time.time)
    created_by:           str = "system"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "HVIPConfig":
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})

    @classmethod
    def default_admin_profile(cls, user_id: str, tenant_id: str, role: str) -> "HVIPConfig":
        """
        Return the default hardening profile for admin-tier accounts.
        Applied automatically when HVIP_AUTO_ADMIN=true.

        OWNER gets the strictest controls; ADMIN gets a slightly relaxed baseline.
        """
        if role.upper() == "OWNER":
            return cls(
                user_id=user_id,
                tenant_id=tenant_id,
                require_dpop=True,
                require_hardware_mfa=True,
                step_up_on_any_anomaly=True,
                revoke_on_high_anomaly=True,
                max_token_age_seconds=3600,   # 1-hour sessions for OWNER
                min_allow_score=85,
                label="Auto: OWNER baseline (IL5 default)",
                created_by="system:auto",
            )
        else:  # ADMIN
            return cls(
                user_id=user_id,
                tenant_id=tenant_id,
                require_dpop=True,
                step_up_on_any_anomaly=True,
                revoke_on_high_anomaly=False,
                max_token_age_seconds=7200,   # 2-hour sessions for ADMIN
                min_allow_score=75,
                label="Auto: ADMIN baseline (IL5 default)",
                created_by="system:auto",
            )


# ── Registry ──────────────────────────────────────────────────────────────────

class HVIPRegistry:
    """
    Persistent registry for HVIP configs.
    Redis-backed with in-process LRU cache for low-latency reads.
    """

    _REDIS_KEY_PREFIX = "hvip:profile"

    def __init__(self, redis_client=None):
        self._redis = redis_client
        self._cache: Dict[str, HVIPConfig] = {}

    def _get_redis(self):
        if self._redis is not None:
            return self._redis
        try:
            import redis as redis_lib
            host     = os.getenv("REDIS_HOST", "localhost")
            port     = int(os.getenv("REDIS_PORT", "6379"))
            password = os.getenv("REDIS_PASSWORD") or None
            tls      = os.getenv("REDIS_TLS", "false").lower() == "true"
            client   = redis_lib.Redis(
                host=host, port=port, password=password,
                ssl=tls, decode_responses=True, socket_timeout=2
            )
            client.ping()
            self._redis = client
        except Exception as e:
            logger.warning(f"[HVIP] Redis unavailable: {e}. Profiles will be in-memory only.")
        return self._redis

    def _redis_key(self, tenant_id: str, user_id: str) -> str:
        return f"{self._REDIS_KEY_PREFIX}:{tenant_id}:{user_id}"

    def get(self, tenant_id: str, user_id: str) -> Optional[HVIPConfig]:
        """Retrieve an HVIP config. Returns None if no profile exists."""
        cache_key = f"{tenant_id}:{user_id}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        redis = self._get_redis()
        if redis:
            try:
                raw = redis.get(self._redis_key(tenant_id, user_id))
                if raw:
                    profile = HVIPConfig.from_dict(json.loads(raw))
                    self._cache[cache_key] = profile
                    return profile
            except Exception as e:
                logger.warning(f"[HVIP] Redis get failed: {e}")

        return None

    def put(self, profile: HVIPConfig) -> None:
        """Persist an HVIP config."""
        profile.updated_at = time.time()
        cache_key  = f"{profile.tenant_id}:{profile.user_id}"
        self._cache[cache_key] = profile

        redis = self._get_redis()
        if redis:
            try:
                redis.set(
                    self._redis_key(profile.tenant_id, profile.user_id),
                    json.dumps(profile.to_dict()),
                    ex=_HVIP_REDIS_TTL,
                )
            except Exception as e:
                logger.warning(f"[HVIP] Redis put failed: {e}")

    def delete(self, tenant_id: str, user_id: str) -> bool:
        """Remove an HVIP config. Returns True if it existed."""
        cache_key = f"{tenant_id}:{user_id}"
        existed = cache_key in self._cache
        self._cache.pop(cache_key, None)

        redis = self._get_redis()
        if redis:
            try:
                deleted = redis.delete(self._redis_key(tenant_id, user_id))
                existed = existed or bool(deleted)
            except Exception as e:
                logger.warning(f"[HVIP] Redis delete failed: {e}")

        return existed

    def list_tenant_profiles(self, tenant_id: str) -> List[HVIPConfig]:
        """List all HVIP profiles for a tenant."""
        redis = self._get_redis()
        profiles: List[HVIPConfig] = []
        if redis:
            try:
                keys = redis.keys(f"{self._REDIS_KEY_PREFIX}:{tenant_id}:*")
                for key in keys:
                    raw = redis.get(key)
                    if raw:
                        profiles.append(HVIPConfig.from_dict(json.loads(raw)))
            except Exception as e:
                logger.warning(f"[HVIP] Redis list failed: {e}")
        return profiles


# ── Enforcer ──────────────────────────────────────────────────────────────────

class HVIPEnforcer:
    """
    Evaluates a request context against an identity's HVIP config.

    Called after base ML scoring — can override ALLOW to STEP_UP or REVOKE
    based on policy constraints the ML model doesn't know about.
    """

    def __init__(self, registry: Optional[HVIPRegistry] = None):
        self.registry = registry or HVIPRegistry()

    def evaluate(
        self,
        user_id: str,
        tenant_id: str,
        request_context: Dict[str, Any],
        base_decision: str = "allow",
        role: str = "readonly",
        token_issued_at: Optional[int] = None,
    ) -> HVIPEvaluationResult:
        """
        Evaluate a request against HVIP policy.

        Args:
            user_id:          Identity making the request
            tenant_id:        Tenant context
            request_context:  Dict with: country, asn, ip, has_dpop, has_hardware_mfa,
                              is_tor, impossible_travel, is_datacenter_ip, amr (list)
            base_decision:    Decision from base ML scoring (allow/step_up/block/revoke)
            role:             RBAC role of the token (owner/admin/analyst/readonly)
            token_issued_at:  Unix timestamp when the access token was issued

        Returns:
            HVIPEvaluationResult — final decision after HVIP policy overlay
        """
        start = time.monotonic()
        violations: List[HVIPViolation] = []

        # Load profile — auto-generate admin baseline if applicable
        profile = self.registry.get(tenant_id, user_id)
        auto_applied = False

        if profile is None and _HVIP_AUTO_ADMIN and role.upper() in ("OWNER", "ADMIN"):
            profile = HVIPConfig.default_admin_profile(user_id, tenant_id, role)
            auto_applied = True
            logger.debug(f"[HVIP] Auto-applied {role} baseline for {user_id}")

        if profile is None:
            # No profile — pass through base decision unchanged
            return HVIPEvaluationResult(
                decision=PolicyDecision(base_decision),
                violations=[],
                profile_applied=False,
                auto_applied=False,
                evaluation_ms=(time.monotonic() - start) * 1000,
            )

        # ── Policy checks ─────────────────────────────────────────────────────

        country = request_context.get("country", "")
        asn     = request_context.get("asn", 0)
        ip      = request_context.get("ip", "")
        has_dpop          = request_context.get("has_dpop", False)
        has_hardware_mfa  = request_context.get("has_hardware_mfa", False)
        amr               = request_context.get("amr", [])
        is_tor            = request_context.get("is_tor", False)
        impossible_travel = request_context.get("impossible_travel", False)
        is_datacenter     = request_context.get("is_datacenter_ip", False)
        ml_score          = request_context.get("ml_score", 100)

        # 1. Geo-lock check
        if profile.geo_lock and country and country.upper() not in [g.upper() for g in profile.geo_lock]:
            violations.append(HVIPViolation(
                violation_type=HVIPViolationType.GEO_LOCK,
                description=(
                    f"Request from country '{country}' not in geo-lock allowlist "
                    f"{profile.geo_lock} for high-value identity '{user_id}'."
                ),
                recommended_action=PolicyDecision.BLOCK,
                details={"country": country, "allowed": profile.geo_lock},
            ))

        # 2. ASN allowlist check
        if profile.allowed_asns and asn and asn not in profile.allowed_asns:
            violations.append(HVIPViolation(
                violation_type=HVIPViolationType.ASN_RESTRICTION,
                description=(
                    f"Request from ASN {asn} not in allowed ASN list "
                    f"{profile.allowed_asns[:5]}."
                ),
                recommended_action=PolicyDecision.STEP_UP,
                details={"asn": asn, "allowed_asns": profile.allowed_asns},
            ))

        # 3. DPoP requirement
        if profile.require_dpop and not has_dpop:
            violations.append(HVIPViolation(
                violation_type=HVIPViolationType.DPOP_REQUIRED,
                description=(
                    f"DPoP proof required for '{user_id}' but not presented. "
                    "IA-2(1): Hardware-bound proof of possession required."
                ),
                recommended_action=PolicyDecision.BLOCK,
                details={"require_dpop": True, "has_dpop": False},
            ))

        # 4. Hardware MFA requirement
        if profile.require_hardware_mfa:
            hw_signals = {"hwk", "fido", "cac", "piv", "swk+hwk"}
            has_hw = (
                has_hardware_mfa
                or any(a in hw_signals for a in amr)
                or "hwk" in amr
            )
            if not has_hw:
                violations.append(HVIPViolation(
                    violation_type=HVIPViolationType.HARDWARE_MFA,
                    description=(
                        f"Hardware MFA (FIDO2/PIV/CAC) required for '{user_id}' "
                        f"but amr={amr} does not indicate hardware key use. "
                        "IA-2(3): Physical authenticator required for OWNER access."
                    ),
                    recommended_action=PolicyDecision.STEP_UP,
                    details={"amr": amr, "required_amr": list(hw_signals)},
                ))

        # 5. Token age check
        if profile.max_token_age_seconds and token_issued_at:
            age_seconds = int(time.time()) - token_issued_at
            if age_seconds > profile.max_token_age_seconds:
                violations.append(HVIPViolation(
                    violation_type=HVIPViolationType.TOKEN_AGE,
                    description=(
                        f"Token age {age_seconds}s exceeds policy max "
                        f"{profile.max_token_age_seconds}s for '{user_id}'. "
                        "IA-11: Re-authentication required after session expiry."
                    ),
                    recommended_action=PolicyDecision.REVOKE,
                    details={
                        "token_age_seconds": age_seconds,
                        "max_age_seconds": profile.max_token_age_seconds,
                    },
                ))

        # 6. ML score floor
        if profile.min_allow_score and ml_score < profile.min_allow_score:
            violations.append(HVIPViolation(
                violation_type=HVIPViolationType.ANOMALY_OVERRIDE,
                description=(
                    f"ML risk score {ml_score} is below HVIP minimum "
                    f"{profile.min_allow_score} for high-value identity '{user_id}'."
                ),
                recommended_action=PolicyDecision.STEP_UP,
                details={"ml_score": ml_score, "min_allow_score": profile.min_allow_score},
            ))

        # 7. Anomaly override — any anomaly signal triggers step-up
        if profile.step_up_on_any_anomaly:
            anomalies = {
                "tor": is_tor,
                "impossible_travel": impossible_travel,
                "datacenter_ip": is_datacenter,
            }
            detected = {k: v for k, v in anomalies.items() if v}
            if detected:
                action = (
                    PolicyDecision.REVOKE
                    if (profile.revoke_on_high_anomaly and (is_tor or impossible_travel))
                    else PolicyDecision.STEP_UP
                )
                violations.append(HVIPViolation(
                    violation_type=HVIPViolationType.ANOMALY_OVERRIDE,
                    description=(
                        f"Anomaly signals detected for high-value identity '{user_id}': "
                        f"{list(detected.keys())}. Policy requires {action.value}."
                    ),
                    recommended_action=action,
                    details={"anomalies": detected},
                ))

        # 8. Time-of-day restriction
        if profile.allowed_hours_utc and len(profile.allowed_hours_utc) == 2:
            now_hour = int(time.gmtime().tm_hour)
            start_h, end_h = profile.allowed_hours_utc
            in_window = start_h <= now_hour < end_h
            if not in_window:
                violations.append(HVIPViolation(
                    violation_type=HVIPViolationType.TIME_OF_DAY,
                    description=(
                        f"Request at UTC hour {now_hour} outside allowed window "
                        f"{start_h}:00–{end_h}:00 UTC for '{user_id}'."
                    ),
                    recommended_action=PolicyDecision.BLOCK,
                    details={"current_hour_utc": now_hour, "allowed": profile.allowed_hours_utc},
                ))

        if profile.allowed_days_of_week:
            today = time.gmtime().tm_wday  # 0=Monday
            if today not in profile.allowed_days_of_week:
                violations.append(HVIPViolation(
                    violation_type=HVIPViolationType.TIME_OF_DAY,
                    description=(
                        f"Request on weekday {today} outside allowed days "
                        f"{profile.allowed_days_of_week} for '{user_id}'."
                    ),
                    recommended_action=PolicyDecision.BLOCK,
                    details={"current_day": today, "allowed_days": profile.allowed_days_of_week},
                ))

        # ── Determine final decision ──────────────────────────────────────────
        # Worst-case wins: REVOKE > BLOCK > STEP_UP > ALLOW
        _priority = {
            PolicyDecision.REVOKE:  4,
            PolicyDecision.BLOCK:   3,
            PolicyDecision.STEP_UP: 2,
            PolicyDecision.ALLOW:   1,
        }

        # Start with base decision
        final = PolicyDecision(base_decision) if base_decision in PolicyDecision._value2member_map_ else PolicyDecision.ALLOW
        for v in violations:
            if _priority[v.recommended_action] > _priority[final]:
                final = v.recommended_action

        step_up_reason = None
        revoke_reason  = None
        if violations:
            worst = max(violations, key=lambda v: _priority[v.recommended_action])
            if final == PolicyDecision.STEP_UP:
                step_up_reason = worst.description
            elif final in (PolicyDecision.REVOKE, PolicyDecision.BLOCK):
                revoke_reason  = worst.description

        elapsed_ms = (time.monotonic() - start) * 1000
        if violations:
            logger.warning(
                f"[HVIP] {len(violations)} violation(s) for user={user_id} "
                f"tenant={tenant_id} decision={final.value} "
                f"violations={[v.violation_type.value for v in violations]}"
            )

        return HVIPEvaluationResult(
            decision=final,
            violations=violations,
            profile_applied=True,
            auto_applied=auto_applied,
            evaluation_ms=elapsed_ms,
            step_up_reason=step_up_reason,
            revoke_reason=revoke_reason,
        )


# ── Singletons ────────────────────────────────────────────────────────────────

registry = HVIPRegistry()
enforcer = HVIPEnforcer(registry=registry)
