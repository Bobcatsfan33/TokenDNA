"""
TokenDNA — Pre-Issuance Risk Gate  (v2.5.0)

Evaluates token issuance requests *before* the IdP issues a credential.
If risk is too high the gate blocks the issuance entirely — the attacker
never gets a token, not even a revocable one.

Integration modes
─────────────────
1. Auth0    — Pre-Token-Generation Action (Node.js shim calls this via HTTP)
2. Okta     — Token Inline Hook
3. Keycloak — Authentication SPI / Event Listener (HTTP webhook)
4. Generic  — Any IdP that supports a pre-token webhook

Gate outcomes
─────────────
  ALLOW   — token issuance proceeds normally
  ENRICH  — token issuance proceeds with extra claims injected
  STEP_UP — force MFA step-up before issuance (deny for now, re-challenge)
  DENY    — block issuance entirely (HTTP 403 to IdP hook endpoint)

Risk signals checked (in order, worst-case wins)
─────────────────────────────────────────────────
  1. Global revocation list — is this uid/tenant globally blocked?
  2. Impossible travel      — login from two distant locations within Δt
  3. Threat intelligence    — Tor exit, known-bad ASN, VPN/proxy flags
  4. New device fingerprint — first-ever device for this uid
  5. Credential stuffing    — too many failed logins from same IP/subnet
  6. Velocity               — too many tokens issued for this uid in window
  7. HVIP policy            — high-value identity: geo-lock, time-of-day
  8. Anomaly ML score       — existing TokenDNA baseline (if available)

NIST 800-53 Rev5: IA-5 (authenticator management), IA-11 (re-authentication),
                  AC-2 (account management), SI-4 (information system monitoring).
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────

_VELOCITY_WINDOW_SECONDS = int(os.getenv("PREFLIGHT_VELOCITY_WINDOW", "3600"))   # 1 hour
_VELOCITY_MAX_TOKENS     = int(os.getenv("PREFLIGHT_VELOCITY_MAX", "20"))         # max tokens/hr
_IMPOSSIBLE_TRAVEL_KMH   = float(os.getenv("PREFLIGHT_MAX_SPEED_KMH", "900"))    # ~jet speed
_CRED_STUFF_THRESHOLD    = int(os.getenv("PREFLIGHT_CRED_STUFF_MAX", "10"))       # failed logins/15m
_HIGH_RISK_DENY_SCORE    = float(os.getenv("PREFLIGHT_DENY_SCORE", "85.0"))       # deny above this
_STEP_UP_SCORE           = float(os.getenv("PREFLIGHT_STEP_UP_SCORE", "60.0"))    # step-up above this


# ── Enums and data models ──────────────────────────────────────────────────────

class GateDecision(str, Enum):
    ALLOW   = "allow"
    ENRICH  = "enrich"    # Allow but inject extra claims
    STEP_UP = "step_up"   # Force re-authentication
    DENY    = "deny"      # Block issuance


@dataclass
class PreflightContext:
    """
    Everything known about the token issuance request.
    Populated from IdP webhook payload and enriched by TokenDNA signals.
    """
    uid:             str
    tenant_id:       str
    client_id:       str                   # OAuth client requesting the token
    requested_scopes: List[str]
    ip:              str
    user_agent:      str
    idp:             str                   # "auth0" | "okta" | "keycloak" | "generic"
    country:         Optional[str] = None
    asn:             Optional[str] = None
    isp:             Optional[str] = None
    lat:             Optional[float] = None
    lon:             Optional[float] = None
    device_id:       Optional[str] = None  # From IdP session / device fingerprint
    login_method:    str = "password"      # "password" | "mfa" | "sso" | "refresh"
    requested_at:    float = field(default_factory=time.time)
    raw_payload:     Dict[str, Any] = field(default_factory=dict)


@dataclass
class GateSignal:
    """Individual risk signal with weight and evidence."""
    name:      str
    triggered: bool
    weight:    float         # Contribution to risk score (0–100)
    evidence:  str           # Human-readable explanation
    mitre:     Optional[str] = None
    nist:      Optional[str] = None


@dataclass
class PreflightResult:
    """Full gate evaluation result."""
    decision:     GateDecision
    risk_score:   float              # 0–100; higher = riskier
    signals:      List[GateSignal]
    deny_reason:  Optional[str]
    enrich_claims: Dict[str, Any]    # Extra claims to inject if ENRICH
    uid:          str
    tenant_id:    str
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "decision":     self.decision.value,
            "risk_score":   round(self.risk_score, 2),
            "deny_reason":  self.deny_reason,
            "enrich_claims": self.enrich_claims,
            "signals": [
                {
                    "name":      s.name,
                    "triggered": s.triggered,
                    "weight":    s.weight,
                    "evidence":  s.evidence,
                }
                for s in self.signals
                if s.triggered
            ],
            "evaluated_at": self.evaluated_at,
        }

    def to_auth0_action_response(self) -> dict:
        """
        Auth0 Pre-Token-Generation Action response format.
        https://auth0.com/docs/customize/actions/flows-and-triggers/login-flow
        """
        if self.decision == GateDecision.DENY:
            return {
                "type": "DENY",
                "message": self.deny_reason or "Access denied by security policy.",
            }
        if self.decision == GateDecision.STEP_UP:
            return {
                "type": "REDIRECT",
                "redirectUri": os.getenv("STEP_UP_REDIRECT_URI", "/mfa-challenge"),
                "queryParams": {"reason": "security_policy"},
            }
        # ALLOW or ENRICH — inject extra claims
        return {
            "type":      "CONTINUE",
            "accessToken": {"customClaims": self.enrich_claims},
        }

    def to_okta_hook_response(self) -> dict:
        """
        Okta Token Inline Hook response format.
        https://developer.okta.com/docs/reference/token-hook/
        """
        if self.decision == GateDecision.DENY:
            return {
                "error": {
                    "errorSummary": self.deny_reason or "Token issuance blocked by security gate.",
                    "errorCauses":  [{"errorSummary": "PREFLIGHT_DENY"}],
                }
            }
        commands = []
        if self.enrich_claims:
            for k, v in self.enrich_claims.items():
                commands.append({
                    "type":  "com.okta.tokens.claims.add",
                    "value": {"name": k, "value": v, "system": False},
                })
        return {"commands": commands}

    def to_keycloak_hook_response(self) -> dict:
        """
        Keycloak Event Listener / Authentication SPI response.
        Returns HTTP 403 + body on DENY, 200 + claims on ALLOW/ENRICH.
        """
        if self.decision == GateDecision.DENY:
            return {
                "deny":   True,
                "reason": self.deny_reason,
            }
        return {
            "deny":   False,
            "claims": self.enrich_claims,
        }


# ── Risk signal checks ────────────────────────────────────────────────────────

class PreflightGate:
    """
    Evaluates token issuance requests against a multi-signal risk model.
    Instantiate once at module load; call .evaluate(ctx) per request.
    """

    def __init__(self):
        pass

    # ── 1. Global revocation list ─────────────────────────────────────────────

    def _check_global_block(self, ctx: PreflightContext) -> GateSignal:
        try:
            from modules.identity.cache_redis import get_redis
            r   = get_redis()
            key = f"global_block:{ctx.tenant_id}:{ctx.uid}"
            blocked = r.exists(key)
            if blocked:
                reason = r.get(key)
                return GateSignal(
                    name="global_block", triggered=True, weight=100.0,
                    evidence=f"UID globally blocked: {reason.decode() if reason else 'revoked'}",
                    mitre="T1078", nist="AC-2",
                )
        except Exception:
            pass
        return GateSignal(name="global_block", triggered=False, weight=0.0, evidence="Not blocked")

    # ── 2. Impossible travel ──────────────────────────────────────────────────

    def _check_impossible_travel(self, ctx: PreflightContext) -> GateSignal:
        if ctx.lat is None or ctx.lon is None:
            return GateSignal(name="impossible_travel", triggered=False,
                              weight=0.0, evidence="No geo data available")
        try:
            from modules.identity.cache_redis import get_redis
            r     = get_redis()
            key   = f"t:{ctx.tenant_id}:last_login:{ctx.uid}"
            raw   = r.hgetall(key)
            if not raw:
                # First login — store and allow
                r.hset(key, mapping={
                    "lat": ctx.lat, "lon": ctx.lon, "ts": ctx.requested_at,
                    "ip": ctx.ip,
                })
                r.expire(key, 86400)
                return GateSignal(name="impossible_travel", triggered=False,
                                  weight=0.0, evidence="First login location recorded")

            prev_lat = float(raw.get(b"lat", raw.get("lat", 0)))
            prev_lon = float(raw.get(b"lon", raw.get("lon", 0)))
            prev_ts  = float(raw.get(b"ts",  raw.get("ts",  ctx.requested_at)))

            dist_km  = _haversine(prev_lat, prev_lon, ctx.lat, ctx.lon)
            delta_h  = max((ctx.requested_at - prev_ts) / 3600, 0.001)
            speed_kph = dist_km / delta_h

            # Update last login
            r.hset(key, mapping={
                "lat": ctx.lat, "lon": ctx.lon, "ts": ctx.requested_at, "ip": ctx.ip,
            })
            r.expire(key, 86400)

            if speed_kph > _IMPOSSIBLE_TRAVEL_KMH:
                return GateSignal(
                    name="impossible_travel", triggered=True,
                    weight=70.0,
                    evidence=(
                        f"Impossible travel: {dist_km:.0f} km in {delta_h*60:.0f} min "
                        f"({speed_kph:.0f} km/h > threshold {_IMPOSSIBLE_TRAVEL_KMH:.0f})"
                    ),
                    mitre="T1078.001", nist="IA-11",
                )
        except Exception as e:
            logger.debug("Impossible travel check failed: %s", e)
        return GateSignal(name="impossible_travel", triggered=False,
                          weight=0.0, evidence="Travel velocity within bounds")

    # ── 3. Threat intelligence ────────────────────────────────────────────────

    def _check_threat_intel(self, ctx: PreflightContext) -> GateSignal:
        try:
            from modules.identity.threat_intel import enrich
            from modules.identity.cache_redis import get_redis
            threat = enrich(ctx.ip, asn=ctx.asn, isp=ctx.isp, redis_client=get_redis())
            score  = threat.score if hasattr(threat, "score") else 0
            flags  = []
            if getattr(threat, "is_tor",   False): flags.append("Tor exit node")
            if getattr(threat, "is_vpn",   False): flags.append("VPN/proxy")
            if getattr(threat, "is_dchost",False): flags.append("datacenter IP")
            if getattr(threat, "is_known_bad", False): flags.append("known-bad ASN")
            if flags or score > 40:
                return GateSignal(
                    name="threat_intel", triggered=True,
                    weight=min(score * 0.8, 80.0),
                    evidence=f"IP threat signals: {', '.join(flags) or f'score={score}'}",
                    mitre="T1090", nist="SI-4",
                )
        except Exception as e:
            logger.debug("Threat intel check failed: %s", e)
        return GateSignal(name="threat_intel", triggered=False,
                          weight=0.0, evidence="No threat signals")

    # ── 4. New device fingerprint ─────────────────────────────────────────────

    def _check_new_device(self, ctx: PreflightContext) -> GateSignal:
        if not ctx.device_id:
            return GateSignal(name="new_device", triggered=False,
                              weight=0.0, evidence="No device fingerprint provided")
        try:
            from modules.identity.cache_redis import get_redis
            r       = get_redis()
            key     = f"t:{ctx.tenant_id}:devices:{ctx.uid}"
            # Use device_id hash to avoid PII in Redis keys
            dev_hash = hashlib.sha256(ctx.device_id.encode()).hexdigest()[:16]
            seen    = r.sismember(key, dev_hash)
            if not seen:
                r.sadd(key, dev_hash)
                r.expire(key, 90 * 86400)   # 90-day device memory
                # First time seeing this device — flag but don't block
                existing = r.scard(key)
                weight = 25.0 if existing > 1 else 5.0  # More suspicious if user has prior devices
                return GateSignal(
                    name="new_device", triggered=True, weight=weight,
                    evidence=f"New device fingerprint (user has {existing-1} prior devices)",
                    mitre="T1078", nist="IA-5",
                )
        except Exception as e:
            logger.debug("New device check failed: %s", e)
        return GateSignal(name="new_device", triggered=False,
                          weight=0.0, evidence="Known device")

    # ── 5. Credential stuffing / brute force ──────────────────────────────────

    def _check_credential_stuffing(self, ctx: PreflightContext) -> GateSignal:
        try:
            from modules.identity.cache_redis import get_redis
            r   = get_redis()
            key = f"failed_logins:{ctx.ip}"
            raw = r.get(key)
            count = int(raw) if raw else 0
            if count >= _CRED_STUFF_THRESHOLD:
                return GateSignal(
                    name="credential_stuffing", triggered=True,
                    weight=65.0,
                    evidence=f"{count} failed logins from {ctx.ip} in past 15 min (threshold: {_CRED_STUFF_THRESHOLD})",
                    mitre="T1110.004", nist="SI-4",
                )
        except Exception as e:
            logger.debug("Cred stuffing check failed: %s", e)
        return GateSignal(name="credential_stuffing", triggered=False,
                          weight=0.0, evidence="Failed login count within threshold")

    # ── 6. Token velocity ─────────────────────────────────────────────────────

    def _check_velocity(self, ctx: PreflightContext) -> GateSignal:
        try:
            from modules.identity.cache_redis import get_redis
            r   = get_redis()
            key = f"t:{ctx.tenant_id}:token_velocity:{ctx.uid}"
            # Sliding window counter
            now = ctx.requested_at
            r.zadd(key, {str(now): now})
            r.zremrangebyscore(key, 0, now - _VELOCITY_WINDOW_SECONDS)
            count = r.zcard(key)
            r.expire(key, _VELOCITY_WINDOW_SECONDS)

            if count > _VELOCITY_MAX_TOKENS:
                return GateSignal(
                    name="token_velocity", triggered=True,
                    weight=50.0,
                    evidence=(
                        f"{count} tokens issued in {_VELOCITY_WINDOW_SECONDS//60} min "
                        f"(limit: {_VELOCITY_MAX_TOKENS})"
                    ),
                    mitre="T1078", nist="AC-2",
                )
        except Exception as e:
            logger.debug("Velocity check failed: %s", e)
        return GateSignal(name="token_velocity", triggered=False,
                          weight=0.0, evidence="Token velocity within bounds")

    # ── 7. HVIP policy ────────────────────────────────────────────────────────

    def _check_hvip(self, ctx: PreflightContext) -> GateSignal:
        try:
            from modules.identity.hvip import enforcer as _hvip, HVIPDecision
            hvip_ctx = {
                "ip":              ctx.ip,
                "country":         ctx.country or "",
                "asn":             ctx.asn or "",
                "has_dpop":        False,   # Pre-issuance — DPoP not yet available
                "has_hardware_mfa": ctx.login_method in ("mfa", "fido"),
                "token_issued_at": None,
                "anomaly_score":   0,
                "anomaly_reasons": [],
                "request_id":      "",
                "tenant_id":       ctx.tenant_id,
                "role":            "unknown",
            }
            # Get user's role from request context if embedded
            role = ctx.raw_payload.get("role", ctx.raw_payload.get("user_role", "user"))
            hvip_ctx["role"] = role

            decision = _hvip.evaluate(ctx.uid, ctx.tenant_id, role, hvip_ctx)
            if decision in (HVIPDecision.BLOCK, HVIPDecision.REVOKE):
                return GateSignal(
                    name="hvip_policy", triggered=True, weight=80.0,
                    evidence=f"HVIP policy violation for {role}: {decision.value}",
                    mitre="T1078.003", nist="IA-5",
                )
            if decision == HVIPDecision.STEP_UP:
                return GateSignal(
                    name="hvip_policy", triggered=True, weight=45.0,
                    evidence=f"HVIP step-up required for {role}",
                    mitre="T1078", nist="IA-11",
                )
        except Exception as e:
            logger.debug("HVIP check failed: %s", e)
        return GateSignal(name="hvip_policy", triggered=False,
                          weight=0.0, evidence="HVIP policy satisfied")

    # ── 8. ML anomaly score ───────────────────────────────────────────────────

    def _check_ml_score(self, ctx: PreflightContext) -> GateSignal:
        try:
            from modules.identity.cache_redis import get_redis, TenantRedis
            from modules.identity import ml_model, geo_intel, token_dna
            r  = get_redis()
            tr = TenantRedis(r, ctx.tenant_id)
            geo     = geo_intel.lookup(ctx.ip, redis_client=r)
            current = token_dna.generate_dna(ctx.user_agent, ctx.ip,
                                              geo.country if geo else "",
                                              str(geo.asn) if geo else "")
            score = ml_model.score(ctx.uid, current, redis=tr)
            if score is not None and score > _HIGH_RISK_DENY_SCORE:
                return GateSignal(
                    name="ml_anomaly", triggered=True,
                    weight=min(float(score), 90.0),
                    evidence=f"ML anomaly score {score:.1f} > deny threshold {_HIGH_RISK_DENY_SCORE}",
                    mitre="T1078", nist="SI-4",
                )
            if score is not None and score > _STEP_UP_SCORE:
                return GateSignal(
                    name="ml_anomaly", triggered=True,
                    weight=float(score) * 0.6,
                    evidence=f"ML anomaly score {score:.1f} above step-up threshold {_STEP_UP_SCORE}",
                    mitre="T1078", nist="SI-4",
                )
        except Exception as e:
            logger.debug("ML score check failed: %s", e)
        return GateSignal(name="ml_anomaly", triggered=False,
                          weight=0.0, evidence="ML score within normal range")

    # ── Gate evaluation ───────────────────────────────────────────────────────

    def evaluate(self, ctx: PreflightContext) -> PreflightResult:
        """
        Run all signal checks and return a GateDecision.
        Signals are evaluated in priority order; worst-case wins.
        """
        from modules.identity.geo_intel import lookup as geo_lookup
        from modules.identity.cache_redis import get_redis

        # Enrich geo if not already populated
        if ctx.country is None or ctx.asn is None:
            try:
                geo = geo_lookup(ctx.ip, redis_client=get_redis())
                if geo:
                    ctx.country = ctx.country or geo.country
                    ctx.asn     = ctx.asn or str(geo.asn)
                    ctx.isp     = ctx.isp or getattr(geo, "isp", None)
                    ctx.lat     = ctx.lat or getattr(geo, "lat", None)
                    ctx.lon     = ctx.lon or getattr(geo, "lon", None)
            except Exception:
                pass

        signals: List[GateSignal] = [
            self._check_global_block(ctx),
            self._check_impossible_travel(ctx),
            self._check_threat_intel(ctx),
            self._check_new_device(ctx),
            self._check_credential_stuffing(ctx),
            self._check_velocity(ctx),
            self._check_hvip(ctx),
            self._check_ml_score(ctx),
        ]

        triggered = [s for s in signals if s.triggered]

        # Risk score = weighted sum, capped at 100
        risk_score = min(sum(s.weight for s in triggered), 100.0)

        # Decision logic — worst-case wins
        decision    = GateDecision.ALLOW
        deny_reason = None

        # Hard blocks (global_block or any signal with weight=100)
        hard_block = any(s.name == "global_block" and s.triggered for s in signals)
        if hard_block:
            decision    = GateDecision.DENY
            deny_reason = next(s.evidence for s in signals if s.name == "global_block" and s.triggered)
        elif risk_score >= _HIGH_RISK_DENY_SCORE:
            decision    = GateDecision.DENY
            top_signals = sorted(triggered, key=lambda s: s.weight, reverse=True)
            deny_reason = "; ".join(s.evidence for s in top_signals[:3])
        elif risk_score >= _STEP_UP_SCORE:
            decision = GateDecision.STEP_UP
        elif triggered:
            # Low-risk signals: allow but inject risk metadata as claims
            decision = GateDecision.ENRICH

        # Build enrichment claims (injected for ALLOW / ENRICH decisions)
        enrich_claims: Dict[str, Any] = {}
        if decision in (GateDecision.ALLOW, GateDecision.ENRICH):
            enrich_claims["https://aegis.io/risk_score"] = round(risk_score, 2)
            enrich_claims["https://aegis.io/preflight"]  = "pass"
            enrich_claims["https://aegis.io/signals"]    = [s.name for s in triggered]
            if ctx.country:
                enrich_claims["https://aegis.io/country"] = ctx.country

        # Audit log every decision
        try:
            from modules.security.audit_log import AuditEventType, AuditOutcome, log_event
            outcome = AuditOutcome.SUCCESS if decision in (GateDecision.ALLOW, GateDecision.ENRICH) else AuditOutcome.FAILURE
            log_event(
                AuditEventType.ACCESS_GRANTED if outcome == AuditOutcome.SUCCESS else AuditEventType.ACCESS_DENIED,
                outcome,
                tenant_id=ctx.tenant_id,
                subject=ctx.uid,
                resource=f"preflight:{ctx.client_id}",
                detail={
                    "gate_decision":    decision.value,
                    "risk_score":       round(risk_score, 2),
                    "signals_triggered": [s.name for s in triggered],
                    "ip":               ctx.ip,
                    "country":          ctx.country,
                    "idp":              ctx.idp,
                },
            )
        except Exception:
            pass

        return PreflightResult(
            decision=decision,
            risk_score=risk_score,
            signals=signals,
            deny_reason=deny_reason,
            enrich_claims=enrich_claims,
            uid=ctx.uid,
            tenant_id=ctx.tenant_id,
        )


# ── Geo helpers ───────────────────────────────────────────────────────────────

def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Return great-circle distance in km between two lat/lon points."""
    R    = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a    = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


# ── FastAPI endpoint builders ─────────────────────────────────────────────────

# Module-level singleton
_gate = PreflightGate()


def build_preflight_context(body: dict, idp: str = "generic") -> PreflightContext:
    """
    Normalise an IdP webhook payload into a PreflightContext.
    Handles Auth0, Okta, Keycloak, and generic payloads.
    """
    if idp == "auth0":
        return PreflightContext(
            uid=body.get("user", {}).get("user_id", body.get("sub", "")),
            tenant_id=body.get("request", {}).get("hostname", "default"),
            client_id=body.get("client", {}).get("client_id", ""),
            requested_scopes=body.get("transaction", {}).get("requested_scopes", []),
            ip=body.get("request", {}).get("ip", ""),
            user_agent=body.get("request", {}).get("user_agent", ""),
            idp="auth0",
            country=body.get("request", {}).get("geoip", {}).get("country_code"),
            raw_payload=body,
        )
    elif idp == "okta":
        data    = body.get("data", {})
        context = data.get("context", {})
        return PreflightContext(
            uid=data.get("userProfile", {}).get("login", data.get("userId", "")),
            tenant_id=context.get("protocol", {}).get("client", {}).get("id", "okta"),
            client_id=context.get("protocol", {}).get("client", {}).get("id", ""),
            requested_scopes=context.get("protocol", {}).get("request", {}).get("scope", "").split(),
            ip=context.get("session", {}).get("userAgent", {}).get("ipAddress", ""),
            user_agent=context.get("session", {}).get("userAgent", {}).get("rawUserAgent", ""),
            idp="okta",
            raw_payload=body,
        )
    elif idp == "keycloak":
        return PreflightContext(
            uid=body.get("userId", body.get("sub", "")),
            tenant_id=body.get("realmId", body.get("realm", "master")),
            client_id=body.get("clientId", ""),
            requested_scopes=body.get("scope", "").split(),
            ip=body.get("ipAddress", ""),
            user_agent=body.get("details", {}).get("userAgent", ""),
            idp="keycloak",
            raw_payload=body,
        )
    else:  # generic
        return PreflightContext(
            uid=body.get("sub", body.get("user_id", body.get("uid", ""))),
            tenant_id=body.get("tenant_id", "default"),
            client_id=body.get("client_id", ""),
            requested_scopes=body.get("scope", "").split() if isinstance(body.get("scope"), str) else body.get("scope", []),
            ip=body.get("ip", body.get("client_ip", "")),
            user_agent=body.get("user_agent", ""),
            idp="generic",
            country=body.get("country"),
            device_id=body.get("device_id"),
            login_method=body.get("login_method", "password"),
            raw_payload=body,
        )


def evaluate_preflight(body: dict, idp: str = "generic") -> PreflightResult:
    """
    Convenience wrapper — parse body, evaluate, persist stats, return result.
    Persists decision + signal counts to Redis for the Attribution Dashboard.
    AU-2 / SI-4: event logging and monitoring.
    """
    ctx    = build_preflight_context(body, idp=idp)
    result = _gate.evaluate(ctx)
    _store_gate_stats(ctx, result)
    return result


def _store_gate_stats(ctx: "PreflightContext", result: "PreflightResult") -> None:
    """
    Persist gate decision and signal trigger counts to Redis for analytics.
    Keys:
      preflight:decisions:{tenant_id}:{YYYY-MM-DD}  → hash {allow, enrich, step_up, deny}
      preflight:signals:{tenant_id}:{YYYY-MM-DD}    → hash {signal_name: count}
    Both keys expire after 90 days to bound Redis memory.
    """
    try:
        from modules.identity.cache_redis import get_redis
        from datetime import datetime, timezone
        r   = get_redis()
        tid = ctx.tenant_id or "global"
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        ttl = 90 * 86400  # 90-day retention

        # Decision counter
        dec_key = f"preflight:decisions:{tid}:{day}"
        r.hincrby(dec_key, result.decision.value, 1)
        r.expire(dec_key, ttl)

        # Signal trigger counters
        sig_key = f"preflight:signals:{tid}:{day}"
        for signal in result.signals:
            if signal.triggered:
                r.hincrby(sig_key, signal.name, 1)
        r.expire(sig_key, ttl)

    except Exception as e:
        # Non-fatal — attribution stats are best-effort
        logger.debug("Failed to persist preflight gate stats: %s", e)
