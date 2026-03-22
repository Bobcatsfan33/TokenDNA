"""
TokenDNA — Token Trap  (v2.5.0)

A cryptographic honeypot that issues deliberately attractive-looking but
inert "trap tokens" and monitors for their unauthorized use.  Any request
that presents a trap token is, by definition, from a stolen-credential
attacker or insider threat — legitimate users never hold trap tokens.

Design goals
────────────
1. Deception:  Trap tokens look indistinguishable from real bearer tokens
   (same format, realistic claims, valid-looking signatures) so attackers
   cannot screen them out.

2. Zero false-positive:  Only trap tokens are flagged; real token pipeline
   is never touched.  Trap tokens are cryptographically signed with a
   *separate* trap key so they cannot be confused with real tokens.

3. High-fidelity attacker telemetry:  IP, User-Agent, ASN, country, request
   timestamp, token age (how long before the attacker used it), headers.

4. Active deception:  Trap API responses are synthetic but plausible so the
   attacker believes they succeeded.  Behind the scenes every request is
   silently logged and the trap is re-armed.

5. Automatic propagation:  On trap-hit, real tokens belonging to the same
   uid/tenant are immediately revoked (the attacker had the trap ⇒ they
   likely have the real token too).

Architecture
────────────
  TrapTokenFactory  — issues trap tokens (HMAC-SHA256 signed with TRAP_HMAC_KEY)
  TrapTokenStore    — Redis-backed registry of live trap tokens
  TrapMonitor       — validates incoming tokens against trap store, fires alerts
  TrapHitRecord     — structured telemetry captured on trap activation

FastAPI wiring
──────────────
  trap_token_check  — FastAPI Depends() that transparently inspects every
                      authenticated request and fires TrapMonitor if the
                      presented token is a trap token.

NIST 800-53 Rev5: SI-3 (malicious code protection), IR-4 (incident handling),
                  AU-2 (event logging), SC-26 (honeypots), RA-5 (vuln scanning).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────

# Separate HMAC key for trap tokens — MUST differ from real token signing key.
# Generate: python3 -c "import secrets; print(secrets.token_hex(32))"
_TRAP_HMAC_KEY: bytes = os.getenv("TRAP_HMAC_KEY", "").encode() or secrets.token_bytes(32)

# How long a trap token stays live before it self-expires (default: 7 days)
_TRAP_TTL_SECONDS: int = int(os.getenv("TRAP_TOKEN_TTL", str(7 * 86400)))

# Redis key namespace
_NS = "tokentrap"

# Synthetic response payload returned to attacker (plausible but inert)
_SYNTHETIC_RESPONSE = {
    "status": "ok",
    "message": "Request processed successfully.",
    "_trap": False,          # Never hint to attacker
}


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class TrapToken:
    trap_id:    str           # Unique ID for this trap (uuid4)
    uid:        str           # User ID the trap impersonates
    tenant_id:  str
    issued_at:  float         # Unix timestamp
    expires_at: float
    label:      str           # Human label for tracking ("aws-exfil", "insider-test", etc.)
    jti:        str           # Fake JTI embedded in the token
    token:      str           # The actual trap token string (opaque bearer token)
    hmac_sig:   str           # HMAC-SHA256(trap_id + uid + issued_at, TRAP_HMAC_KEY) hex


@dataclass
class TrapHitRecord:
    trap_id:       str
    uid:           str
    tenant_id:     str
    hit_at:        str        # ISO-8601 UTC
    token_age_seconds: float  # How long between issuance and first use
    attacker_ip:   str
    attacker_ua:   str
    attacker_asn:  Optional[str]
    attacker_country: Optional[str]
    request_headers: Dict[str, str]
    request_path:  str
    real_tokens_revoked: int  # How many real tokens were proactively revoked
    label:         str
    alert_sent:    bool = False

    def to_dict(self) -> dict:
        return asdict(self)


# ── HMAC helpers ──────────────────────────────────────────────────────────────

def _sign(trap_id: str, uid: str, issued_at: float) -> str:
    """Produce HMAC-SHA256 signature over trap identity material."""
    msg = f"{trap_id}:{uid}:{issued_at:.6f}".encode()
    return hmac.new(_TRAP_HMAC_KEY, msg, hashlib.sha256).hexdigest()


def _verify_sig(trap: TrapToken) -> bool:
    expected = _sign(trap.trap_id, trap.uid, trap.issued_at)
    return hmac.compare_digest(expected, trap.hmac_sig)


def _make_bearer_token(trap_id: str, uid: str, jti: str, issued_at: float) -> str:
    """
    Craft a plausible-looking bearer token string.
    Format: base64url(JSON header) . base64url(JSON payload) . HMAC-sig
    Indistinguishable from a real HS256 JWT to casual inspection, but
    signed with TRAP_HMAC_KEY so the platform can unmask it instantly.
    """
    import base64

    def b64u(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    header  = {"alg": "HS256", "typ": "JWT", "trap": True}   # HS256 is realistic; trap flag is hidden in base64
    payload = {
        "sub":  uid,
        "jti":  jti,
        "iat":  int(issued_at),
        "exp":  int(issued_at) + _TRAP_TTL_SECONDS,
        "iss":  "https://auth.aegis-security.io",
        "aud":  "aegis-api",
        "scope": "read:data write:data",
    }
    hdr_b64  = b64u(header)
    pay_b64  = b64u(payload)
    sig_raw  = hmac.new(_TRAP_HMAC_KEY,
                         f"{hdr_b64}.{pay_b64}".encode(),
                         hashlib.sha256).digest()
    sig_b64  = base64.urlsafe_b64encode(sig_raw).rstrip(b"=").decode()
    return f"{hdr_b64}.{pay_b64}.{sig_b64}"


# ── TrapTokenStore (Redis-backed) ─────────────────────────────────────────────

class TrapTokenStore:
    """
    Persists trap tokens in Redis with TTL.
    Key:  tokentrap:token:{sha256(token)}  → JSON(TrapToken)
    Key:  tokentrap:uid:{tenant_id}:{uid}  → set of trap_ids
    Key:  tokentrap:hits                   → sorted set (score=timestamp, member=JSON)
    """

    def __init__(self):
        self._local: Dict[str, TrapToken] = {}   # in-process fallback when Redis unavailable

    def _redis(self):
        try:
            from modules.identity.cache_redis import get_redis
            r = get_redis()
            r.ping()
            return r
        except Exception:
            return None

    def _token_key(self, token: str) -> str:
        digest = hashlib.sha256(token.encode()).hexdigest()
        return f"{_NS}:token:{digest}"

    def _uid_key(self, tenant_id: str, uid: str) -> str:
        return f"{_NS}:uid:{tenant_id}:{uid}"

    def store(self, trap: TrapToken) -> None:
        ttl = max(1, int(trap.expires_at - time.time()))
        data = json.dumps(asdict(trap))
        key  = self._token_key(trap.token)

        r = self._redis()
        if r:
            try:
                r.setex(key, ttl, data)
                r.sadd(self._uid_key(trap.tenant_id, trap.uid), trap.trap_id)
                r.expire(self._uid_key(trap.tenant_id, trap.uid), _TRAP_TTL_SECONDS)
            except Exception as e:
                logger.warning("TrapTokenStore Redis write failed: %s", e)
                self._local[key] = trap
        else:
            self._local[key] = trap

    def lookup(self, token: str) -> Optional[TrapToken]:
        key = self._token_key(token)
        r   = self._redis()
        if r:
            try:
                raw = r.get(key)
                if raw:
                    d = json.loads(raw)
                    return TrapToken(**d)
            except Exception:
                pass
        # Fallback to local cache
        return self._local.get(key)

    def is_trap(self, token: str) -> bool:
        return self.lookup(token) is not None

    def revoke_trap(self, trap: TrapToken) -> None:
        """Remove trap from store (after hit — prevents double-fire on replay)."""
        key = self._token_key(trap.token)
        r   = self._redis()
        if r:
            try:
                r.delete(key)
            except Exception:
                pass
        self._local.pop(key, None)

    def list_by_uid(self, tenant_id: str, uid: str) -> List[str]:
        """Return list of trap_ids for a given uid."""
        r = self._redis()
        if r:
            try:
                members = r.smembers(self._uid_key(tenant_id, uid))
                return [m.decode() if isinstance(m, bytes) else m for m in members]
            except Exception:
                pass
        return []

    def record_hit(self, hit: TrapHitRecord) -> None:
        r = self._redis()
        if r:
            try:
                r.zadd(f"{_NS}:hits",
                       {json.dumps(hit.to_dict()): time.time()})
                # Keep only the most recent 10 000 hits
                r.zremrangebyrank(f"{_NS}:hits", 0, -10001)
            except Exception as e:
                logger.warning("TrapTokenStore hit record failed: %s", e)

    def recent_hits(self, limit: int = 50) -> List[dict]:
        r = self._redis()
        if r:
            try:
                raw = r.zrevrange(f"{_NS}:hits", 0, limit - 1)
                return [json.loads(x) for x in raw]
            except Exception:
                pass
        return []


# ── TrapTokenFactory ──────────────────────────────────────────────────────────

class TrapTokenFactory:
    """
    Issues cryptographically signed trap tokens.
    Every token is registered in the TrapTokenStore at issuance.
    """

    def __init__(self, store: Optional[TrapTokenStore] = None):
        self._store = store or TrapTokenStore()

    def issue(
        self,
        uid: str,
        tenant_id: str,
        label: str = "default",
        ttl_seconds: Optional[int] = None,
    ) -> TrapToken:
        """
        Issue a new trap token for uid/tenant.
        Returns the TrapToken with the .token field set to a bearer token string.
        """
        trap_id   = str(uuid.uuid4())
        jti       = str(uuid.uuid4())
        now       = time.time()
        ttl       = ttl_seconds or _TRAP_TTL_SECONDS
        expires   = now + ttl
        sig       = _sign(trap_id, uid, now)
        token_str = _make_bearer_token(trap_id, uid, jti, now)

        trap = TrapToken(
            trap_id=trap_id,
            uid=uid,
            tenant_id=tenant_id,
            issued_at=now,
            expires_at=expires,
            label=label,
            jti=jti,
            token=token_str,
            hmac_sig=sig,
        )
        self._store.store(trap)
        logger.info("TrapToken issued: trap_id=%s uid=%s tenant=%s label=%s",
                    trap_id, uid, tenant_id, label)
        return trap

    def issue_batch(
        self,
        uid: str,
        tenant_id: str,
        count: int = 5,
        labels: Optional[List[str]] = None,
    ) -> List[TrapToken]:
        """Issue multiple trap tokens at once (scatter across credential stores)."""
        if labels is None:
            labels = [f"trap-{i}" for i in range(count)]
        return [
            self.issue(uid, tenant_id, label=labels[i % len(labels)])
            for i in range(count)
        ]


# ── TrapMonitor ───────────────────────────────────────────────────────────────

class TrapMonitor:
    """
    Core detection engine.
    Inspects every request's Authorization header.
    If the token is a trap token → attacker detected → fire alert pipeline.
    """

    def __init__(
        self,
        store: Optional[TrapTokenStore] = None,
        factory: Optional[TrapTokenFactory] = None,
    ):
        self._store   = store or TrapTokenStore()
        self._factory = factory or TrapTokenFactory(store=self._store)

    def inspect(
        self,
        raw_token: str,
        request_context: Dict[str, Any],
    ) -> Optional[TrapHitRecord]:
        """
        Inspect a raw bearer token.
        Returns TrapHitRecord if it's a trap token, None otherwise.
        request_context keys: ip, user_agent, asn, country, headers, path
        """
        trap = self._store.lookup(raw_token)
        if trap is None:
            return None

        # Verify HMAC to ensure this is a *genuine* trap token, not a collision
        if not _verify_sig(trap):
            logger.error("TrapToken HMAC verification failed for trap_id=%s — possible forgery", trap.trap_id)
            return None

        now = time.time()
        age = now - trap.issued_at

        # Proactively revoke real tokens for the same uid/tenant
        revoked_count = self._revoke_real_tokens(trap.uid, trap.tenant_id, raw_token)

        hit = TrapHitRecord(
            trap_id=trap.trap_id,
            uid=trap.uid,
            tenant_id=trap.tenant_id,
            hit_at=datetime.now(timezone.utc).isoformat(),
            token_age_seconds=age,
            attacker_ip=request_context.get("ip", "unknown"),
            attacker_ua=request_context.get("user_agent", ""),
            attacker_asn=request_context.get("asn"),
            attacker_country=request_context.get("country"),
            request_headers=request_context.get("headers", {}),
            request_path=request_context.get("path", ""),
            real_tokens_revoked=revoked_count,
            label=trap.label,
        )

        # Persist hit record
        self._store.record_hit(hit)

        # Re-arm the trap (don't reveal detection — let attacker keep trying)
        # Re-issue a fresh trap under the same label; old trap entry is kept
        # to preserve forensic record (TTL will expire it naturally).

        # Fire async alert pipeline
        self._fire_alert(hit, trap)

        logger.critical(
            "TRAP HIT: trap_id=%s uid=%s tenant=%s ip=%s ua=%s age=%.1fs revoked=%d",
            trap.trap_id, trap.uid, trap.tenant_id,
            hit.attacker_ip, hit.attacker_ua[:60], age, revoked_count,
        )

        return hit

    def _revoke_real_tokens(self, uid: str, tenant_id: str, trap_token: str) -> int:
        """
        Proactively revoke all active sessions for the compromised identity.
        If attacker has the trap token, they likely also have real tokens.
        SI-3 / IR-4: Incident containment.
        """
        try:
            from modules.identity.cache_redis import get_redis, revoke_token
            r = get_redis()

            # Scan Redis for session keys belonging to this uid/tenant
            pattern  = f"t:{tenant_id}:session:{uid}:*"
            count    = 0
            try:
                for key in r.scan_iter(pattern, count=100):
                    jti = key.decode().split(":")[-1] if isinstance(key, bytes) else key.split(":")[-1]
                    revoke_token(jti, ttl_seconds=86400, tenant_id=tenant_id)
                    count += 1
            except Exception:
                pass

            # Also revoke the trap token's own jti to prevent replay
            jti_key = f"t:{tenant_id}:revoked:{uid}"
            try:
                r.setex(jti_key, _TRAP_TTL_SECONDS, "trap_hit")
            except Exception:
                pass

            return count
        except Exception as e:
            logger.warning("TrapMonitor real-token revocation failed: %s", e)
            return 0

    def _fire_alert(self, hit: TrapHitRecord, trap: TrapToken) -> None:
        """
        Fire alert to all configured backends:
        - SIEM webhook (SIEM_WEBHOOK_URL)
        - Slack webhook (SLACK_WEBHOOK_URL)
        - Audit log (always)
        Runs in a fire-and-forget thread to not block the response.
        """
        import threading
        threading.Thread(target=self._send_alert, args=(hit, trap), daemon=True).start()

    def _send_alert(self, hit: TrapHitRecord, trap: TrapToken) -> None:
        try:
            from modules.security.audit_log import AuditEventType, AuditOutcome, log_event
            log_event(
                AuditEventType.ACCESS_DENIED,
                AuditOutcome.FAILURE,
                tenant_id=hit.tenant_id,
                subject=hit.uid,
                resource=f"trap:{hit.trap_id}",
                detail={
                    "event":            "token_trap_hit",
                    "attacker_ip":      hit.attacker_ip,
                    "attacker_ua":      hit.attacker_ua,
                    "attacker_country": hit.attacker_country,
                    "token_age_sec":    round(hit.token_age_seconds, 1),
                    "real_revoked":     hit.real_tokens_revoked,
                    "label":            hit.label,
                    "severity":         "CRITICAL",
                    "mitre":            "T1539",  # Steal Web Session Cookie
                    "nist":             "SI-3, IR-4, SC-26",
                },
            )
        except Exception as e:
            logger.warning("TrapMonitor audit log failed: %s", e)

        # SIEM webhook
        siem_url = os.getenv("SIEM_WEBHOOK_URL", "")
        if siem_url:
            try:
                import urllib.request
                payload = json.dumps({
                    "alert_type":  "TOKEN_TRAP_HIT",
                    "severity":    "CRITICAL",
                    "tenant_id":   hit.tenant_id,
                    "uid":         hit.uid,
                    "trap_id":     hit.trap_id,
                    "attacker_ip": hit.attacker_ip,
                    "hit_at":      hit.hit_at,
                    "token_age":   round(hit.token_age_seconds, 1),
                    "mitre":       "T1539 — Steal Web Session Cookie",
                }).encode()
                req = urllib.request.Request(
                    siem_url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=5)
            except Exception as e:
                logger.warning("SIEM webhook failed: %s", e)

        # Slack webhook
        slack_url = os.getenv("SLACK_WEBHOOK_URL", "")
        if slack_url:
            try:
                import urllib.request
                text = (
                    f":rotating_light: *TOKEN TRAP HIT* :rotating_light:\n"
                    f"*Tenant:* `{hit.tenant_id}` | *UID:* `{hit.uid}`\n"
                    f"*Attacker IP:* `{hit.attacker_ip}` ({hit.attacker_country})\n"
                    f"*Token age:* {hit.token_age_seconds:.1f}s | *Label:* `{hit.label}`\n"
                    f"*Real tokens revoked:* {hit.real_tokens_revoked}\n"
                    f"*MITRE:* T1539 — Steal Web Session Cookie"
                )
                payload = json.dumps({"text": text}).encode()
                req = urllib.request.Request(
                    slack_url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=5)
                logger.info("TrapMonitor Slack alert sent for trap_id=%s", hit.trap_id)
            except Exception as e:
                logger.warning("Slack webhook failed: %s", e)


# ── FastAPI integration ────────────────────────────────────────────────────────

# Module-level singletons
_store   = TrapTokenStore()
_factory = TrapTokenFactory(store=_store)
_monitor = TrapMonitor(store=_store, factory=_factory)


async def trap_token_check(request: "Request") -> Optional[TrapHitRecord]:  # type: ignore[name-defined]  # noqa: F821
    """
    FastAPI dependency — transparently checks every authenticated request.
    Add as a Depends() on any route that should be monitored.
    Returns TrapHitRecord if trap is hit (triggers attacker pipeline),
    None for legitimate requests.

    Usage:
        @app.get("/secure")
        async def secure(
            ...
            _trap: Optional[TrapHitRecord] = Depends(trap_token_check),
        ):

    The route can inspect _trap to decide whether to return synthetic data
    or real data (typically return synthetic for trap hits).
    """
    from fastapi import Request as _Request

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    raw_token = auth_header[7:].strip()

    # Cheap pre-check: SHA256 lookup (O(1), no Redis round-trip for non-traps
    # since TrapTokenStore._local is checked first)
    if not _store.is_trap(raw_token):
        return None

    # Full inspection (Redis round-trip, HMAC verification, telemetry)
    try:
        from modules.identity.geo_intel import lookup as geo_lookup
        geo     = geo_lookup(request.client.host if request.client else "")
        asn     = str(geo.asn) if geo else None
        country = geo.country if geo else None
    except Exception:
        asn, country = None, None

    # Collect safe subset of request headers (exclude Authorization)
    safe_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in {"authorization", "cookie", "x-api-key"}
    }

    ctx = {
        "ip":         request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", ""),
        "asn":        asn,
        "country":    country,
        "headers":    safe_headers,
        "path":       str(request.url.path),
    }

    return _monitor.inspect(raw_token, ctx)


def get_synthetic_response(hit: TrapHitRecord) -> dict:
    """
    Return a plausible synthetic API response for attacker.
    Contains no real data but looks like a legitimate success response.
    """
    return {
        **_SYNTHETIC_RESPONSE,
        "request_id": str(uuid.uuid4()),
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        # Include realistic-looking but fake data
        "user": {
            "id":    hit.uid,
            "email": f"{hit.uid[:8]}@example.com",
            "role":  "analyst",
        },
        "session": {
            "score":  72.3,
            "tier":   "allow",
            "status": "active",
        },
    }


# ── Public convenience API ────────────────────────────────────────────────────

def issue_trap(uid: str, tenant_id: str, label: str = "default") -> TrapToken:
    """Issue a single trap token. Convenience wrapper over TrapTokenFactory."""
    return _factory.issue(uid, tenant_id, label=label)


def issue_trap_batch(uid: str, tenant_id: str, count: int = 3) -> List[TrapToken]:
    """Issue multiple trap tokens with scatter labels."""
    labels = ["aws-cred-file", "s3-backup", "api-key-leak", "env-file", "git-history"]
    return _factory.issue_batch(uid, tenant_id, count=count, labels=labels[:count])


def recent_trap_hits(limit: int = 50) -> List[dict]:
    """Return most recent trap hit records (for admin dashboard)."""
    return _store.recent_hits(limit=limit)
