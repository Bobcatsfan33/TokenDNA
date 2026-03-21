"""
TokenDNA -- Adaptive ML model for per-user behavioral profiling.

Redis-backed, tenant-isolated.  All functions now accept an optional
`redis` parameter of type TenantRedis (or any object with hget/hset/etc).
When called with a TenantRedis instance, every key is automatically
namespaced under the tenant.

Profile schema (Redis hash):
    devices, ips, countries, asns, os_list, browsers  -- JSON lists (capped 25)
    event_count, first_seen, last_seen, is_mobile

Scoring weights (sum <= 100):
    device   30  | country 25 | ip 15 | asn 15 | os 5 | browser 5 | mobile flip 5
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from config import REDIS_PROFILE_TTL

logger = logging.getLogger(__name__)

_W_DEVICE  = 30
_W_COUNTRY = 25
_W_IP      = 15
_W_ASN     = 15
_W_OS      = 5
_W_BROWSER = 5
_W_MOBILE  = 5
_MAX_KNOWN = 25


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_set(raw: Optional[str]) -> set:
    if not raw:
        return set()
    try:
        return set(json.loads(raw))
    except Exception:
        return set()


def _dump_set(s: set) -> str:
    return json.dumps(list(s)[-_MAX_KNOWN:])


def _get_redis(redis=None):
    if redis is not None:
        return redis
    from modules.identity.cache_redis import get_redis
    return get_redis()


def update_profile(user_id: str, dna: dict, redis=None) -> None:
    """Add DNA signals to the user profile.  Creates it if absent."""
    try:
        r   = _get_redis(redis)
        key = f"profile:{user_id}"
        raw = r.hgetall(key)

        devices   = _load_set(raw.get("devices"))
        ips       = _load_set(raw.get("ips"))
        countries = _load_set(raw.get("countries"))
        asns      = _load_set(raw.get("asns"))
        os_list   = _load_set(raw.get("os_list"))
        browsers  = _load_set(raw.get("browsers"))

        devices.add(dna.get("device", ""))
        ips.add(dna.get("ip", ""))
        countries.add(dna.get("country", ""))
        asns.add(dna.get("asn", ""))
        os_list.add(dna.get("ua_os", ""))
        browsers.add(dna.get("ua_browser", ""))

        count      = int(raw.get("event_count", 0)) + 1
        first_seen = raw.get("first_seen") or _now_iso()

        r.hset(key, mapping={
            "devices":     _dump_set(devices),
            "ips":         _dump_set(ips),
            "countries":   _dump_set(countries),
            "asns":        _dump_set(asns),
            "os_list":     _dump_set(os_list),
            "browsers":    _dump_set(browsers),
            "event_count": str(count),
            "first_seen":  first_seen,
            "last_seen":   _now_iso(),
            "is_mobile":   str(dna.get("is_mobile", False)),
        })
        r.expire(key, REDIS_PROFILE_TTL)

    except Exception as e:
        logger.warning("update_profile %s: %s", user_id, e)


def score(user_id: str, dna: dict, redis=None) -> int:
    """Score DNA vs stored profile. Returns 0-100; 100 = fully trusted."""
    try:
        r   = _get_redis(redis)
        raw = r.hgetall(f"profile:{user_id}")
        if not raw:
            return 100   # new user, treat as trusted until baseline forms

        devices   = _load_set(raw.get("devices"))
        ips       = _load_set(raw.get("ips"))
        countries = _load_set(raw.get("countries"))
        asns      = _load_set(raw.get("asns"))
        os_list   = _load_set(raw.get("os_list"))
        browsers  = _load_set(raw.get("browsers"))
        was_mobile = raw.get("is_mobile", "False") == "True"

        deductions = 0
        if dna.get("device")     not in devices:   deductions += _W_DEVICE
        if dna.get("ip")         not in ips:       deductions += _W_IP
        if dna.get("country")    not in countries: deductions += _W_COUNTRY
        if dna.get("asn")        not in asns:      deductions += _W_ASN
        if dna.get("ua_os")      not in os_list:   deductions += _W_OS
        if dna.get("ua_browser") not in browsers:  deductions += _W_BROWSER
        if was_mobile != dna.get("is_mobile", False): deductions += _W_MOBILE

        return max(100 - deductions, 0)

    except Exception as e:
        logger.warning("score %s: %s", user_id, e)
        return 100   # fail-open


def get_profile(user_id: str, redis=None) -> Optional[dict]:
    try:
        r   = _get_redis(redis)
        raw = r.hgetall(f"profile:{user_id}")
        if not raw:
            return None
        return {
            "devices":     json.loads(raw.get("devices",   "[]")),
            "ips":         json.loads(raw.get("ips",       "[]")),
            "countries":   json.loads(raw.get("countries", "[]")),
            "asns":        json.loads(raw.get("asns",      "[]")),
            "os_list":     json.loads(raw.get("os_list",   "[]")),
            "browsers":    json.loads(raw.get("browsers",  "[]")),
            "event_count": int(raw.get("event_count", 0)),
            "first_seen":  raw.get("first_seen"),
            "last_seen":   raw.get("last_seen"),
        }
    except Exception as e:
        logger.warning("get_profile %s: %s", user_id, e)
        return None


def reset_profile(user_id: str, redis=None) -> None:
    try:
        r = _get_redis(redis)
        r.delete(f"profile:{user_id}")
        logger.info("Profile reset for %s", user_id)
    except Exception as e:
        logger.warning("reset_profile %s: %s", user_id, e)
