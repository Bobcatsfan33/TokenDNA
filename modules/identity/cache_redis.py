"""
TokenDNA -- Redis client, connection pool, and baseline cache.

Key isolation: all keys are namespaced per tenant so no two customers
share data even on a single Redis instance:

    t:{tenant_id}:baseline:{user_id}
    t:{tenant_id}:baseline_history:{user_id}
    t:{tenant_id}:rate:{ip}
    t:{tenant_id}:revoked:{jti}
    t:{tenant_id}:counters:{YYYY-MM-DD}
"""

import json
import logging
from typing import Any, Optional

import redis

from config import (
    REDIS_BASELINE_TTL,
    REDIS_HOST,
    REDIS_PASSWORD,
    REDIS_PORT,
    REDIS_PROFILE_TTL,
    REDIS_TLS,
    REDIS_TIMEOUT,
)

logger = logging.getLogger(__name__)
_DEFAULT_TENANT = "_global_"


# -- Connection pool -----------------------------------------------------------

def _build_pool() -> redis.ConnectionPool:
    kwargs: dict[str, Any] = {
        "host":                   REDIS_HOST,
        "port":                   REDIS_PORT,
        "decode_responses":       True,
        "socket_timeout":         REDIS_TIMEOUT,
        "socket_connect_timeout": REDIS_TIMEOUT,
        "health_check_interval":  30,
        "max_connections":        50,
    }
    if REDIS_PASSWORD:
        kwargs["password"] = REDIS_PASSWORD
    if REDIS_TLS:
        kwargs["ssl"] = True
        kwargs["ssl_cert_reqs"] = "required"
    return redis.ConnectionPool(**kwargs)


_pool: Optional[redis.ConnectionPool] = None


def get_redis() -> redis.Redis:
    global _pool
    if _pool is None:
        _pool = _build_pool()
    return redis.Redis(connection_pool=_pool)


def is_available() -> bool:
    try:
        get_redis().ping()
        return True
    except Exception:
        return False


def _k(tenant_id: str, *parts: str) -> str:
    return "t:" + tenant_id + ":" + ":".join(parts)


# -- TenantRedis wrapper -------------------------------------------------------

class TenantRedis:
    """
    Wraps Redis so every key is automatically prefixed with the tenant namespace.
    Pass one of these to any module that reads/writes Redis.
    """

    def __init__(self, client: redis.Redis, tenant_id: str):
        self._r   = client
        self._tid = tenant_id

    def _key(self, k: str) -> str:
        return _k(self._tid, k)

    def get(self, key: str) -> Optional[str]:
        try:
            return self._r.get(self._key(key))
        except Exception as e:
            logger.warning("TenantRedis.get %s: %s", key, e)
            return None

    def set(self, key: str, value: str) -> None:
        try:
            self._r.set(self._key(key), value)
        except Exception as e:
            logger.warning("TenantRedis.set %s: %s", key, e)

    def setex(self, key: str, ttl: int, value: str) -> None:
        try:
            self._r.setex(self._key(key), ttl, value)
        except Exception as e:
            logger.warning("TenantRedis.setex %s: %s", key, e)

    def delete(self, *keys: str) -> None:
        try:
            self._r.delete(*[self._key(k) for k in keys])
        except Exception as e:
            logger.warning("TenantRedis.delete: %s", e)

    def incr(self, key: str) -> int:
        try:
            return int(self._r.incr(self._key(key)))
        except Exception:
            return 0

    def expire(self, key: str, ttl: int) -> None:
        try:
            self._r.expire(self._key(key), ttl)
        except Exception as e:
            logger.warning("TenantRedis.expire %s: %s", key, e)

    def lpush(self, key: str, *values: str) -> None:
        try:
            self._r.lpush(self._key(key), *values)
        except Exception as e:
            logger.warning("TenantRedis.lpush %s: %s", key, e)

    def ltrim(self, key: str, start: int, end: int) -> None:
        try:
            self._r.ltrim(self._key(key), start, end)
        except Exception as e:
            logger.warning("TenantRedis.ltrim %s: %s", key, e)

    def lrange(self, key: str, start: int, end: int) -> list:
        try:
            return self._r.lrange(self._key(key), start, end)
        except Exception as e:
            logger.warning("TenantRedis.lrange %s: %s", key, e)
            return []

    def hget(self, key: str, field: str) -> Optional[str]:
        try:
            return self._r.hget(self._key(key), field)
        except Exception as e:
            logger.warning("TenantRedis.hget %s: %s", key, e)
            return None

    def hgetall(self, key: str) -> dict:
        try:
            return self._r.hgetall(self._key(key))
        except Exception as e:
            logger.warning("TenantRedis.hgetall %s: %s", key, e)
            return {}

    def hset(self, key: str, mapping: dict) -> None:
        try:
            self._r.hset(self._key(key), mapping=mapping)
        except Exception as e:
            logger.warning("TenantRedis.hset %s: %s", key, e)

    def hincrby(self, key: str, field: str, amount: int = 1) -> None:
        try:
            self._r.hincrby(self._key(key), field, amount)
        except Exception as e:
            logger.warning("TenantRedis.hincrby %s: %s", key, e)

    def pipeline(self):
        return self._r.pipeline()

    def raw(self) -> redis.Redis:
        return self._r


# -- Baseline helpers ----------------------------------------------------------

def get_baseline(user_id: str, tenant_id: str = _DEFAULT_TENANT) -> Optional[dict]:
    try:
        raw = get_redis().get(_k(tenant_id, "baseline", user_id))
        return json.loads(raw) if raw else None
    except Exception as e:
        logger.warning("get_baseline %s/%s: %s", tenant_id, user_id, e)
        return None


def set_baseline(user_id: str, dna: dict, tenant_id: str = _DEFAULT_TENANT) -> None:
    try:
        get_redis().setex(
            _k(tenant_id, "baseline", user_id),
            REDIS_BASELINE_TTL,
            json.dumps(dna),
        )
    except Exception as e:
        logger.warning("set_baseline %s/%s: %s", tenant_id, user_id, e)


def get_baseline_history(user_id: str, tenant_id: str = _DEFAULT_TENANT) -> list[dict]:
    try:
        items = get_redis().lrange(_k(tenant_id, "baseline_history", user_id), 0, 9)
        return [json.loads(i) for i in items]
    except Exception as e:
        logger.warning("get_baseline_history: %s", e)
        return []


def push_baseline_history(user_id: str, dna: dict, tenant_id: str = _DEFAULT_TENANT) -> None:
    try:
        r   = get_redis()
        key = _k(tenant_id, "baseline_history", user_id)
        r.lpush(key, json.dumps(dna))
        r.ltrim(key, 0, 9)
        r.expire(key, REDIS_PROFILE_TTL)
    except Exception as e:
        logger.warning("push_baseline_history: %s", e)


# -- Rate limiting (per tenant+IP, never cross-tenant) ------------------------

def increment_rate(
    key: str,
    window_seconds: int = 60,
    tenant_id: str = _DEFAULT_TENANT,
) -> int:
    try:
        r      = get_redis()
        ns_key = _k(tenant_id, key)
        pipe   = r.pipeline()
        pipe.incr(ns_key)
        pipe.expire(ns_key, window_seconds)
        result = pipe.execute()
        return int(result[0])
    except Exception:
        return 0   # fail-open


# -- Token revocation ----------------------------------------------------------

def revoke_token(jti: str, ttl_seconds: int = 3600, tenant_id: str = _DEFAULT_TENANT) -> None:
    try:
        get_redis().setex(_k(tenant_id, "revoked", jti), ttl_seconds, "1")
        logger.info("Token %s revoked (tenant=%s ttl=%ds)", jti, tenant_id, ttl_seconds)
    except Exception as e:
        logger.error("revoke_token %s: %s", jti, e)


def is_token_revoked(jti: str, tenant_id: str = _DEFAULT_TENANT) -> bool:
    try:
        return bool(get_redis().get(_k(tenant_id, "revoked", jti)))
    except Exception:
        return False


# -- Event counters (dashboard KPIs without hitting ClickHouse) ---------------

def increment_event_counter(tier: str, tenant_id: str = _DEFAULT_TENANT) -> None:
    import datetime
    today = datetime.date.today().isoformat()
    try:
        r   = get_redis()
        key = _k(tenant_id, "counters", today)
        r.hincrby(key, tier.lower(), 1)
        r.expire(key, 86400 * 8)
    except Exception:
        pass


def get_event_counters(tenant_id: str, days: int = 1) -> dict:
    import datetime
    r      = get_redis()
    totals = {"allow": 0, "step_up": 0, "block": 0, "revoke": 0}
    try:
        for i in range(days):
            d   = (datetime.date.today() - datetime.timedelta(days=i)).isoformat()
            raw = r.hgetall(_k(tenant_id, "counters", d))
            for t in totals:
                totals[t] += int(raw.get(t, 0))
    except Exception:
        pass
    totals["total"] = sum(totals.values())
    return totals
