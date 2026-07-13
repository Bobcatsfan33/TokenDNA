"""Zero-dependency cache fallback (P2.5).

Redis was the last hard dependency in the default path. Without it, token
revocation, rate limits and baseline caching silently degraded to no-ops — the
worst failure mode available: a revoked token kept working and nothing said so.

These tests hold the fallback to two things: it must be *correct* (the Redis
semantics the codebase relies on — TTL, LRU, list/hash ops, pipelines), and it must
be *honest* (it announces that it is single-process rather than quietly pretending
to be Redis).
"""
from __future__ import annotations

import time

import pytest

from modules.identity.memory_cache import MemoryCache


@pytest.fixture()
def cache():
    return MemoryCache()


# ── Strings + TTL ─────────────────────────────────────────────────────────────

def test_set_get_delete(cache):
    assert cache.get("k") is None
    cache.set("k", "v")
    assert cache.get("k") == "v"
    deleted = cache.delete("k")
    assert deleted == 1
    assert cache.get("k") is None


def test_setex_expires(cache):
    cache.setex("k", 1, "v")
    assert cache.get("k") == "v"
    cache._expires["k"] = time.monotonic() - 1   # fast-forward past the TTL
    assert cache.get("k") is None
    assert cache.exists("k") == 0


def test_set_clears_an_existing_ttl_like_redis(cache):
    cache.setex("k", 60, "v")
    cache.set("k", "v2")
    assert cache.ttl("k") == -1   # exists, no TTL


def test_ttl_reports_missing_vs_no_expiry(cache):
    assert cache.ttl("nope") == -2
    cache.set("k", "v")
    assert cache.ttl("k") == -1
    cache.expire("k", 60)
    assert 0 < cache.ttl("k") <= 60


def test_incr_counts_from_zero(cache):
    first = cache.incr("c")
    second = cache.incr("c")
    assert (first, second) == (1, 2)


def test_keys_matches_glob(cache):
    cache.set("t:acme:revoked:a", "1")
    cache.set("t:acme:revoked:b", "1")
    cache.set("t:other:revoked:c", "1")
    assert sorted(cache.keys("t:acme:*")) == ["t:acme:revoked:a", "t:acme:revoked:b"]


def test_lru_bound_evicts_oldest(cache):
    small = MemoryCache(max_keys=3)
    for i in range(5):
        small.set(f"k{i}", str(i))
    # A long-running single-container deployment must not grow without limit.
    assert len(small.keys()) == 3
    assert small.get("k0") is None
    assert small.get("k4") == "4"


# ── Lists + hashes ────────────────────────────────────────────────────────────

def test_list_ops(cache):
    cache.lpush("l", "b")
    cache.lpush("l", "a")
    cache.rpush("l", "c")
    assert cache.lrange("l", 0, -1) == ["a", "b", "c"]
    cache.ltrim("l", 0, 1)
    assert cache.lrange("l", 0, -1) == ["a", "b"]


def test_lrange_end_is_inclusive_like_redis(cache):
    cache.rpush("l", "a", "b", "c")
    assert cache.lrange("l", 0, 1) == ["a", "b"]


def test_hash_ops(cache):
    cache.hset("h", mapping={"a": "1"})
    cache.hset("h", "b", "2")
    assert cache.hget("h", "a") == "1"
    assert cache.hgetall("h") == {"a": "1", "b": "2"}
    incremented = cache.hincrby("h", "a", 4)
    assert incremented == 5


# ── Pipelines ─────────────────────────────────────────────────────────────────

def test_pipeline_queues_then_executes(cache):
    pipe = cache.pipeline()
    pipe.set("a", "1").incr("c").hincrby("h", "f", 2)
    assert cache.get("a") is None, "queued commands must not apply before execute()"

    results = pipe.execute()

    assert cache.get("a") == "1"
    assert cache.get("c") == "1"
    assert cache.hget("h", "f") == "2"
    assert len(results) == 3


def test_pipeline_rejects_an_unsupported_command(cache):
    """The fallback is deliberately not a Redis clone: an unsupported command must
    fail loudly rather than silently do nothing."""
    with pytest.raises(AttributeError, match="subset"):
        cache.pipeline().geoadd("k", 1, 2, "m")


# ── The behaviour that actually matters ───────────────────────────────────────

def test_token_revocation_works_with_no_redis(monkeypatch):
    """The headline: on a laptop with no Redis, revoking a token must REVOKE it.

    Before P2.5 this silently degraded to a no-op — the revoked token kept working.
    """
    monkeypatch.setenv("TOKENDNA_CACHE", "memory")

    from modules.identity import cache_redis
    cache_redis.reset_client()

    assert cache_redis.using_fallback() is True
    assert cache_redis.is_token_revoked("jti-1", tenant_id="acme") is False

    cache_redis.revoke_token("jti-1", tenant_id="acme")

    assert cache_redis.is_token_revoked("jti-1", tenant_id="acme") is True
    # Tenant-isolated even in the fallback.
    assert cache_redis.is_token_revoked("jti-1", tenant_id="other") is False

    cache_redis.reset_client()


def test_clickhouse_is_not_attempted_when_unconfigured(monkeypatch):
    """"Not deployed" and "deployed and down" are different things. Only the second
    should cost a connection attempt."""
    from modules.identity import clickhouse_client

    monkeypatch.delenv("CLICKHOUSE_HOST", raising=False)
    monkeypatch.setattr(clickhouse_client, "_client", None)

    def _explode():
        raise AssertionError("must not attempt a connection when unconfigured")

    monkeypatch.setattr(clickhouse_client, "_ensure_schema",
                        lambda *_a, **_k: _explode())

    assert clickhouse_client.is_configured() is False
    assert clickhouse_client._get_client() is None
    assert clickhouse_client.is_available() is False


def test_zero_dependency_boot(monkeypatch, tmp_path):
    """P2.5's acceptance criterion: the app serves a verdict on a machine with no
    Redis, no Postgres and no ClickHouse."""
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("TOKENDNA_CACHE", "memory")     # no Redis
    monkeypatch.delenv("CLICKHOUSE_HOST", raising=False)  # no ClickHouse
    monkeypatch.delenv("TOKENDNA_PG_DSN", raising=False)  # no Postgres → SQLite
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("TOKENDNA_ENV", "test")
    monkeypatch.setenv("DEV_TENANT_ID", "acme")

    import importlib

    from modules.identity import cache_redis
    from modules.tenants import middleware

    cache_redis.reset_client()
    importlib.reload(middleware)  # DEV_MODE is frozen at import

    import api
    from fastapi.testclient import TestClient

    client = TestClient(api.app)

    assert client.get("/healthz").status_code == 200
    # The flagship endpoint answers — the whole point of Tier 1.
    r = client.post("/v1/authorize", json={
        "agent_id": "agent-1", "action": "read", "resource": "db://acme/x",
    })
    assert r.status_code == 200
    assert r.json()["verdict"] == "ALLOW"

    # Restore: middleware freezes DEV_MODE at import, so a reloaded module would
    # otherwise leave DEV_MODE=true baked in for every test that runs after this one.
    cache_redis.reset_client()
    monkeypatch.delenv("DEV_MODE", raising=False)
    importlib.reload(middleware)


def test_fallback_is_announced_not_hidden(monkeypatch, caplog):
    """Single-process is a real limitation. It must be stated out loud."""
    import logging

    from modules.identity import cache_redis
    cache_redis.reset_client()
    monkeypatch.delenv("TOKENDNA_CACHE", raising=False)
    # Point at a port nothing is listening on so the probe fails like a real
    # no-Redis machine, rather than mocking the failure away.
    monkeypatch.setattr(cache_redis, "REDIS_HOST", "127.0.0.1")
    monkeypatch.setattr(cache_redis, "REDIS_PORT", 1)
    monkeypatch.setattr(cache_redis, "_build_pool",
                        lambda: (_ for _ in ()).throw(OSError("connection refused")))

    with caplog.at_level(logging.WARNING):
        cache_redis.get_redis()

    assert cache_redis.using_fallback() is True
    warning = " ".join(r.getMessage() for r in caplog.records)
    assert "SINGLE-PROCESS" in warning
    assert "not shared between workers" in warning.lower()

    cache_redis.reset_client()
