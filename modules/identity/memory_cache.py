"""In-process cache — the zero-dependency fallback for Redis (P2.5).

Tier 1 of the deployment story is "pip install, run it, get a verdict" on a laptop
with no Postgres, no Redis and no ClickHouse. Redis was the last hard dependency in
the default path: without it, token revocation, rate limits and baseline caching all
silently degraded to no-ops.

This implements the subset of the Redis API this codebase actually uses — enumerated
from the call sites, not guessed — backed by a dict with TTLs and an LRU bound. It is
deliberately NOT a Redis clone: anything the product does not use is absent, so an
unsupported call fails loudly here rather than pretending to work.

**It is single-process, and that is a real limitation, not a footnote.** Two workers
do not share a revocation list, so a token revoked on worker A is still accepted by
worker B. ``cache_redis`` logs a loud warning at startup when this fallback engages,
and production compose/Helm still ship Redis. Single-process is correct for
evaluation and CI; it is not correct for a multi-worker deployment.
"""
from __future__ import annotations

import fnmatch
import logging
import threading
import time
from collections import OrderedDict
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Bound the cache so a long-running single-container deployment cannot grow without
# limit. Evicts least-recently-used, like Redis' allkeys-lru policy.
DEFAULT_MAX_KEYS = 10_000


class MemoryCache:
    """Thread-safe, TTL-aware, LRU-bounded in-process stand-in for redis.Redis.

    Values are stored and returned as ``str`` to match the real client, which is
    constructed with ``decode_responses=True``.
    """

    def __init__(self, max_keys: int = DEFAULT_MAX_KEYS):
        self._max_keys = max_keys
        self._lock = threading.RLock()
        self._data: OrderedDict[str, Any] = OrderedDict()
        self._expires: dict[str, float] = {}

    # ── internals ────────────────────────────────────────────────────────────

    def _expired(self, key: str) -> bool:
        exp = self._expires.get(key)
        return exp is not None and exp <= time.monotonic()

    def _purge(self, key: str) -> None:
        self._data.pop(key, None)
        self._expires.pop(key, None)

    def _live(self, key: str) -> bool:
        """True if the key exists and has not expired (purging it if it has)."""
        if key not in self._data:
            return False
        if self._expired(key):
            self._purge(key)
            return False
        self._data.move_to_end(key)
        return True

    def _put(self, key: str, value: Any) -> None:
        self._data[key] = value
        self._data.move_to_end(key)
        while len(self._data) > self._max_keys:
            oldest, _ = self._data.popitem(last=False)
            self._expires.pop(oldest, None)

    # ── strings ──────────────────────────────────────────────────────────────

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            if not self._live(key):
                return None
            val = self._data[key]
            return val if isinstance(val, str) else None

    def set(self, key: str, value: Any) -> bool:
        with self._lock:
            self._put(key, str(value))
            self._expires.pop(key, None)  # SET clears any TTL, as Redis does
            return True

    def setex(self, key: str, ttl: int, value: Any) -> bool:
        with self._lock:
            self._put(key, str(value))
            self._expires[key] = time.monotonic() + max(int(ttl), 0)
            return True

    def delete(self, *keys: str) -> int:
        with self._lock:
            n = 0
            for key in keys:
                if key in self._data:
                    self._purge(key)
                    n += 1
            return n

    def exists(self, key: str) -> int:
        with self._lock:
            return 1 if self._live(key) else 0

    def incr(self, key: str, amount: int = 1) -> int:
        with self._lock:
            current = int(self._data[key]) if self._live(key) else 0
            new = current + amount
            self._put(key, str(new))
            return new

    def expire(self, key: str, ttl: int) -> bool:
        with self._lock:
            if not self._live(key):
                return False
            self._expires[key] = time.monotonic() + max(int(ttl), 0)
            return True

    def ttl(self, key: str) -> int:
        with self._lock:
            if not self._live(key):
                return -2          # Redis: key does not exist
            exp = self._expires.get(key)
            if exp is None:
                return -1          # Redis: key exists but has no TTL
            return max(int(exp - time.monotonic()), 0)

    def keys(self, pattern: str = "*") -> list[str]:
        with self._lock:
            live = [k for k in list(self._data) if self._live(k)]
            return [k for k in live if fnmatch.fnmatchcase(k, pattern)]

    # ── lists ────────────────────────────────────────────────────────────────

    def _list(self, key: str) -> list[str]:
        if not self._live(key) or not isinstance(self._data.get(key), list):
            self._put(key, [])
        return self._data[key]

    def lpush(self, key: str, *values: Any) -> int:
        with self._lock:
            lst = self._list(key)
            for v in values:
                lst.insert(0, str(v))
            return len(lst)

    def rpush(self, key: str, *values: Any) -> int:
        with self._lock:
            lst = self._list(key)
            lst.extend(str(v) for v in values)
            return len(lst)

    def lrange(self, key: str, start: int, end: int) -> list[str]:
        with self._lock:
            lst = self._list(key)
            # Redis' end index is inclusive, and -1 means "to the end".
            stop = len(lst) if end == -1 else end + 1
            return lst[start:stop]

    def ltrim(self, key: str, start: int, end: int) -> bool:
        with self._lock:
            lst = self._list(key)
            stop = len(lst) if end == -1 else end + 1
            self._data[key] = lst[start:stop]
            return True

    # ── hashes ───────────────────────────────────────────────────────────────

    def _hash(self, key: str) -> dict[str, str]:
        if not self._live(key) or not isinstance(self._data.get(key), dict):
            self._put(key, {})
        return self._data[key]

    def hget(self, key: str, field: str) -> Optional[str]:
        with self._lock:
            return self._hash(key).get(field)

    def hgetall(self, key: str) -> dict[str, str]:
        with self._lock:
            return dict(self._hash(key))

    def hset(self, key: str, field: str | None = None, value: Any = None,
             mapping: dict | None = None) -> int:
        with self._lock:
            h = self._hash(key)
            written = 0
            if mapping:
                for f, v in mapping.items():
                    h[str(f)] = str(v)
                    written += 1
            if field is not None:
                h[str(field)] = str(value)
                written += 1
            return written

    def hincrby(self, key: str, field: str, amount: int = 1) -> int:
        with self._lock:
            h = self._hash(key)
            new = int(h.get(field, 0)) + amount
            h[field] = str(new)
            return new

    # ── misc ─────────────────────────────────────────────────────────────────

    def ping(self) -> bool:
        return True

    def info(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        with self._lock:
            return {
                "redis_version": "memory-fallback",
                "db0": {"keys": len(self._data)},
                "tokendna_backend": "in-process",
            }

    def flushdb(self) -> bool:
        with self._lock:
            self._data.clear()
            self._expires.clear()
            return True

    def pipeline(self, *_args: Any, **_kwargs: Any) -> "MemoryPipeline":
        return MemoryPipeline(self)


class MemoryPipeline:
    """Queues commands and applies them on execute(), like redis-py's pipeline.

    No transactional guarantee is claimed beyond the cache's own per-op locking —
    which is exactly as much as the non-transactional redis-py pipelines this
    codebase uses actually provide.
    """

    def __init__(self, cache: MemoryCache):
        self._cache = cache
        self._queued: list[tuple[str, tuple, dict]] = []

    def __getattr__(self, name: str):
        if not hasattr(MemoryCache, name):
            raise AttributeError(
                f"MemoryCache has no command {name!r} — the in-process fallback "
                "implements only the Redis subset TokenDNA uses"
            )

        def _queue(*args: Any, **kwargs: Any) -> "MemoryPipeline":
            self._queued.append((name, args, kwargs))
            return self  # chainable, like redis-py

        return _queue

    def execute(self) -> list[Any]:
        with self._cache._lock:
            results = [getattr(self._cache, name)(*args, **kwargs)
                       for name, args, kwargs in self._queued]
        self._queued.clear()
        return results

    def __enter__(self) -> "MemoryPipeline":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self._queued.clear()
