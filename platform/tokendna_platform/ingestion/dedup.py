"""Deduplicate by ``event_id`` over a sliding TTL window.

The collector ships at-least-once: when the cloud is briefly
unreachable, the runner spools to disk and replays on reconnect.
That replay can re-deliver events the cloud already accepted.

This module keeps a bounded set of recent ``event_id`` values;
``seen()`` returns True for repeats so the router can drop them
without re-processing.

Implementation is in-memory with a TTL eviction cycle.  At very high
volumes (>50k events/sec sustained) the right answer is to back this
with Redis or a probabilistic structure (Bloom filter); for Sprint 3-4
the in-memory variant is correct + performant enough for the design
partner workload.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from __future__ import annotations

import threading
from collections import OrderedDict
from datetime import datetime, timedelta, timezone


class DedupWindow:
    """Bounded LRU set of (tenant_id, event_id) tuples with TTL."""

    def __init__(
        self,
        *,
        ttl_seconds: int = 3600,        # default: 1-hour replay window
        max_entries: int = 1_000_000,   # hard cap on memory
    ):
        if ttl_seconds < 1:
            raise ValueError("ttl_seconds must be >= 1")
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self._ttl = timedelta(seconds=ttl_seconds)
        self._max = max_entries
        # OrderedDict gives us insertion-order eviction without a
        # separate datastructure.
        self._seen: OrderedDict[tuple[str, str], datetime] = OrderedDict()
        self._lock = threading.Lock()

    def seen(self, tenant_id: str, event_id: str, *, now: datetime | None = None) -> bool:
        """Return True iff (tenant_id, event_id) was inserted within TTL.

        Threadsafe; intended to be called from the request-handling
        thread before passing the event to the router.
        """
        moment = now or datetime.now(timezone.utc)
        key = (tenant_id, event_id)
        with self._lock:
            self._evict_expired(moment)
            existing = self._seen.get(key)
            if existing is not None and (moment - existing) < self._ttl:
                # Move to MRU so a thrashing replay doesn't accidentally
                # evict the freshest dupes.
                self._seen.move_to_end(key)
                return True
            self._seen[key] = moment
            self._seen.move_to_end(key)
            if len(self._seen) > self._max:
                self._seen.popitem(last=False)
            return False

    def _evict_expired(self, now: datetime) -> None:
        cutoff = now - self._ttl
        # OrderedDict iteration order = insertion order = ascending time.
        # Stop at the first non-expired entry.
        keys_to_drop: list[tuple[str, str]] = []
        for key, ts in self._seen.items():
            if ts >= cutoff:
                break
            keys_to_drop.append(key)
        for key in keys_to_drop:
            self._seen.pop(key, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)
