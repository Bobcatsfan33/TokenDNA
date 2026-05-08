"""Persisted-event storage interface.

The ingestion layer hands every accepted event to ``EventStore.write``
for durable persistence.  In production this writes to ClickHouse via
the existing ``modules.identity.clickhouse_client`` (which moves into
``platform/tokendna_platform/storage/clickhouse.py`` per the disposition
map in a later sprint).

For Sprint 3-4 the production binding is left abstract; the in-memory
implementation below is what tests + early integrations use.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from typing import Iterable

from ..schema import NormalizedEvent


class EventStore(ABC):
    """Durable event storage contract."""

    @abstractmethod
    def write(self, events: Iterable[NormalizedEvent]) -> int:
        """Persist a batch of events; returns the count actually written.

        Implementations MUST be idempotent on ``event_id`` — the
        ingestion router already runs ``DedupWindow``, but a defensive
        unique-key constraint at the storage layer protects against
        edge cases (multi-region replay, dedup-window expiry).
        """


class InMemoryEventStore(EventStore):
    """Reference implementation; threadsafe; useful for tests + smoke runs."""

    def __init__(self) -> None:
        self._events: list[NormalizedEvent] = []
        self._seen_ids: set[tuple[str, str]] = set()
        self._lock = threading.Lock()

    def write(self, events: Iterable[NormalizedEvent]) -> int:
        written = 0
        with self._lock:
            for event in events:
                key = (event.tenant_id, event.event_id)
                if key in self._seen_ids:
                    continue
                self._seen_ids.add(key)
                self._events.append(event)
                written += 1
        return written

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)

    def all(self) -> list[NormalizedEvent]:
        """Snapshot for tests; not part of the production interface."""
        with self._lock:
            return list(self._events)
