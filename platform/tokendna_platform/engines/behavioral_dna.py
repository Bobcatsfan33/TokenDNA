"""Behavioural DNA engine — event-stream entry point.

Builds a per-subject behavioural fingerprint from the inbound stream
and surfaces drift when the live fingerprint diverges from the
baseline.

In collector-only mode, the fingerprint is coarse (action frequencies
over rolling windows).  In SDK mode, the SDK telemetry enriches the
fingerprint with per-call detail and the engine produces a much finer
signal — same engine class, different input fidelity.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from __future__ import annotations

import threading
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import ClassVar

from ..schema import EventCategory, NormalizedEvent
from .base import StreamEngine


class BehavioralDNAEngine(StreamEngine):
    """Rolling-window action-frequency fingerprint per (tenant, subject)."""

    name: ClassVar[str] = "behavioral_dna"
    categories: ClassVar[tuple[EventCategory, ...]] = (
        EventCategory.AUTHENTICATION,
        EventCategory.AI_INVOCATION,
        EventCategory.AUTHORIZATION,
        EventCategory.NETWORK,
    )

    def __init__(self, *, window_seconds: int = 3600) -> None:
        self._window = timedelta(seconds=window_seconds)
        # (tenant_id, subject) -> list[(timestamp, action)]
        self._events: defaultdict[tuple[str, str], list[tuple[datetime, str]]] = defaultdict(list)
        self._lock = threading.Lock()

    def handle(self, event: NormalizedEvent) -> None:
        key = (event.tenant_id, event.subject)
        with self._lock:
            history = self._events[key]
            history.append((event.timestamp, event.action))
            self._evict(history, event.timestamp)

    def fingerprint(self, tenant_id: str, subject: str) -> dict[str, int]:
        """Return action-frequency Counter for the rolling window."""
        key = (tenant_id, subject)
        now = datetime.now(timezone.utc)
        with self._lock:
            history = self._events.get(key, [])
            self._evict(history, now)
            return dict(Counter(action for _, action in history))

    def _evict(self, history: list[tuple[datetime, str]], now: datetime) -> None:
        cutoff = now - self._window
        # history is append-only by timestamp ⇒ leading prefix is what evicts.
        while history and history[0][0] < cutoff:
            history.pop(0)
