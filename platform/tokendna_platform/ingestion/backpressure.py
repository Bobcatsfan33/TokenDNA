"""Backpressure gate.

A bounded queue between the HTTP ingest endpoint and the router.  When
the platform is processing slower than collectors are sending, the
queue fills.  Past a high-water mark, the gate refuses to accept new
batches so the collector returns to its on-disk buffer (instead of the
platform OOMing).

This is the only place the cloud surfaces 429 responses to collectors.
Every collector treats 429 the same way it treats 5xx — back off,
retry, spool to disk if persistent.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from __future__ import annotations

import threading
from dataclasses import dataclass


class IngestQueueFull(Exception):
    """Raised by ``BackpressureGate.try_admit`` when the queue is at limit."""


@dataclass(frozen=True)
class GateStatus:
    pending: int
    high_water_mark: int
    capacity: int


class BackpressureGate:
    """Counts pending events; refuses admission past the high-water mark.

    Threadsafe.  The gate doesn't actually hold a queue — the caller
    owns that.  The gate just tracks how many events are in flight and
    decides whether to admit more.

    Typical use:

        gate = BackpressureGate(capacity=5000, high_water_mark=4500)

        # in the HTTP handler
        try:
            gate.admit(len(batch))
        except IngestQueueFull:
            return Response(status=429, headers={"Retry-After": "5"})

        try:
            # ... process batch ...
        finally:
            gate.release(len(batch))
    """

    def __init__(self, *, capacity: int, high_water_mark: int | None = None):
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self._capacity = capacity
        self._hwm = high_water_mark or max(int(capacity * 0.9), 1)
        if self._hwm > capacity:
            raise ValueError("high_water_mark cannot exceed capacity")
        self._pending = 0
        self._lock = threading.Lock()

    def try_admit(self, n: int = 1) -> bool:
        """Admit ``n`` events if room.  Returns False if at HWM."""
        if n < 1:
            raise ValueError("n must be >= 1")
        with self._lock:
            if self._pending + n > self._hwm:
                return False
            self._pending += n
            return True

    def admit(self, n: int = 1) -> None:
        """Admit or raise ``IngestQueueFull``.  Convenience wrapper."""
        if not self.try_admit(n):
            raise IngestQueueFull(
                f"queue at high-water mark ({self._pending}/{self._hwm}); "
                f"capacity={self._capacity}"
            )

    def release(self, n: int = 1) -> None:
        if n < 1:
            raise ValueError("n must be >= 1")
        with self._lock:
            self._pending = max(0, self._pending - n)

    def status(self) -> GateStatus:
        with self._lock:
            return GateStatus(
                pending=self._pending,
                high_water_mark=self._hwm,
                capacity=self._capacity,
            )
