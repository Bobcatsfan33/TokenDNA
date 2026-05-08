"""Permission-drift engine — event-stream entry point.

Compares IDP state snapshots inferred from a stream of
``permission_change`` events against the last known baseline.  When
the resource set a subject can reach grows by more than the
configured factor (default 2x) without an accompanying attestation
event, the engine emits a drift finding.

For Sprint 5-6 this records the snapshots and computes the deltas.
The actual finding-emission to downstream alerting / dashboard is a
Sprint 9-10 concern; for now the engine just exposes a query API the
later sprint will hang the alert pipeline off of.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import ClassVar

from ..schema import EventCategory, NormalizedEvent
from .base import StreamEngine


@dataclass
class DriftFinding:
    """One drift episode against a subject's prior baseline."""
    tenant_id: str
    subject: str
    baseline_resource_count: int
    current_resource_count: int
    growth_factor: float
    detected_at: datetime
    new_resources: set[str] = field(default_factory=set)


class PermissionDriftEngine(StreamEngine):
    """Tracks resource-set deltas per subject.  Surfaces growth findings."""

    name: ClassVar[str] = "permission_drift"
    categories: ClassVar[tuple[EventCategory, ...]] = (
        EventCategory.PERMISSION_CHANGE,
        EventCategory.AUTHORIZATION,
    )

    def __init__(self, *, growth_factor_threshold: float = 2.0) -> None:
        if growth_factor_threshold <= 1.0:
            raise ValueError("growth_factor_threshold must be > 1.0")
        self._threshold = growth_factor_threshold
        # (tenant_id, subject) -> set of resources observed-as-accessible
        self._resources: dict[tuple[str, str], set[str]] = {}
        # Baseline = the resource set at first observation per subject.
        self._baseline: dict[tuple[str, str], int] = {}
        self._findings: list[DriftFinding] = []
        self._lock = threading.Lock()

    def handle(self, event: NormalizedEvent) -> None:
        key = (event.tenant_id, event.subject)
        with self._lock:
            current = self._resources.setdefault(key, set())
            previous_size = len(current)
            current.add(event.resource)
            if previous_size == 0 and key not in self._baseline:
                self._baseline[key] = 1  # baseline = first resource observed
                return
            self._baseline.setdefault(key, max(previous_size, 1))

            baseline = self._baseline[key]
            if baseline == 0:
                return
            growth = len(current) / baseline
            if growth >= self._threshold:
                # Avoid flapping: only emit a new finding if the current
                # set grew vs the last finding for this subject.
                last = next(
                    (f for f in reversed(self._findings)
                     if (f.tenant_id, f.subject) == key),
                    None,
                )
                if last is None or len(current) > last.current_resource_count:
                    new_resources = set(current)
                    if last:
                        new_resources -= {r for r in current
                                          if last.current_resource_count >= len(current)}
                    self._findings.append(DriftFinding(
                        tenant_id=event.tenant_id,
                        subject=event.subject,
                        baseline_resource_count=baseline,
                        current_resource_count=len(current),
                        growth_factor=growth,
                        detected_at=event.timestamp,
                        new_resources=set(current),
                    ))

    def findings(self) -> list[DriftFinding]:
        with self._lock:
            return list(self._findings)
