"""Trust-graph engine — event-stream entry point.

Builds an agent → action → resource graph from the inbound event
stream.  This is the cloud-side adapter that subscribes to the
ingestion router; the underlying graph algorithms still live in
``modules/identity/trust_graph.py`` for now.  When that module moves
under ``tokendna_platform/`` per the disposition map, this adapter
binds to the new location and the import path here updates.

Until the move lands, the adapter accumulates events in an internal
buffer keyed by ``(tenant_id, subject)`` so the existing graph
algorithms can be applied in batch.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import ClassVar

from ..schema import EventCategory, NormalizedEvent
from .base import StreamEngine


@dataclass
class GraphEdge:
    """One subject → resource edge observation."""
    subject: str
    action: str
    resource: str
    last_seen: datetime
    seen_count: int = 1
    distinct_actions: set[str] = field(default_factory=set)


class TrustGraphEngine(StreamEngine):
    """Stream-side trust-graph builder.

    Subscribes to authentication / authorization / AI invocation /
    permission-change events; updates an in-memory edge model that
    downstream queries can read.

    The intentional design point: this engine *records* edges from the
    stream.  Anomaly detection over those edges (the existing
    `record_policy_modification` logic etc.) re-uses the algorithms in
    ``modules/identity/trust_graph.py`` until the disposition-map move.
    """

    name: ClassVar[str] = "trust_graph"
    categories: ClassVar[tuple[EventCategory, ...]] = (
        EventCategory.AUTHENTICATION,
        EventCategory.AUTHORIZATION,
        EventCategory.AI_INVOCATION,
        EventCategory.PERMISSION_CHANGE,
    )

    def __init__(self) -> None:
        # (tenant_id, subject, resource) -> GraphEdge
        self._edges: dict[tuple[str, str, str], GraphEdge] = {}
        # tenant_id -> edge count (cheap aggregate query target)
        self._counts: defaultdict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    def handle(self, event: NormalizedEvent) -> None:
        key = (event.tenant_id, event.subject, event.resource)
        with self._lock:
            existing = self._edges.get(key)
            if existing is None:
                self._edges[key] = GraphEdge(
                    subject=event.subject,
                    action=event.action,
                    resource=event.resource,
                    last_seen=event.timestamp,
                    seen_count=1,
                    distinct_actions={event.action},
                )
                self._counts[event.tenant_id] += 1
            else:
                existing.seen_count += 1
                existing.last_seen = max(existing.last_seen, event.timestamp)
                existing.distinct_actions.add(event.action)

    # ── Read-side accessors (used by the existing algorithm hooks) ──────
    def edge_count(self, tenant_id: str) -> int:
        with self._lock:
            return self._counts[tenant_id]

    def edges_for(self, tenant_id: str, subject: str) -> list[GraphEdge]:
        with self._lock:
            return [
                e for (t, s, _r), e in self._edges.items()
                if t == tenant_id and s == subject
            ]
