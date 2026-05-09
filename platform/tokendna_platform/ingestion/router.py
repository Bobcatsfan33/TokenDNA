"""Route events to engines based on ``EventCategory``.

The router is the only place the platform's intelligence engines see
an inbound event.  Each engine registers an interest in one or more
``EventCategory`` values; the router fans out matching events to all
registered handlers in registration order.

Handlers must be fast — the request-path latency budget for ingest
is < 50 ms p99.  Anything that needs heavy processing should hand off
to a background queue inside the handler.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from __future__ import annotations

import logging
from typing import Callable

from ..schema import EventCategory, NormalizedEvent

logger = logging.getLogger("tokendna_platform.ingestion.router")


# Handler signature: synchronous; the router runs each handler in
# isolation so one slow handler can't block the others.
Handler = Callable[[NormalizedEvent], None]


class EventRouter:
    """Fan-out by EventCategory to registered handlers."""

    def __init__(self) -> None:
        self._handlers: dict[EventCategory, list[tuple[str, Handler]]] = {
            cat: [] for cat in EventCategory
        }

    def register_handler(
        self,
        name: str,
        handler: Handler,
        *categories: EventCategory,
    ) -> None:
        """Register ``handler`` to receive events in any of ``categories``.

        The ``name`` is operator-facing and surfaces in logs when the
        handler raises.  Registering the same name twice replaces the
        existing registration (so engines can hot-swap behaviour
        without a restart).
        """
        if not categories:
            raise ValueError(f"handler {name!r} must register at least one category")
        for cat in categories:
            bucket = self._handlers[cat]
            # Replace if same name already present.
            for idx, (existing_name, _) in enumerate(bucket):
                if existing_name == name:
                    bucket[idx] = (name, handler)
                    break
            else:
                bucket.append((name, handler))

    def route(self, event: NormalizedEvent) -> dict[str, int]:
        """Dispatch one event; returns {"handlers_invoked": N, "handlers_failed": M}."""
        bucket = self._handlers.get(event.event_category, [])
        # Always also fan out to UNKNOWN-listeners so an engine that
        # wants every event can subscribe once.
        if event.event_category != EventCategory.UNKNOWN:
            bucket = bucket + self._handlers.get(EventCategory.UNKNOWN, [])

        invoked = failed = 0
        for name, handler in bucket:
            try:
                handler(event)
                invoked += 1
            except Exception:
                failed += 1
                logger.exception(
                    "router handler %r failed on event %s",
                    name, event.event_id,
                )
        return {"handlers_invoked": invoked, "handlers_failed": failed}

    def handlers_for(self, category: EventCategory) -> list[str]:
        """Inspect which handlers will receive events of ``category``."""
        return [name for name, _ in self._handlers.get(category, [])]
