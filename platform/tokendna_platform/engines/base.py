"""Stream-consuming engine contract.

Per the deployment redesign, the cloud's intelligence engines no
longer observe in-process events; they subscribe to the ingestion
router and consume the normalized event stream.

This module defines the contract every engine implements:

  * ``categories`` — which ``EventCategory`` values it cares about.
  * ``handle(event)`` — synchronous event consumer; runs inside the
    router's request path so it MUST be fast (heavy work goes on a
    background queue inside the engine).
  * ``register_with(router)`` — convenience to register `handle`
    against `router` for every category in `categories`.

Concrete engines (``trust_graph``, ``behavioral_dna``,
``permission_drift``, ``mcp_inspector``, ``policy_guard``) live in
sibling modules and subclass ``StreamEngine``.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar, Iterable

from ..schema import EventCategory, NormalizedEvent

if TYPE_CHECKING:
    from ..ingestion.router import EventRouter


class StreamEngine(ABC):
    """Base class for any platform engine that consumes the event stream."""

    #: Override in subclasses.  Empty tuple means "subscribe to UNKNOWN
    #: only" (catch-all listener — see EventRouter for semantics).
    categories: ClassVar[tuple[EventCategory, ...]] = ()

    #: Operator-facing identifier used by EventRouter for logging and
    #: by subclasses to namespace their internal metrics.
    name: ClassVar[str] = ""

    @abstractmethod
    def handle(self, event: NormalizedEvent) -> None:
        """Consume one event.  Must not raise unless the engine is broken."""
        raise NotImplementedError

    def register_with(self, router: "EventRouter") -> None:
        """Subscribe ``self.handle`` to the router for our categories."""
        if not self.name:
            raise ValueError(
                f"{type(self).__name__}.name must be set on the subclass"
            )
        cats: Iterable[EventCategory] = self.categories or (EventCategory.UNKNOWN,)
        router.register_handler(self.name, self.handle, *cats)
