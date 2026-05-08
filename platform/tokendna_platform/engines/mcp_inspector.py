"""MCP inspector engine — event-stream entry point.

Subscribes to ``ai_invocation`` events emitted by the MCP-mirror
adapter on the collector side.  Detects suspicious tool-call chains
(e.g. ``read_file → send_email``) over a configurable bounded-gap
window.

The chain-pattern matching algorithm itself lives in
``modules/identity/mcp_inspector.py`` — this adapter recognises chains
in the inbound stream and delegates the per-pattern verdict to that
module.  When the existing module moves under
``tokendna_platform/mcp/`` per the disposition map, this adapter
imports from the new location.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timedelta
from typing import ClassVar

from ..schema import EventCategory, NormalizedEvent
from .base import StreamEngine


# Default chain patterns the engine looks for.  Customers can extend
# this list at construction time without touching the engine code.
#
# Each entry: (sequence of tool-call actions, severity).
DEFAULT_CHAIN_PATTERNS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("read_file", "send_email"),         "high"),
    (("read_file", "http_post"),          "high"),
    (("execute_command", "send_email"),   "critical"),
)


class MCPChainEngine(StreamEngine):
    """Recognises multi-step MCP tool-call chains in the stream."""

    name: ClassVar[str] = "mcp_inspector"
    categories: ClassVar[tuple[EventCategory, ...]] = (
        EventCategory.AI_INVOCATION,
    )

    def __init__(
        self,
        *,
        max_gap: int = 3,
        window_seconds: int = 3600,
        patterns: tuple[tuple[tuple[str, ...], str], ...] | None = None,
    ):
        self._max_gap = max(0, max_gap)
        self._window = timedelta(seconds=window_seconds)
        self._patterns = patterns or DEFAULT_CHAIN_PATTERNS
        # session_id -> deque of (timestamp, action, event_id)
        self._history: dict[str, deque[tuple[datetime, str, str]]] = {}
        self._matches: list[dict] = []
        self._lock = threading.Lock()

    def handle(self, event: NormalizedEvent) -> None:
        # detail.session_id stitches together MCP calls inside one
        # logical agent session.  Without it we can't reason about
        # chains, so events without one are ignored here.
        session_id = event.detail.get("session_id")
        if not session_id:
            return
        with self._lock:
            history = self._history.setdefault(session_id, deque(maxlen=100))
            self._evict(history, event.timestamp)
            history.append((event.timestamp, event.action, event.event_id))
            self._scan_for_matches(event, session_id, history)

    def _scan_for_matches(
        self,
        event: NormalizedEvent,
        session_id: str,
        history: deque[tuple[datetime, str, str]],
    ) -> None:
        actions_in_history = [a for _, a, _ in history]
        for pattern, severity in self._patterns:
            if self._matches_with_gap(actions_in_history, pattern):
                self._matches.append({
                    "tenant_id": event.tenant_id,
                    "session_id": session_id,
                    "pattern": pattern,
                    "severity": severity,
                    "matched_at": event.timestamp.isoformat(),
                    "trigger_event_id": event.event_id,
                })

    def _matches_with_gap(self, actions: list[str], pattern: tuple[str, ...]) -> bool:
        """Check if `pattern` is a subsequence of `actions` with bounded gap."""
        if not pattern:
            return False
        idx = 0
        gap = 0
        for action in actions:
            if action == pattern[idx]:
                idx += 1
                gap = 0
                if idx == len(pattern):
                    return True
            elif idx > 0:
                gap += 1
                if gap > self._max_gap:
                    return False
        return False

    def _evict(self, history: deque[tuple[datetime, str, str]], now: datetime) -> None:
        cutoff = now - self._window
        while history and history[0][0] < cutoff:
            history.popleft()

    def matches(self) -> list[dict]:
        with self._lock:
            return list(self._matches)
