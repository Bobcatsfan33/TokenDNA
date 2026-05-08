"""Tests for MCPChainEngine bounded-gap subsequence detection."""
# SPDX-License-Identifier: BUSL-1.1

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from tokendna_platform.engines.mcp_inspector import MCPChainEngine
from tokendna_platform.schema import EventCategory, EventOutcome, NormalizedEvent


def _mcp(action: str, *, session: str = "s1", offset: int = 0) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"e-{action}-{offset}",
        timestamp=datetime(2026, 5, 8, 12, 0, offset, tzinfo=timezone.utc),
        source_type="mcp_mirror",
        event_category=EventCategory.AI_INVOCATION,
        subject="agent-1",
        action=action,
        resource="some-tool",
        outcome=EventOutcome.SUCCESS,
        detail={"session_id": session},
        tenant_id="t1",
        collector_id="c1",
    )


def test_read_then_exfil_pattern_detected() -> None:
    e = MCPChainEngine()
    e.handle(_mcp("read_file", offset=1))
    e.handle(_mcp("send_email", offset=2))
    matches = e.matches()
    assert len(matches) >= 1
    assert matches[0]["pattern"] == ("read_file", "send_email")
    assert matches[0]["severity"] == "high"


def test_chain_with_intervening_call_within_max_gap_still_matches() -> None:
    e = MCPChainEngine(max_gap=2)
    e.handle(_mcp("read_file", offset=1))
    e.handle(_mcp("noop", offset=2))      # one filler within gap
    e.handle(_mcp("send_email", offset=3))
    matches = e.matches()
    assert len(matches) >= 1


def test_chain_with_too_many_intervening_calls_does_not_match() -> None:
    e = MCPChainEngine(max_gap=1)
    e.handle(_mcp("read_file", offset=1))
    e.handle(_mcp("a", offset=2))
    e.handle(_mcp("b", offset=3))
    e.handle(_mcp("c", offset=4))
    e.handle(_mcp("send_email", offset=5))
    assert e.matches() == []


def test_event_without_session_id_ignored() -> None:
    e = MCPChainEngine()
    ev = NormalizedEvent(
        event_id="e1",
        timestamp=datetime.now(timezone.utc),
        source_type="mcp_mirror",
        event_category=EventCategory.AI_INVOCATION,
        subject="agent",
        action="read_file",
        resource="x",
        outcome=EventOutcome.SUCCESS,
        detail={},   # no session_id
        tenant_id="t1",
        collector_id="c1",
    )
    e.handle(ev)
    assert e.matches() == []


def test_separate_sessions_do_not_chain() -> None:
    e = MCPChainEngine()
    e.handle(_mcp("read_file", session="s1", offset=1))
    e.handle(_mcp("send_email", session="s2", offset=2))
    assert e.matches() == []
