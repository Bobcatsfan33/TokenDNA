"""Tests for the local-disk buffer."""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from tokendna_collector.schema import EventCategory, EventOutcome, NormalizedEvent
from tokendna_collector.transport.buffer import LocalBuffer, _serialize


def _ev(i: int) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"e-{i}",
        timestamp=datetime(2026, 5, 8, 12, 0, i, tzinfo=timezone.utc),
        source_type="test",
        event_category=EventCategory.AUTHENTICATION,
        subject="alice",
        action="login",
        resource="app",
        outcome=EventOutcome.SUCCESS,
        detail={},
        tenant_id="t1",
        collector_id="c1",
    )


def test_append_and_iter_round_trip(tmp_path: Path) -> None:
    buf = LocalBuffer(tmp_path)
    events = [_ev(i) for i in range(3)]
    buf.append_many(events)
    pending = list(buf.iter_pending())
    assert len(pending) == 3
    # Lines are serialized JSONL — first event id should appear in the first line.
    assert "e-0" in pending[0][1]
    assert "e-2" in pending[2][1]


def test_drain_through_removes_prefix(tmp_path: Path) -> None:
    buf = LocalBuffer(tmp_path)
    events = [_ev(i) for i in range(5)]
    buf.append_many(events)

    pending = list(buf.iter_pending())
    cursor_line = pending[2][1]  # remove first 3 events
    removed = buf.drain_through(cursor_line)
    assert removed == 3

    remaining = list(buf.iter_pending())
    assert len(remaining) == 2
    assert "e-3" in remaining[0][1]
    assert "e-4" in remaining[1][1]


def test_serialize_includes_all_fields(tmp_path: Path) -> None:
    line = _serialize(_ev(1))
    assert "e-1" in line
    assert "authentication" in line
    assert "success" in line
    # ISO timestamp survives the round-trip
    assert "2026-05-08T12:00:01" in line
