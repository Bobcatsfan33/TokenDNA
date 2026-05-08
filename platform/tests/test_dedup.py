"""Tests for the at-least-once → exactly-once dedup window."""
# SPDX-License-Identifier: BUSL-1.1

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tokendna_platform.ingestion.dedup import DedupWindow


def test_first_seen_returns_false() -> None:
    w = DedupWindow()
    assert w.seen("t1", "e-1") is False


def test_repeat_within_ttl_returns_true() -> None:
    w = DedupWindow()
    w.seen("t1", "e-1")
    assert w.seen("t1", "e-1") is True


def test_different_tenants_do_not_collide() -> None:
    w = DedupWindow()
    w.seen("t1", "e-1")
    assert w.seen("t2", "e-1") is False


def test_repeat_after_ttl_returns_false() -> None:
    w = DedupWindow(ttl_seconds=10)
    moment = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
    w.seen("t1", "e-1", now=moment)
    assert w.seen("t1", "e-1", now=moment + timedelta(seconds=11)) is False


def test_max_entries_caps_memory() -> None:
    w = DedupWindow(max_entries=3)
    for i in range(5):
        w.seen("t1", f"e-{i}")
    # Oldest entries evicted; only the 3 most recent remain.
    assert len(w) == 3
    # e-0 evicted → not seen anymore
    assert w.seen("t1", "e-0") is False
    # e-4 still in window
    assert w.seen("t1", "e-4") is True


def test_invalid_ttl_rejected() -> None:
    with pytest.raises(ValueError):
        DedupWindow(ttl_seconds=0)


def test_invalid_max_rejected() -> None:
    with pytest.raises(ValueError):
        DedupWindow(max_entries=0)
