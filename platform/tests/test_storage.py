"""Tests for the EventStore contract + in-memory reference implementation."""
# SPDX-License-Identifier: BUSL-1.1

from __future__ import annotations

from datetime import datetime, timezone

from tokendna_platform.ingestion.storage import InMemoryEventStore
from tokendna_platform.schema import EventCategory, EventOutcome, NormalizedEvent


def _ev(event_id: str, tenant: str = "t1") -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc),
        source_type="okta",
        event_category=EventCategory.AUTHENTICATION,
        subject="alice",
        action="x",
        resource="r",
        outcome=EventOutcome.SUCCESS,
        detail={},
        tenant_id=tenant,
        collector_id="c1",
    )


def test_write_persists_unique_events() -> None:
    s = InMemoryEventStore()
    written = s.write([_ev("e-1"), _ev("e-2")])
    assert written == 2
    assert len(s) == 2


def test_write_dedupes_by_id_within_tenant() -> None:
    s = InMemoryEventStore()
    s.write([_ev("e-1")])
    again = s.write([_ev("e-1")])
    assert again == 0
    assert len(s) == 1


def test_same_id_different_tenant_not_deduped() -> None:
    s = InMemoryEventStore()
    s.write([_ev("e-1", tenant="t1")])
    written = s.write([_ev("e-1", tenant="t2")])
    assert written == 1
    assert len(s) == 2
