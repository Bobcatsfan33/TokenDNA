"""Tests for the universal event schema."""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

import pytest

from tokendna_collector.schema import (
    EventCategory,
    EventOutcome,
    NormalizedEvent,
    SCHEMA_VERSION,
)


def test_event_is_frozen() -> None:
    ev = _sample_event()
    with pytest.raises(dataclasses.FrozenInstanceError):
        ev.subject = "tampered"  # type: ignore[misc]


def test_schema_version_pinned() -> None:
    """Bumping this constant is a coordinated change with the cloud."""
    assert SCHEMA_VERSION == "1.0"


def test_round_trip_to_dict() -> None:
    ev = _sample_event()
    d = dataclasses.asdict(ev)
    assert d["source_type"] == "test"
    # Enums are str-Enum, so asdict gives back the enum object — that's
    # fine inside the runtime.  Wire serialisation is the transport layer's
    # job and is exercised in test_buffer + test_stream.
    assert d["event_category"] == EventCategory.AUTHENTICATION
    assert d["outcome"] == EventOutcome.SUCCESS


def test_event_categories_complete() -> None:
    """If we add a category here we MUST update adapters that emit it."""
    expected = {
        "authentication", "authorization", "config_change",
        "ai_invocation", "permission_change", "network", "unknown",
    }
    assert {c.value for c in EventCategory} == expected


def test_event_outcomes_complete() -> None:
    expected = {"success", "failure", "denied", "unknown"}
    assert {o.value for o in EventOutcome} == expected


# ── helpers ─────────────────────────────────────────────────────────────────

def _sample_event() -> NormalizedEvent:
    return NormalizedEvent(
        event_id="e-1",
        timestamp=datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc),
        source_type="test",
        event_category=EventCategory.AUTHENTICATION,
        subject="alice@example.com",
        action="user.session.start",
        resource="okta-app",
        outcome=EventOutcome.SUCCESS,
        detail={"client_ip": "203.0.113.1"},
        tenant_id="t1",
        collector_id="c1",
    )
