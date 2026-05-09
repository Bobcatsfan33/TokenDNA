"""Tests for the cloud-side NormalizedEvent + tolerant reader."""
# SPDX-License-Identifier: BUSL-1.1

from __future__ import annotations

import pytest

from tokendna_platform.schema import (
    EventCategory,
    EventOutcome,
    KNOWN_SCHEMA_VERSIONS,
    NormalizedEvent,
    SchemaError,
)


def _wire_payload(**overrides) -> dict:
    base = {
        "event_id": "e-1",
        "timestamp": "2026-05-08T12:00:00Z",
        "source_type": "okta",
        "event_category": "authentication",
        "subject": "alice@example.com",
        "action": "user.session.start",
        "resource": "okta-app",
        "outcome": "success",
        "detail": {"client_ip": "203.0.113.1"},
        "tenant_id": "t1",
        "collector_id": "c1",
        "schema_version": "1.0",
    }
    base.update(overrides)
    return base


def test_round_trip_from_wire() -> None:
    ev = NormalizedEvent.from_wire(_wire_payload())
    assert ev.event_id == "e-1"
    assert ev.event_category == EventCategory.AUTHENTICATION
    assert ev.outcome == EventOutcome.SUCCESS
    assert ev.detail == {"client_ip": "203.0.113.1"}


def test_unsupported_schema_version_rejected() -> None:
    with pytest.raises(SchemaError):
        NormalizedEvent.from_wire(_wire_payload(schema_version="9.99"))


def test_known_schema_versions_pinned() -> None:
    assert KNOWN_SCHEMA_VERSIONS == frozenset({"1.0"})


def test_missing_required_field_reports_specific_field() -> None:
    payload = _wire_payload()
    del payload["subject"]
    with pytest.raises(SchemaError, match="subject"):
        NormalizedEvent.from_wire(payload)


def test_unknown_category_falls_through_to_unknown() -> None:
    # An adapter we don't know about emits something — ingestion still
    # accepts the event, marks it UNKNOWN.  The router fans UNKNOWN
    # events to the catch-all listeners.
    payload = _wire_payload(event_category="unknown")
    ev = NormalizedEvent.from_wire(payload)
    assert ev.event_category == EventCategory.UNKNOWN


def test_invalid_category_string_rejected() -> None:
    payload = _wire_payload(event_category="not_a_real_category")
    with pytest.raises(SchemaError):
        NormalizedEvent.from_wire(payload)


def test_timestamp_accepts_z_and_offset_suffix() -> None:
    z = NormalizedEvent.from_wire(_wire_payload(timestamp="2026-05-08T12:00:00Z"))
    plus = NormalizedEvent.from_wire(_wire_payload(timestamp="2026-05-08T12:00:00+00:00"))
    assert z.timestamp == plus.timestamp
