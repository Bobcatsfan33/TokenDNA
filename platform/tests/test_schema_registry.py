"""Tests for the schema registry / multi-version dispatcher."""
# SPDX-License-Identifier: BUSL-1.1

from __future__ import annotations

import pytest

from tokendna_platform.ingestion.schema_registry import (
    SchemaRegistry,
    UnsupportedSchemaError,
    default_registry,
)
from tokendna_platform.schema import (
    EventCategory,
    EventOutcome,
    KNOWN_SCHEMA_VERSIONS,
    NormalizedEvent,
)
from datetime import datetime, timezone


def test_default_registry_handles_known_versions() -> None:
    reg = default_registry()
    assert reg.known_versions == KNOWN_SCHEMA_VERSIONS


def test_unknown_version_raises() -> None:
    reg = default_registry()
    with pytest.raises(UnsupportedSchemaError):
        reg.deserialize({"schema_version": "99.0"})


def test_register_custom_version() -> None:
    reg = SchemaRegistry()

    def deserialise_2_0(payload):  # pretend 2.0 wraps detail under "context"
        return NormalizedEvent(
            event_id=payload["event_id"],
            timestamp=datetime.now(timezone.utc),
            source_type=payload["source_type"],
            event_category=EventCategory.AUTHENTICATION,
            subject=payload["subject"],
            action=payload["action"],
            resource=payload["resource"],
            outcome=EventOutcome.SUCCESS,
            detail=payload.get("context", {}),
            tenant_id=payload["tenant_id"],
            collector_id=payload["collector_id"],
            schema_version="2.0",
        )

    reg.register("2.0", deserialise_2_0)
    out = reg.deserialize({
        "schema_version": "2.0",
        "event_id": "e-x",
        "source_type": "okta",
        "subject": "alice",
        "action": "x",
        "resource": "r",
        "tenant_id": "t1",
        "collector_id": "c1",
        "context": {"foo": "bar"},
    })
    assert out.detail == {"foo": "bar"}
    assert out.schema_version == "2.0"


def test_double_register_rejected() -> None:
    reg = SchemaRegistry()
    with pytest.raises(ValueError):
        reg.register("1.0", lambda p: None)  # already registered by default
