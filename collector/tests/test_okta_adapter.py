"""Tests for the Okta System Log adapter.

Stub the HTTP fetch via monkeypatching ``_fetch_events`` — keeps the test
suite hermetic, no real Okta tenant required.
"""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio

import pytest

from tokendna_collector.adapters.idp.okta import (
    OktaAdapterError,
    OktaSystemLogAdapter,
)
from tokendna_collector.config import AdapterConfig
from tokendna_collector.health import HealthState
from tokendna_collector.schema import EventCategory, EventOutcome


def _config(**extra) -> AdapterConfig:
    opts = {
        "domain": "example.okta.com",
        "api_token": "fake-token",
        "tenant_id": "t1",
        "collector_id": "c1",
        **extra,
    }
    return AdapterConfig(source_type="okta", name="okta-test", options=opts)


def test_normalize_authentication_event() -> None:
    a = OktaSystemLogAdapter()
    asyncio.run(a.connect(_config()))
    raw = {
        "uuid": "abc-123",
        "published": "2026-05-08T12:00:00Z",
        "eventType": "user.session.start",
        "actor": {"alternateId": "alice@example.com"},
        "target": [{"alternateId": "okta-app"}],
        "outcome": {"result": "SUCCESS"},
        "client": {"ipAddress": "203.0.113.1"},
    }
    ev = a._normalize(raw)
    assert ev is not None
    assert ev.source_type == "okta"
    assert ev.event_category == EventCategory.AUTHENTICATION
    assert ev.subject == "alice@example.com"
    assert ev.resource == "okta-app"
    assert ev.outcome == EventOutcome.SUCCESS
    assert ev.detail["client_ip"] == "203.0.113.1"
    assert ev.tenant_id == "t1"
    assert ev.collector_id == "c1"


def test_normalize_failure_outcome() -> None:
    a = OktaSystemLogAdapter()
    asyncio.run(a.connect(_config()))
    raw = {
        "uuid": "abc-456",
        "published": "2026-05-08T12:00:00Z",
        "eventType": "user.authentication.auth_via_mfa",
        "actor": {"alternateId": "alice@example.com"},
        "target": [],
        "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
        "client": {},
    }
    ev = a._normalize(raw)
    assert ev is not None
    assert ev.outcome == EventOutcome.FAILURE
    assert ev.detail["outcome_reason"] == "INVALID_CREDENTIALS"


def test_normalize_permission_change_event() -> None:
    a = OktaSystemLogAdapter()
    asyncio.run(a.connect(_config()))
    raw = {
        "uuid": "abc-789",
        "published": "2026-05-08T12:00:00Z",
        "eventType": "group.user_membership.add",
        "actor": {"alternateId": "admin@example.com"},
        "target": [{"alternateId": "ai-engineers"}],
        "outcome": {"result": "SUCCESS"},
        "client": {},
    }
    ev = a._normalize(raw)
    assert ev is not None
    assert ev.event_category == EventCategory.PERMISSION_CHANGE


def test_unknown_event_type_falls_through_to_unknown_category() -> None:
    a = OktaSystemLogAdapter()
    asyncio.run(a.connect(_config()))
    raw = {
        "uuid": "x",
        "published": "2026-05-08T12:00:00Z",
        "eventType": "totally.new.event.we.do.not.know",
        "actor": {"alternateId": "alice"},
        "outcome": {"result": "SUCCESS"},
    }
    ev = a._normalize(raw)
    assert ev is not None
    assert ev.event_category == EventCategory.UNKNOWN


def test_connect_requires_domain_and_token() -> None:
    a = OktaSystemLogAdapter()
    with pytest.raises(OktaAdapterError):
        asyncio.run(a.connect(AdapterConfig(source_type="okta", name="x", options={})))


def test_health_starts_healthy() -> None:
    a = OktaSystemLogAdapter()
    asyncio.run(a.connect(_config()))
    h = asyncio.run(a.health_check())
    assert h.state == HealthState.HEALTHY


def test_poll_advances_cursor(monkeypatch) -> None:
    a = OktaSystemLogAdapter()
    asyncio.run(a.connect(_config()))
    # First poll returns one event with timestamp T1.
    monkeypatch.setattr(a, "_fetch_events", lambda _cur: [
        {
            "uuid": "e1",
            "published": "2026-05-08T12:00:00Z",
            "eventType": "user.session.start",
            "actor": {"alternateId": "alice"},
            "outcome": {"result": "SUCCESS"},
        },
    ])

    async def drain() -> list:
        return [ev async for ev in a.poll()]

    events = asyncio.run(drain())
    assert len(events) == 1
    assert a._cursor == "2026-05-08T12:00:00Z"


def test_poll_propagates_failure_as_adapter_error(monkeypatch) -> None:
    a = OktaSystemLogAdapter()
    asyncio.run(a.connect(_config()))

    def boom(_cur):
        raise RuntimeError("network down")

    monkeypatch.setattr(a, "_fetch_events", boom)

    async def drain():
        return [ev async for ev in a.poll()]

    with pytest.raises(OktaAdapterError):
        asyncio.run(drain())
    assert a._consecutive_failures == 1
