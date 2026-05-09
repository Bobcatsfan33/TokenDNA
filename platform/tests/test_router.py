"""Tests for the category → engine event router."""
# SPDX-License-Identifier: BUSL-1.1

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tokendna_platform.ingestion.router import EventRouter
from tokendna_platform.schema import EventCategory, EventOutcome, NormalizedEvent


def _ev(category: EventCategory) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"e-{category.value}",
        timestamp=datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc),
        source_type="test",
        event_category=category,
        subject="alice",
        action="x",
        resource="r",
        outcome=EventOutcome.SUCCESS,
        detail={},
        tenant_id="t1",
        collector_id="c1",
    )


def test_handler_only_called_for_registered_category() -> None:
    r = EventRouter()
    seen: list[str] = []
    r.register_handler("trust_graph", lambda e: seen.append(e.event_id), EventCategory.AUTHENTICATION)

    r.route(_ev(EventCategory.AUTHENTICATION))
    r.route(_ev(EventCategory.NETWORK))

    assert seen == ["e-authentication"]


def test_handler_can_subscribe_to_multiple_categories() -> None:
    r = EventRouter()
    seen: list[str] = []
    r.register_handler(
        "behavioural_dna",
        lambda e: seen.append(e.event_id),
        EventCategory.AUTHENTICATION,
        EventCategory.AUTHORIZATION,
        EventCategory.AI_INVOCATION,
    )

    for cat in (EventCategory.AUTHENTICATION, EventCategory.AUTHORIZATION,
                EventCategory.AI_INVOCATION, EventCategory.NETWORK):
        r.route(_ev(cat))

    assert seen == [
        "e-authentication", "e-authorization", "e-ai_invocation",
    ]


def test_unknown_category_handler_is_catch_all() -> None:
    """Handlers registered on UNKNOWN receive events of every category."""
    r = EventRouter()
    seen: list[str] = []
    r.register_handler("audit_archive", lambda e: seen.append(e.event_id), EventCategory.UNKNOWN)

    r.route(_ev(EventCategory.AUTHENTICATION))
    r.route(_ev(EventCategory.UNKNOWN))

    assert seen == ["e-authentication", "e-unknown"]


def test_handler_failure_does_not_block_other_handlers() -> None:
    r = EventRouter()
    seen: list[str] = []

    def boom(_e: NormalizedEvent) -> None:
        raise RuntimeError("explicit handler failure")

    r.register_handler("boom", boom, EventCategory.AUTHENTICATION)
    r.register_handler("ok", lambda e: seen.append(e.event_id), EventCategory.AUTHENTICATION)

    result = r.route(_ev(EventCategory.AUTHENTICATION))
    assert result == {"handlers_invoked": 1, "handlers_failed": 1}
    assert seen == ["e-authentication"]


def test_re_register_replaces_existing_handler() -> None:
    r = EventRouter()
    seen: list[str] = []
    r.register_handler("h", lambda e: seen.append("v1"), EventCategory.AUTHENTICATION)
    r.register_handler("h", lambda e: seen.append("v2"), EventCategory.AUTHENTICATION)

    r.route(_ev(EventCategory.AUTHENTICATION))
    assert seen == ["v2"]
    assert r.handlers_for(EventCategory.AUTHENTICATION) == ["h"]


def test_register_with_no_categories_rejected() -> None:
    r = EventRouter()
    with pytest.raises(ValueError):
        r.register_handler("nothing", lambda e: None)
