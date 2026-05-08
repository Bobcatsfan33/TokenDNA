"""Tests for the TrustGraphEngine event-stream entry point."""
# SPDX-License-Identifier: BUSL-1.1

from __future__ import annotations

from datetime import datetime, timezone

from tokendna_platform.engines.trust_graph import TrustGraphEngine
from tokendna_platform.ingestion.router import EventRouter
from tokendna_platform.schema import EventCategory, EventOutcome, NormalizedEvent


def _ev(subject: str, resource: str, action: str = "x",
        category: EventCategory = EventCategory.AUTHENTICATION,
        tenant: str = "t1") -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"e-{subject}-{resource}-{action}",
        timestamp=datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc),
        source_type="okta",
        event_category=category,
        subject=subject,
        action=action,
        resource=resource,
        outcome=EventOutcome.SUCCESS,
        detail={},
        tenant_id=tenant,
        collector_id="c1",
    )


def test_first_event_creates_edge() -> None:
    e = TrustGraphEngine()
    e.handle(_ev("alice", "okta-app"))
    assert e.edge_count("t1") == 1
    assert e.edges_for("t1", "alice")[0].resource == "okta-app"


def test_repeat_event_increments_count() -> None:
    e = TrustGraphEngine()
    e.handle(_ev("alice", "okta-app"))
    e.handle(_ev("alice", "okta-app"))
    assert e.edge_count("t1") == 1
    edges = e.edges_for("t1", "alice")
    assert edges[0].seen_count == 2


def test_distinct_actions_tracked_per_edge() -> None:
    e = TrustGraphEngine()
    e.handle(_ev("alice", "app", action="user.session.start"))
    e.handle(_ev("alice", "app", action="user.session.end"))
    edges = e.edges_for("t1", "alice")
    assert edges[0].distinct_actions == {"user.session.start", "user.session.end"}


def test_register_with_router_routes_only_relevant_events() -> None:
    router = EventRouter()
    engine = TrustGraphEngine()
    engine.register_with(router)
    router.route(_ev("alice", "app", category=EventCategory.AUTHENTICATION))
    router.route(_ev("alice", "app", category=EventCategory.NETWORK))
    # NETWORK is not in the engine's category list, so only one event hit.
    edges = engine.edges_for("t1", "alice")
    assert edges[0].seen_count == 1


def test_tenant_isolation() -> None:
    e = TrustGraphEngine()
    e.handle(_ev("alice", "app", tenant="t1"))
    e.handle(_ev("alice", "app", tenant="t2"))
    assert e.edge_count("t1") == 1
    assert e.edge_count("t2") == 1
    assert len(e.edges_for("t1", "alice")) == 1
