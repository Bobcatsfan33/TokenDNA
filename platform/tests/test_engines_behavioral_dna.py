"""Tests for BehavioralDNAEngine."""
# SPDX-License-Identifier: BUSL-1.1

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from tokendna_platform.engines.behavioral_dna import BehavioralDNAEngine
from tokendna_platform.schema import EventCategory, EventOutcome, NormalizedEvent


def _ev(action: str, when: datetime, subject: str = "alice") -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"e-{action}-{when.isoformat()}",
        timestamp=when,
        source_type="okta",
        event_category=EventCategory.AUTHENTICATION,
        subject=subject,
        action=action,
        resource="app",
        outcome=EventOutcome.SUCCESS,
        detail={},
        tenant_id="t1",
        collector_id="c1",
    )


def test_fingerprint_counts_actions() -> None:
    e = BehavioralDNAEngine()
    now = datetime.now(timezone.utc)
    for _ in range(3):
        e.handle(_ev("login", now))
    e.handle(_ev("invoke_model", now))
    fp = e.fingerprint("t1", "alice")
    assert fp == {"login": 3, "invoke_model": 1}


def test_window_evicts_old_events() -> None:
    e = BehavioralDNAEngine(window_seconds=60)
    base = datetime.now(timezone.utc)
    e.handle(_ev("old", base - timedelta(seconds=120)))
    e.handle(_ev("new", base))
    fp = e.fingerprint("t1", "alice")
    assert fp == {"new": 1}


def test_subjects_isolated() -> None:
    e = BehavioralDNAEngine()
    now = datetime.now(timezone.utc)
    e.handle(_ev("a", now, subject="alice"))
    e.handle(_ev("b", now, subject="bob"))
    assert e.fingerprint("t1", "alice") == {"a": 1}
    assert e.fingerprint("t1", "bob") == {"b": 1}
