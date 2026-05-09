"""Tests for PermissionDriftEngine."""
# SPDX-License-Identifier: BUSL-1.1

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tokendna_platform.engines.permission_drift import PermissionDriftEngine
from tokendna_platform.schema import EventCategory, EventOutcome, NormalizedEvent


def _perm_change(resource: str, subject: str = "alice", tenant: str = "t1") -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"e-{subject}-{resource}",
        timestamp=datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc),
        source_type="okta",
        event_category=EventCategory.PERMISSION_CHANGE,
        subject=subject,
        action="group.user_membership.add",
        resource=resource,
        outcome=EventOutcome.SUCCESS,
        detail={},
        tenant_id=tenant,
        collector_id="c1",
    )


def test_first_resource_establishes_baseline_no_finding() -> None:
    e = PermissionDriftEngine()
    e.handle(_perm_change("group-a"))
    assert e.findings() == []


def test_growth_above_threshold_emits_finding() -> None:
    e = PermissionDriftEngine(growth_factor_threshold=2.0)
    e.handle(_perm_change("g1"))
    e.handle(_perm_change("g2"))
    e.handle(_perm_change("g3"))
    findings = e.findings()
    # The set grew 1→2 (≥2x, finding) and 2→3 (further growth, second finding).
    # Both are legitimate per the engine's anti-flapping rule (re-emit only
    # when current_resource_count strictly increases).
    assert len(findings) >= 1
    assert findings[-1].subject == "alice"
    assert findings[-1].growth_factor >= 2.0
    # Latest finding should reflect the largest set seen.
    assert findings[-1].current_resource_count == 3


def test_growth_below_threshold_no_finding() -> None:
    e = PermissionDriftEngine(growth_factor_threshold=3.0)
    e.handle(_perm_change("g1"))
    e.handle(_perm_change("g2"))
    assert e.findings() == []


def test_invalid_threshold_rejected() -> None:
    with pytest.raises(ValueError):
        PermissionDriftEngine(growth_factor_threshold=1.0)


def test_repeat_resource_does_not_grow_set() -> None:
    e = PermissionDriftEngine(growth_factor_threshold=2.0)
    e.handle(_perm_change("g1"))
    e.handle(_perm_change("g1"))  # duplicate
    assert e.findings() == []
