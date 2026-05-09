"""Tests for PolicyGuardEngine detect-mode rule evaluation."""
# SPDX-License-Identifier: BUSL-1.1

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tokendna_platform.engines.policy_guard import (
    GuardMode,
    PolicyGuardEngine,
    PolicyRule,
)
from tokendna_platform.schema import EventCategory, EventOutcome, NormalizedEvent


def _ev(action: str, subject: str = "alice") -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"e-{action}",
        timestamp=datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc),
        source_type="okta",
        event_category=EventCategory.AUTHORIZATION,
        subject=subject,
        action=action,
        resource="resource",
        outcome=EventOutcome.SUCCESS,
        detail={},
        tenant_id="t1",
        collector_id="c1",
    )


def test_default_mode_is_detect() -> None:
    e = PolicyGuardEngine()
    assert e.mode == GuardMode.DETECT


def test_rule_fires_on_predicate_match() -> None:
    e = PolicyGuardEngine()
    e.add_rule(PolicyRule(
        rule_id="CONST-01",
        severity="critical",
        description="self-modification of policy",
        predicate=lambda ev: ev.action == "policy.modify_self",
    ))
    e.handle(_ev("policy.modify_self"))
    e.handle(_ev("user.login"))
    findings = e.findings()
    assert len(findings) == 1
    assert findings[0].rule_id == "CONST-01"
    assert findings[0].severity == "critical"


def test_predicate_exception_does_not_break_engine() -> None:
    e = PolicyGuardEngine()

    def boom(_ev):
        raise RuntimeError("buggy rule")

    e.add_rule(PolicyRule("BAD", "low", "buggy", boom))
    e.add_rule(PolicyRule("OK", "low", "ok", lambda ev: True))
    e.handle(_ev("anything"))
    findings = e.findings()
    assert len(findings) == 1
    assert findings[0].rule_id == "OK"


def test_duplicate_rule_id_rejected() -> None:
    e = PolicyGuardEngine()
    e.add_rule(PolicyRule("R1", "low", "", lambda ev: False))
    with pytest.raises(ValueError):
        e.add_rule(PolicyRule("R1", "high", "", lambda ev: True))


def test_engine_can_construct_in_enforce_mode() -> None:
    """Enforce mode is just a flag here; webhook actions live in
    platform/sdk per the disposition map and aren't wired in this sprint."""
    e = PolicyGuardEngine(mode=GuardMode.ENFORCE)
    assert e.mode == GuardMode.ENFORCE
