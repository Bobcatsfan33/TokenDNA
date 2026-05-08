"""Tests for the alert router."""
# SPDX-License-Identifier: BUSL-1.1

from __future__ import annotations

from tokendna_platform.alerts.router import (
    AlertRouter,
    AlertRule,
    InMemoryChannel,
)
from tokendna_platform.findings import Finding, FindingSeverity


def _f(severity: FindingSeverity = FindingSeverity.HIGH) -> Finding:
    return Finding.new(
        title="something",
        severity=severity,
        tenant_id="t1",
        subject="alice",
        source_engine="trust_graph",
    )


def test_finding_routed_to_matching_channel() -> None:
    router = AlertRouter()
    slack = InMemoryChannel("slack")
    router.register_channel(slack)
    router.add_rule(AlertRule(
        name="critical_to_slack",
        predicate=lambda f: f.severity == FindingSeverity.CRITICAL,
        channels=("slack",),
    ))
    router.dispatch(_f(FindingSeverity.LOW))
    router.dispatch(_f(FindingSeverity.CRITICAL))
    delivered = slack.delivered()
    assert len(delivered) == 1
    assert delivered[0].severity == FindingSeverity.CRITICAL


def test_finding_routed_to_multiple_channels() -> None:
    router = AlertRouter()
    slack = InMemoryChannel("slack")
    pd = InMemoryChannel("pagerduty")
    router.register_channel(slack)
    router.register_channel(pd)
    router.add_rule(AlertRule(
        name="all_to_both",
        predicate=lambda f: True,
        channels=("slack", "pagerduty"),
    ))
    router.dispatch(_f())
    assert len(slack.delivered()) == 1
    assert len(pd.delivered()) == 1


def test_unknown_channel_counts_as_failed() -> None:
    router = AlertRouter()
    router.add_rule(AlertRule(
        name="missing_channel",
        predicate=lambda f: True,
        channels=("nonexistent",),
    ))
    result = router.dispatch(_f())
    assert result == {"delivered": 0, "failed": 1}


def test_predicate_exception_does_not_break_dispatch() -> None:
    router = AlertRouter()
    slack = InMemoryChannel("slack")
    router.register_channel(slack)

    def boom(_f):
        raise RuntimeError("buggy predicate")

    router.add_rule(AlertRule("boom", boom, ("slack",)))
    router.add_rule(AlertRule("ok", lambda f: True, ("slack",)))
    router.dispatch(_f())
    # Only the working rule's delivery counts.
    assert len(slack.delivered()) == 1
