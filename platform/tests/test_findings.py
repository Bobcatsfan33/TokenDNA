"""Tests for the unified finding shape + in-memory store."""
# SPDX-License-Identifier: BUSL-1.1

from __future__ import annotations

from tokendna_platform.findings import (
    Finding,
    FindingSeverity,
    InMemoryFindingStore,
)


def _f(severity: FindingSeverity, *, tenant: str = "t1") -> Finding:
    return Finding.new(
        title="t",
        severity=severity,
        tenant_id=tenant,
        subject="alice",
        source_engine="test",
    )


def test_severity_rank_orders_correctly() -> None:
    low = _f(FindingSeverity.LOW)
    crit = _f(FindingSeverity.CRITICAL)
    assert crit.severity_rank > low.severity_rank


def test_store_round_trip() -> None:
    s = InMemoryFindingStore()
    s.write(_f(FindingSeverity.LOW))
    s.write(_f(FindingSeverity.CRITICAL))
    items = s.list("t1")
    assert len(items) == 2


def test_store_filters_by_min_severity() -> None:
    s = InMemoryFindingStore()
    s.write(_f(FindingSeverity.LOW))
    s.write(_f(FindingSeverity.HIGH))
    s.write(_f(FindingSeverity.CRITICAL))
    items = s.list("t1", min_severity=FindingSeverity.HIGH)
    assert len(items) == 2
    assert {i.severity for i in items} == {FindingSeverity.HIGH, FindingSeverity.CRITICAL}


def test_store_orders_by_recent_first() -> None:
    import time
    s = InMemoryFindingStore()
    a = _f(FindingSeverity.LOW)
    s.write(a)
    time.sleep(0.001)
    b = _f(FindingSeverity.LOW)
    s.write(b)
    items = s.list("t1")
    assert items[0].finding_id == b.finding_id
    assert items[1].finding_id == a.finding_id


def test_store_isolates_tenants() -> None:
    s = InMemoryFindingStore()
    s.write(_f(FindingSeverity.LOW, tenant="t1"))
    s.write(_f(FindingSeverity.LOW, tenant="t2"))
    assert len(s.list("t1")) == 1
    assert len(s.list("t2")) == 1
