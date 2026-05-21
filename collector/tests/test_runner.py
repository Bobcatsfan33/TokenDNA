"""Tests for collector runner transport durability."""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

from tokendna_collector.config import CollectorConfig
from tokendna_collector.runner import CollectorRunner
from tokendna_collector.schema import EventCategory, EventOutcome, NormalizedEvent
from tokendna_collector.transport import LocalBuffer, TransientTransportError


def _ev(i: int) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"e-{i}",
        timestamp=datetime(2026, 5, 8, 12, 0, i, tzinfo=timezone.utc),
        source_type="test",
        event_category=EventCategory.AUTHENTICATION,
        subject="alice",
        action="login",
        resource="app",
        outcome=EventOutcome.SUCCESS,
        detail={},
        tenant_id="t1",
        collector_id="c1",
    )


class _Cloud:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.batches: list[list[NormalizedEvent]] = []

    def send_batch(self, events):
        if self.fail:
            raise TransientTransportError("offline")
        self.batches.append(list(events))
        return {"accepted": len(self.batches[-1]), "duplicates": 0}


def _cfg(tmp_path: Path) -> CollectorConfig:
    return CollectorConfig(
        tenant_id="t1",
        collector_id="c1",
        cloud_endpoint="https://tokendna.example",
        cloud_api_key="k",
        buffer_path=str(tmp_path),
    )


def _runner(*args, **kwargs) -> CollectorRunner:
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return CollectorRunner(*args, **kwargs)
    finally:
        asyncio.set_event_loop(None)
        loop.close()


def test_runner_drains_buffered_events_before_fresh_queue(tmp_path: Path) -> None:
    cloud = _Cloud()
    buffer = LocalBuffer(tmp_path)
    buffer.append_many([_ev(1), _ev(2)])
    runner = _runner(
        _cfg(tmp_path),
        [],
        cloud_stream=cloud,  # type: ignore[arg-type]
        local_buffer=buffer,
        batch_size=10,
    )

    assert runner._drain_buffer_once() is True
    assert [e.event_id for e in cloud.batches[0]] == ["e-1", "e-2"]
    assert list(buffer.iter_pending()) == []


def test_runner_keeps_buffer_on_transient_failure(tmp_path: Path) -> None:
    cloud = _Cloud(fail=True)
    buffer = LocalBuffer(tmp_path)
    buffer.append(_ev(1))
    runner = _runner(
        _cfg(tmp_path),
        [],
        cloud_stream=cloud,  # type: ignore[arg-type]
        local_buffer=buffer,
    )

    try:
        runner._drain_buffer_once()
    except TransientTransportError:
        pass
    else:  # pragma: no cover - defensive
        raise AssertionError("expected transient failure")

    assert len(list(buffer.iter_pending())) == 1
