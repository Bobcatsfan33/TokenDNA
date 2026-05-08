"""Collector process runner — wires adapters, buffer, transport together.

This is the main loop.  Each adapter runs as its own asyncio task with
a configurable poll interval; events flow into a shared bounded queue
that the transport task drains in batches and ships to the cloud.

If the cloud is unreachable, transient failures cause the transport to
spool to ``LocalBuffer``.  When the cloud comes back, the buffer drains
in arrival order before fresh events are sent.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from __future__ import annotations

import asyncio
import logging
import random
from typing import Iterable

from .adapters.base import BaseAdapter
from .config import CollectorConfig
from .health import HealthState, HealthStatus
from .schema import NormalizedEvent
from .transport import (
    CloudStream,
    LocalBuffer,
    PermanentTransportError,
    TransientTransportError,
)

logger = logging.getLogger("tokendna_collector")


class CollectorRunner:
    """Owns the adapter tasks + transport task for one collector process."""

    def __init__(
        self,
        config: CollectorConfig,
        adapters: Iterable[BaseAdapter],
        *,
        cloud_stream: CloudStream | None = None,
        local_buffer: LocalBuffer | None = None,
        batch_size: int = 500,
    ):
        self._config = config
        self._adapters = list(adapters)
        self._cloud = cloud_stream or CloudStream(
            endpoint=config.cloud_endpoint,
            api_key=config.cloud_api_key,
            tenant_id=config.tenant_id,
            collector_id=config.collector_id,
        )
        self._buffer = local_buffer or LocalBuffer(config.buffer_path)
        self._queue: asyncio.Queue[NormalizedEvent] = asyncio.Queue(maxsize=10_000)
        self._batch_size = batch_size
        self._stop = asyncio.Event()

    # ── Lifecycle ───────────────────────────────────────────────────────
    async def start(self) -> None:
        await asyncio.gather(*(self._adapter_loop(a) for a in self._adapters),
                             self._transport_loop())

    def stop(self) -> None:
        self._stop.set()

    # ── Per-adapter polling loop ────────────────────────────────────────
    async def _adapter_loop(self, adapter: BaseAdapter) -> None:
        cfg = next(
            (c for c in self._config.adapters if c.source_type == adapter.source_type),
            None,
        )
        if cfg is None:
            logger.warning("no AdapterConfig for source %s; skipping", adapter.source_type)
            return
        # Inject framework-managed identity into the adapter's options
        # so the adapter can stamp every emitted event with them.
        cfg.options.setdefault("tenant_id", self._config.tenant_id)
        cfg.options.setdefault("collector_id", self._config.collector_id)
        try:
            await adapter.connect(cfg)
        except Exception:
            logger.exception("adapter %s connect() failed; will not start", adapter.source_type)
            return
        backoff = 1.0
        while not self._stop.is_set():
            try:
                async for event in adapter.poll():
                    await self._queue.put(event)
                backoff = 1.0
            except Exception:
                logger.exception("adapter %s poll failed", adapter.source_type)
                await asyncio.sleep(min(backoff, 60.0) + random.random())
                backoff = min(backoff * 2, 60.0)
                continue
            await asyncio.sleep(cfg.poll_interval_seconds)

    # ── Transport drain loop ────────────────────────────────────────────
    async def _transport_loop(self) -> None:
        backoff = 1.0
        while not self._stop.is_set():
            batch = await self._collect_batch()
            if not batch:
                await asyncio.sleep(0.5)
                continue
            try:
                await asyncio.to_thread(self._cloud.send_batch, batch)
                backoff = 1.0
            except PermanentTransportError:
                logger.exception("cloud rejected batch (permanent); dropping after buffer")
                # Buffer it anyway so a human can investigate later.
                self._buffer.append_many(batch)
            except TransientTransportError:
                logger.warning("cloud transient failure; spilling %d events to disk", len(batch))
                self._buffer.append_many(batch)
                await asyncio.sleep(min(backoff, 60.0) + random.random())
                backoff = min(backoff * 2, 60.0)

    async def _collect_batch(self) -> list[NormalizedEvent]:
        batch: list[NormalizedEvent] = []
        try:
            first = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            batch.append(first)
        except asyncio.TimeoutError:
            return batch
        while len(batch) < self._batch_size:
            try:
                batch.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return batch

    # ── Aggregate health ───────────────────────────────────────────────
    async def health(self) -> dict:
        per_adapter: list[HealthStatus] = []
        for adapter in self._adapters:
            try:
                per_adapter.append(await adapter.health_check())
            except Exception:
                per_adapter.append(HealthStatus(
                    state=HealthState.UNHEALTHY,
                    detail=f"health_check raised on {adapter.source_type}",
                ))
        worst = HealthState.HEALTHY
        for h in per_adapter:
            if h.state == HealthState.UNHEALTHY:
                worst = HealthState.UNHEALTHY
                break
            if h.state == HealthState.DEGRADED:
                worst = HealthState.DEGRADED
        return {
            "state": worst.value,
            "queue_depth": self._queue.qsize(),
            "adapters": [
                {
                    "source_type": a.source_type,
                    "state": h.state.value,
                    "detail": h.detail,
                    "consecutive_failures": h.consecutive_failures,
                    "last_successful_poll": (
                        h.last_successful_poll.isoformat()
                        if h.last_successful_poll else None
                    ),
                }
                for a, h in zip(self._adapters, per_adapter)
            ],
        }
