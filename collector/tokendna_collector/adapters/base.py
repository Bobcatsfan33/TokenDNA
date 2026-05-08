"""Adapter contract.

Every collector adapter implements ``BaseAdapter`` and emits
``NormalizedEvent`` instances.  The architectural rationale lives in
``collector/README.md``.

This is the only place the contract lives — every concrete adapter
under ``tokendna_collector.adapters.{idp,siem,cloud,ai_workload}``
imports from here.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import AsyncIterator

from ..config import AdapterConfig
from ..health import HealthStatus
from ..schema import NormalizedEvent


class BaseAdapter(ABC):
    """All collector adapters subclass this.

    Adapters MUST be safe to instantiate without doing I/O.  Network
    connections happen inside :meth:`connect`.  Polling happens inside
    :meth:`poll` and yields events lazily so the collector can apply
    backpressure when the cloud is slow.
    """

    @property
    @abstractmethod
    def source_type(self) -> str:
        """Stable identifier such as ``"okta"`` or ``"aws_cloudtrail"``."""
        raise NotImplementedError

    @abstractmethod
    async def connect(self, config: AdapterConfig) -> None:
        """Establish the connection to the source system.

        Raises an adapter-specific exception on auth/network failure;
        the collector logs and retries with exponential backoff.
        """
        raise NotImplementedError

    @abstractmethod
    async def poll(self) -> AsyncIterator[NormalizedEvent]:
        """Pull events that have arrived since the last successful poll.

        Implementations track their own cursor (timestamp / sequence)
        so a restart can resume without duplicating or losing events.
        Yields events lazily; the transport layer consumes them.
        """
        raise NotImplementedError

    @abstractmethod
    async def health_check(self) -> HealthStatus:
        """Report the adapter's current health.

        Surfaced through the collector's ``/health`` endpoint and
        Prometheus metrics.  Should be cheap (no I/O if possible) and
        non-blocking.
        """
        raise NotImplementedError
