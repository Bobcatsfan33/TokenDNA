"""TokenDNA Collector — open-source edge collector.

Lives inside the customer's network.  Pulls events from their existing
IDP, SIEM, cloud platforms, and AI workload telemetry, normalizes them
into :class:`tokendna_collector.schema.NormalizedEvent`, and ships
them over mTLS to the TokenDNA Cloud platform.

Public surface:

  * :class:`~tokendna_collector.adapters.BaseAdapter` — adapter contract
  * :class:`~tokendna_collector.schema.NormalizedEvent` — universal event shape
  * :class:`~tokendna_collector.config.CollectorConfig` — process config
  * :class:`~tokendna_collector.health.HealthStatus` — adapter health

License: Apache 2.0.  See ``collector/LICENSE``.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

__version__ = "0.0.1"

from .adapters import BaseAdapter
from .config import AdapterConfig, CollectorConfig
from .health import HealthState, HealthStatus
from .schema import EventCategory, EventOutcome, NormalizedEvent, SCHEMA_VERSION

__all__ = [
    "AdapterConfig",
    "BaseAdapter",
    "CollectorConfig",
    "EventCategory",
    "EventOutcome",
    "HealthState",
    "HealthStatus",
    "NormalizedEvent",
    "SCHEMA_VERSION",
    "__version__",
]
