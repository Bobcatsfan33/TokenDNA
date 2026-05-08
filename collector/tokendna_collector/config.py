"""Adapter + collector configuration shapes.

Loaded from environment variables at startup; see ``collector/README.md``
for the complete env-var reference.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AdapterConfig:
    """Per-adapter configuration.

    Concrete adapter subclasses are free to define a stricter dataclass
    that subclasses this one — the base captures the fields every
    adapter needs and nothing more.
    """
    source_type: str                                # must equal BaseAdapter.source_type
    name: str                                       # human-readable label
    poll_interval_seconds: int = 30
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class CollectorConfig:
    """Top-level collector process configuration."""
    tenant_id: str
    collector_id: str
    cloud_endpoint: str
    cloud_api_key: str
    health_listen_addr: str = "0.0.0.0:9100"
    buffer_path: str = "/var/lib/tokendna-collector/buffer"
    adapters: list[AdapterConfig] = field(default_factory=list)
