"""Health reporting types.

The collector's ``/health`` endpoint aggregates per-adapter
``HealthStatus`` snapshots into a single document for container-
orchestration probes (k8s, docker-compose) and Prometheus.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class HealthState(str, Enum):
    """Three-state health: green / yellow / red."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"      # working but with warnings
    UNHEALTHY = "unhealthy"    # cannot reach source


@dataclass(frozen=True)
class HealthStatus:
    """Single adapter's health snapshot."""
    state: HealthState
    detail: str
    last_successful_poll: datetime | None = None
    consecutive_failures: int = 0
    checked_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
