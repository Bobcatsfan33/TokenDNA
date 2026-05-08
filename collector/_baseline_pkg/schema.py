"""TokenDNA Collector — universal event schema.

All adapters in ``tokendna_collector.adapters.*`` normalize events from
their source systems (Okta, Splunk, AWS CloudTrail, MCP traffic, etc.)
into the shape defined here.  The cloud platform's ingestion layer
assumes every event arriving from a collector matches this schema
exactly.

Adding a field is a minor version bump:
  1. Bump ``SCHEMA_VERSION``.
  2. Update every adapter that produces the field.
  3. Coordinate with the cloud team — the ingestion layer must accept
     the new field before any adapter starts emitting it.

Removing a field is a breaking change.  Coordinate with the cloud team.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


SCHEMA_VERSION = "1.0"


class EventCategory(str, Enum):
    """Coarse classification used by the cloud ingestion router."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CONFIG_CHANGE = "config_change"
    AI_INVOCATION = "ai_invocation"
    PERMISSION_CHANGE = "permission_change"
    NETWORK = "network"
    UNKNOWN = "unknown"


class EventOutcome(str, Enum):
    """Whether the underlying action in the source system succeeded."""
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class NormalizedEvent:
    """Universal event shape every adapter emits.

    Frozen so the transport layer cannot accidentally mutate events in
    flight, and so events are safe to share across coroutines without
    copying.
    """

    event_id: str                 # Stable per-event id (collector-generated; UUID v4).
    timestamp: datetime           # Source-of-truth timestamp from the source system.
    source_type: str              # e.g. "okta", "aws_cloudtrail", "mcp_mirror".
    event_category: EventCategory
    subject: str                  # WHO performed the action.
    action: str                   # WHAT they did.
    resource: str                 # ON WHAT they did it.
    outcome: EventOutcome
    detail: dict[str, Any]        # Source-specific subset of the raw event.
    tenant_id: str                # Which TokenDNA cloud tenant this belongs to.
    collector_id: str             # Which collector instance emitted this event.

    # Bookkeeping fields the transport layer fills in.
    schema_version: str = SCHEMA_VERSION
    received_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
