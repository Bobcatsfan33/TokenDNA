"""Cloud-side NormalizedEvent — tolerant reader for collector frames.

Mirrors the on-wire shape produced by ``tokendna_collector.schema``.
Defined separately on the cloud side so the platform can ship at a
different cadence than the collector and accept multiple collector
versions concurrently (every customer rolls their collector update at
their own pace).

The ``schema_version`` field arriving on each event drives the schema-
registry logic in ``ingestion.schema_registry``.  See that module for
how unknown versions are handled.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CONFIG_CHANGE = "config_change"
    AI_INVOCATION = "ai_invocation"
    PERMISSION_CHANGE = "permission_change"
    NETWORK = "network"
    UNKNOWN = "unknown"


class EventOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    UNKNOWN = "unknown"


# Schema versions the cloud knows how to ingest.  Adding a new version
# is a coordinated change with the collector team.
KNOWN_SCHEMA_VERSIONS = frozenset({"1.0"})


class SchemaError(ValueError):
    """Raised when an inbound event fails validation."""


@dataclass(frozen=True)
class NormalizedEvent:
    """Cloud-side event record (mirrors collector's wire shape)."""

    event_id: str
    timestamp: datetime
    source_type: str
    event_category: EventCategory
    subject: str
    action: str
    resource: str
    outcome: EventOutcome
    detail: dict[str, Any]
    tenant_id: str
    collector_id: str
    schema_version: str = "1.0"
    received_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def from_wire(cls, payload: dict[str, Any]) -> "NormalizedEvent":
        """Tolerant reader: accepts every known schema version.

        Strict on required fields; missing or unknown values raise
        ``SchemaError`` so the ingestion router can return a 400 to
        the collector with a precise reason.
        """
        version = str(payload.get("schema_version") or "1.0")
        if version not in KNOWN_SCHEMA_VERSIONS:
            raise SchemaError(f"unsupported schema_version: {version}")

        try:
            ts = _parse_timestamp(payload["timestamp"])
            received = (
                _parse_timestamp(payload["received_at"])
                if "received_at" in payload
                else datetime.now(timezone.utc)
            )
            category = EventCategory(payload.get("event_category", "unknown"))
            outcome = EventOutcome(payload.get("outcome", "unknown"))
            return cls(
                event_id=str(payload["event_id"]),
                timestamp=ts,
                source_type=str(payload["source_type"]),
                event_category=category,
                subject=str(payload["subject"]),
                action=str(payload["action"]),
                resource=str(payload["resource"]),
                outcome=outcome,
                detail=dict(payload.get("detail") or {}),
                tenant_id=str(payload["tenant_id"]),
                collector_id=str(payload["collector_id"]),
                schema_version=version,
                received_at=received,
            )
        except KeyError as exc:
            raise SchemaError(f"missing required field: {exc.args[0]}") from None
        except (ValueError, TypeError) as exc:
            raise SchemaError(str(exc)) from exc


def _parse_timestamp(raw: Any) -> datetime:
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if isinstance(raw, str):
        # Accept both "...Z" and "+00:00" suffixes
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    raise ValueError(f"timestamp must be ISO string or datetime, got {type(raw).__name__}")
