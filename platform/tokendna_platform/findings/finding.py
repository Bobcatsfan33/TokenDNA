"""Unified finding shape consumed by every downstream subsystem."""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from __future__ import annotations

import threading
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class FindingSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_RANK = {
    FindingSeverity.LOW: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.HIGH: 3,
    FindingSeverity.CRITICAL: 4,
}


@dataclass(frozen=True)
class Finding:
    """Canonical finding record.

    Engines convert their internal output (``DriftFinding``,
    ``PolicyFinding``, MCP chain match dict, etc.) into this shape so
    every downstream consumer (alerts, SIEM, dashboard, compliance)
    sees one schema.
    """

    finding_id: str
    title: str
    severity: FindingSeverity
    tenant_id: str
    subject: str               # WHO this is about (agent, user, role)
    source_engine: str         # "trust_graph" | "behavioral_dna" | ...
    detected_at: datetime
    description: str = ""
    related_event_ids: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def new(
        cls,
        *,
        title: str,
        severity: FindingSeverity | str,
        tenant_id: str,
        subject: str,
        source_engine: str,
        description: str = "",
        related_event_ids: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> "Finding":
        """Convenience constructor that mints a UUID + timestamp."""
        if isinstance(severity, str) and not isinstance(severity, FindingSeverity):
            severity = FindingSeverity(severity)
        return cls(
            finding_id=f"f-{uuid.uuid4().hex[:16]}",
            title=title,
            severity=severity,
            tenant_id=tenant_id,
            subject=subject,
            source_engine=source_engine,
            detected_at=datetime.now(timezone.utc),
            description=description,
            related_event_ids=tuple(related_event_ids),
            metadata=dict(metadata or {}),
        )

    @property
    def severity_rank(self) -> int:
        return _SEVERITY_RANK[self.severity]


class FindingStore(ABC):
    """Persisted-finding storage contract."""

    @abstractmethod
    def write(self, finding: Finding) -> None:
        ...

    @abstractmethod
    def list(
        self,
        tenant_id: str,
        *,
        min_severity: FindingSeverity | None = None,
        limit: int = 100,
    ) -> list[Finding]:
        ...


class InMemoryFindingStore(FindingStore):
    """Reference implementation; used by tests + dashboard mock mode."""

    def __init__(self) -> None:
        self._findings: dict[str, list[Finding]] = {}
        self._lock = threading.Lock()

    def write(self, finding: Finding) -> None:
        with self._lock:
            self._findings.setdefault(finding.tenant_id, []).append(finding)

    def list(
        self,
        tenant_id: str,
        *,
        min_severity: FindingSeverity | None = None,
        limit: int = 100,
    ) -> list[Finding]:
        with self._lock:
            findings = list(self._findings.get(tenant_id, []))
        if min_severity is not None:
            min_rank = _SEVERITY_RANK[min_severity]
            findings = [f for f in findings if f.severity_rank >= min_rank]
        # Most recent first.
        findings.sort(key=lambda f: f.detected_at, reverse=True)
        return findings[:limit]
