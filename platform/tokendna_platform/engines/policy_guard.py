"""Policy guard engine — event-stream entry point with detect/enforce modes.

Per the redesign doc's Step 3 "Replace inline enforcement with
detect-and-alert + optional response":

  * **Detect mode** (default, collector-only customers): observes
    events, evaluates rules against them, emits findings.  No action
    is taken on the customer's side — TokenDNA presents evidence.

  * **Enforce mode** (SDK customers): the same rule engine, but rule
    matches additionally fire response actions (webhooks to revoke an
    Okta session, block at the WAF, etc).  This mode is only safe when
    the SDK is in the call path — it requires the customer to have
    granted TokenDNA the ability to revoke or block.

The engine here is *detect-mode-only*.  Enforce mode lives in
``platform/tokendna_platform/sdk/`` (per the disposition map) and is
gated to the SDK tier.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, ClassVar

from ..schema import EventCategory, NormalizedEvent
from .base import StreamEngine


class GuardMode(str, Enum):
    DETECT = "detect"
    ENFORCE = "enforce"


@dataclass
class PolicyRule:
    """One named rule evaluated against every inbound event."""
    rule_id: str
    severity: str               # "low" | "medium" | "high" | "critical"
    description: str
    predicate: Callable[[NormalizedEvent], bool]


@dataclass
class PolicyFinding:
    """A rule fired against an event."""
    rule_id: str
    severity: str
    tenant_id: str
    subject: str
    event_id: str
    detected_at: datetime
    description: str = ""


class PolicyGuardEngine(StreamEngine):
    """Detect-mode policy evaluation over the event stream."""

    name: ClassVar[str] = "policy_guard"
    categories: ClassVar[tuple[EventCategory, ...]] = (
        EventCategory.AUTHENTICATION,
        EventCategory.AUTHORIZATION,
        EventCategory.AI_INVOCATION,
        EventCategory.PERMISSION_CHANGE,
        EventCategory.CONFIG_CHANGE,
    )

    def __init__(self, *, mode: GuardMode = GuardMode.DETECT) -> None:
        self._mode = mode
        self._rules: list[PolicyRule] = []
        self._findings: list[PolicyFinding] = []
        self._lock = threading.Lock()

    @property
    def mode(self) -> GuardMode:
        return self._mode

    def add_rule(self, rule: PolicyRule) -> None:
        with self._lock:
            for existing in self._rules:
                if existing.rule_id == rule.rule_id:
                    raise ValueError(f"rule already registered: {rule.rule_id}")
            self._rules.append(rule)

    def handle(self, event: NormalizedEvent) -> None:
        with self._lock:
            rules = list(self._rules)
        for rule in rules:
            try:
                if rule.predicate(event):
                    self._record(rule, event)
            except Exception:  # noqa: BLE001
                # A broken predicate must not break ingestion.
                pass

    def _record(self, rule: PolicyRule, event: NormalizedEvent) -> None:
        finding = PolicyFinding(
            rule_id=rule.rule_id,
            severity=rule.severity,
            tenant_id=event.tenant_id,
            subject=event.subject,
            event_id=event.event_id,
            detected_at=event.timestamp,
            description=rule.description,
        )
        with self._lock:
            self._findings.append(finding)

    def findings(self) -> list[PolicyFinding]:
        with self._lock:
            return list(self._findings)
