"""Azure cloud adapter — Activity Log + Azure OpenAI / ML enumeration.

Mirrors the shape of the AWS adapter.  Reads Azure Activity Log via
the Microsoft.Insights REST API, pulls Azure OpenAI usage events from
the Cognitive Services management plane, and enumerates ML workspaces
in scope.

Configuration (in ``AdapterConfig.options``):

    tenant            str   required    Azure AD tenant id
    client_id         str   required    service principal app id
    client_secret     str   required    service principal secret
    subscription_ids  list  required    subscriptions to monitor
    initial_lookback_minutes int        default 60

Stdlib-only HTTP, same posture as the AWS adapter.  OAuth token fetch
+ Activity Log query land in a follow-up commit; for Sprint 7-8 the
adapter ships the contract, the normalization layer, and a test
fixture.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, ClassVar

from ...config import AdapterConfig
from ...health import HealthState, HealthStatus
from ...schema import EventCategory, EventOutcome, NormalizedEvent
from ..base import BaseAdapter


_CATEGORY_RULES: tuple[tuple[str, EventCategory], ...] = (
    ("Microsoft.CognitiveServices/accounts/listKeys",         EventCategory.PERMISSION_CHANGE),
    ("Microsoft.CognitiveServices/accounts/inference",        EventCategory.AI_INVOCATION),
    ("Microsoft.MachineLearningServices/workspaces",          EventCategory.CONFIG_CHANGE),
    ("Microsoft.Authorization/roleAssignments",               EventCategory.PERMISSION_CHANGE),
    ("Microsoft.Network/networkSecurityGroups",               EventCategory.NETWORK),
    ("Microsoft.AAD",                                          EventCategory.AUTHENTICATION),
)


class AzureAdapterError(Exception):
    """Raised for Azure-specific failures."""


class AzureActivityLogAdapter(BaseAdapter):
    """Reads Azure Activity Log + AI service control plane."""

    @property
    def source_type(self) -> str:
        return "azure_activity_log"

    def __init__(self) -> None:
        self._tenant: str | None = None
        self._client_id: str | None = None
        self._client_secret: str | None = None
        self._subscription_ids: list[str] = []
        self._cursor: dict[str, str] = {}
        self._tenant_id: str = ""
        self._collector_id: str = ""
        self._consecutive_failures = 0
        self._last_successful_poll: datetime | None = None

    # ── BaseAdapter ──────────────────────────────────────────────────────
    async def connect(self, config: AdapterConfig) -> None:
        opts = config.options
        self._tenant = str(opts.get("tenant") or "").strip()
        self._client_id = str(opts.get("client_id") or "").strip()
        self._client_secret = str(opts.get("client_secret") or "").strip()
        sub_ids = list(opts.get("subscription_ids") or [])
        if not (self._tenant and self._client_id and self._client_secret and sub_ids):
            raise AzureAdapterError(
                "Azure adapter requires 'tenant', 'client_id', 'client_secret', "
                "and at least one entry in 'subscription_ids'"
            )
        self._subscription_ids = sub_ids
        self._tenant_id = opts.get("tenant_id", "")
        self._collector_id = opts.get("collector_id", "")
        if not self._cursor:
            lookback = int(opts.get("initial_lookback_minutes", 60))
            cursor_iso = (
                datetime.now(timezone.utc) - timedelta(minutes=lookback)
            ).isoformat().replace("+00:00", "Z")
            for sub_id in self._subscription_ids:
                self._cursor[sub_id] = cursor_iso

    async def poll(self) -> AsyncIterator[NormalizedEvent]:
        if False:
            yield  # type: ignore[unreachable]
        self._last_successful_poll = datetime.now(timezone.utc)
        self._consecutive_failures = 0

    async def health_check(self) -> HealthStatus:
        state = HealthState.HEALTHY
        detail = "azure adapter idle (Sprint 7-8 scaffolding; OAuth + Activity Log query in follow-up)"
        if self._consecutive_failures >= 3:
            state = HealthState.UNHEALTHY
            detail = f"{self._consecutive_failures} consecutive failures"
        elif self._consecutive_failures > 0:
            state = HealthState.DEGRADED
            detail = f"{self._consecutive_failures} consecutive failures"
        return HealthStatus(
            state=state,
            detail=detail,
            last_successful_poll=self._last_successful_poll,
            consecutive_failures=self._consecutive_failures,
        )

    # ── Normalisation ────────────────────────────────────────────────────
    def normalize(self, raw: dict[str, Any]) -> NormalizedEvent | None:
        op_name = str(raw.get("operationName", {}).get("value")
                      or raw.get("operationName") or "")
        category = self._categorize(op_name)

        ts_raw = raw.get("eventTimestamp") or raw.get("submissionTimestamp")
        try:
            timestamp = (
                datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
                if isinstance(ts_raw, str)
                else datetime.now(timezone.utc)
            )
        except ValueError:
            timestamp = datetime.now(timezone.utc)

        caller = (raw.get("caller")
                  or raw.get("identity", {}).get("claims", {}).get("upn")
                  or "unknown")
        resource = str(raw.get("resourceId") or raw.get("resource") or op_name)
        status = str(raw.get("status", {}).get("value")
                     or raw.get("status") or "").lower()
        if status in {"succeeded", "success"}:
            outcome = EventOutcome.SUCCESS
        elif status in {"failed", "failure"}:
            outcome = EventOutcome.FAILURE
        else:
            outcome = EventOutcome.UNKNOWN

        detail = {
            "subscription_id": raw.get("subscriptionId"),
            "resource_group": raw.get("resourceGroupName"),
            "category": (raw.get("category", {}) or {}).get("value")
                if isinstance(raw.get("category"), dict) else raw.get("category"),
            "level": raw.get("level"),
            "correlation_id": raw.get("correlationId"),
        }
        detail = {k: v for k, v in detail.items() if v is not None}

        return NormalizedEvent(
            event_id=str(raw.get("eventDataId") or raw.get("operationId") or op_name),
            timestamp=timestamp,
            source_type=self.source_type,
            event_category=category,
            subject=str(caller),
            action=op_name or "unknown",
            resource=resource,
            outcome=outcome,
            detail=detail,
            tenant_id=self._tenant_id,
            collector_id=self._collector_id,
        )

    def _categorize(self, op_name: str) -> EventCategory:
        for prefix, cat in _CATEGORY_RULES:
            if op_name.startswith(prefix):
                return cat
        return EventCategory.UNKNOWN
