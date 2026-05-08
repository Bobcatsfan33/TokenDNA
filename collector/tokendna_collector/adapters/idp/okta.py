"""Okta System Log adapter.

Reads events from Okta's System Log API
(https://developer.okta.com/docs/reference/api/system-log/) and emits
``NormalizedEvent`` instances.

This is the P0 adapter — Okta is the most common IDP across the customer
base we're targeting, and having a working IDP adapter unlocks every
identity-axis intelligence engine on the cloud side.

Configuration (in ``AdapterConfig.options``):

    domain          str   required  e.g. "example.okta.com"
    api_token       str   required  Okta API token (read-only is fine)
    initial_lookback_minutes int    optional, default 60
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from __future__ import annotations

import asyncio
import json
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator

from ...config import AdapterConfig
from ...health import HealthState, HealthStatus
from ...schema import EventCategory, EventOutcome, NormalizedEvent
from ..base import BaseAdapter


# Okta event-type prefixes → coarse EventCategory mapping.  A miss falls
# through to UNKNOWN, which the cloud router can re-classify with full
# semantic awareness.
_CATEGORY_PREFIXES: tuple[tuple[str, EventCategory], ...] = (
    ("user.session.",       EventCategory.AUTHENTICATION),
    ("user.authentication.", EventCategory.AUTHENTICATION),
    ("user.mfa.",           EventCategory.AUTHENTICATION),
    ("user.lifecycle.",     EventCategory.PERMISSION_CHANGE),
    ("user.account.",       EventCategory.PERMISSION_CHANGE),
    ("group.user_membership.", EventCategory.PERMISSION_CHANGE),
    ("application.user_membership.", EventCategory.AUTHORIZATION),
    ("application.lifecycle.",  EventCategory.CONFIG_CHANGE),
    ("policy.",             EventCategory.CONFIG_CHANGE),
    ("system.",             EventCategory.CONFIG_CHANGE),
)

_OUTCOME_MAP = {
    "SUCCESS": EventOutcome.SUCCESS,
    "ALLOW":   EventOutcome.SUCCESS,
    "FAILURE": EventOutcome.FAILURE,
    "DENY":    EventOutcome.DENIED,
}


class OktaAdapterError(Exception):
    """Raised for Okta-specific failures the runner should log + retry."""


class OktaSystemLogAdapter(BaseAdapter):
    """Pulls events from /api/v1/logs since a high-water cursor.

    The cursor is the ISO timestamp of the last event seen, exclusive
    (``since`` parameter).  Okta returns events in ascending order so we
    can advance the cursor monotonically.
    """

    @property
    def source_type(self) -> str:
        return "okta"

    def __init__(self) -> None:
        self._domain: str | None = None
        self._token: str | None = None
        self._cursor: str | None = None
        self._tenant_id: str = ""
        self._collector_id: str = ""
        self._consecutive_failures = 0
        self._last_successful_poll: datetime | None = None

    # ── BaseAdapter ──────────────────────────────────────────────────────
    async def connect(self, config: AdapterConfig) -> None:
        opts = config.options
        domain = str(opts.get("domain") or "").strip()
        token = str(opts.get("api_token") or "").strip()
        if not domain or not token:
            raise OktaAdapterError(
                "Okta adapter requires 'domain' and 'api_token' in options"
            )
        self._domain = domain
        self._token = token
        self._tenant_id = opts.get("tenant_id", "")
        self._collector_id = opts.get("collector_id", "")
        if self._cursor is None:
            lookback = int(opts.get("initial_lookback_minutes", 60))
            self._cursor = (
                datetime.now(timezone.utc) - timedelta(minutes=lookback)
            ).isoformat().replace("+00:00", "Z")

    async def poll(self) -> AsyncIterator[NormalizedEvent]:
        if not self._domain or not self._token:
            raise OktaAdapterError("connect() must be called before poll()")

        try:
            raw_events = await asyncio.to_thread(self._fetch_events, self._cursor)
        except Exception as exc:
            self._consecutive_failures += 1
            raise OktaAdapterError(f"okta_fetch_failed: {exc}") from exc

        last_seen: str | None = None
        for raw in raw_events:
            ev = self._normalize(raw)
            if ev is not None:
                yield ev
            ts = raw.get("published") or raw.get("eventTime")
            if isinstance(ts, str):
                last_seen = ts
        if last_seen:
            self._cursor = last_seen
        self._consecutive_failures = 0
        self._last_successful_poll = datetime.now(timezone.utc)

    async def health_check(self) -> HealthStatus:
        if self._consecutive_failures == 0:
            state = HealthState.HEALTHY
            detail = "okta adapter polling normally"
        elif self._consecutive_failures < 3:
            state = HealthState.DEGRADED
            detail = f"okta adapter has {self._consecutive_failures} consecutive failures"
        else:
            state = HealthState.UNHEALTHY
            detail = f"okta adapter has {self._consecutive_failures} consecutive failures"
        return HealthStatus(
            state=state,
            detail=detail,
            last_successful_poll=self._last_successful_poll,
            consecutive_failures=self._consecutive_failures,
        )

    # ── Internal HTTP + normalization ───────────────────────────────────
    def _fetch_events(self, cursor: str | None) -> list[dict[str, Any]]:
        """Synchronous HTTP call (run via asyncio.to_thread).

        Stdlib-only so the collector image stays tiny.  Switch to httpx
        in a follow-up if connection pooling becomes the bottleneck.
        """
        params = {"limit": "1000"}
        if cursor:
            params["since"] = cursor
        url = (
            f"https://{self._domain}/api/v1/logs?"
            + urllib.parse.urlencode(params)
        )
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"SSWS {self._token}",
                "Accept": "application/json",
                "User-Agent": "tokendna-collector/0.0.1",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            payload = json.loads(r.read().decode("utf-8"))
        if not isinstance(payload, list):
            raise OktaAdapterError(f"unexpected okta response shape: {type(payload).__name__}")
        return payload

    def _normalize(self, raw: dict[str, Any]) -> NormalizedEvent | None:
        event_id = str(raw.get("uuid") or uuid.uuid4().hex)
        ts_str = raw.get("published") or raw.get("eventTime")
        try:
            timestamp = (
                datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if isinstance(ts_str, str)
                else datetime.now(timezone.utc)
            )
        except ValueError:
            timestamp = datetime.now(timezone.utc)

        event_type = str(raw.get("eventType") or "")
        category = EventCategory.UNKNOWN
        for prefix, cat in _CATEGORY_PREFIXES:
            if event_type.startswith(prefix):
                category = cat
                break

        actor = raw.get("actor") or {}
        subject = (
            actor.get("alternateId")
            or actor.get("displayName")
            or actor.get("id")
            or "unknown"
        )

        target = (raw.get("target") or [{}])[0] if raw.get("target") else {}
        resource = (
            target.get("alternateId")
            or target.get("displayName")
            or target.get("id")
            or event_type
        )

        outcome_result = ((raw.get("outcome") or {}).get("result") or "").upper()
        outcome = _OUTCOME_MAP.get(outcome_result, EventOutcome.UNKNOWN)

        # Trim detail to a small, predictable subset — full raw events
        # can exceed 64 KB and inflate bandwidth.  Cloud can re-fetch on
        # demand if it needs the full payload.
        detail = {
            "event_type": event_type,
            "client_ip": (raw.get("client") or {}).get("ipAddress"),
            "user_agent": (raw.get("client") or {}).get("userAgent", {}).get("rawUserAgent"),
            "auth_provider": (raw.get("authenticationContext") or {}).get("externalSessionId"),
            "outcome_reason": (raw.get("outcome") or {}).get("reason"),
        }
        # Drop None values to keep wire payload lean.
        detail = {k: v for k, v in detail.items() if v is not None}

        return NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            source_type=self.source_type,
            event_category=category,
            subject=str(subject),
            action=event_type or "unknown",
            resource=str(resource),
            outcome=outcome,
            detail=detail,
            tenant_id=self._tenant_id,
            collector_id=self._collector_id,
        )
