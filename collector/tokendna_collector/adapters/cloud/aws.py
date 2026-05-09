"""AWS cloud adapter — CloudTrail audit events + AI service enumeration.

Connects via a customer-provisioned read-only IAM role (cross-account
trust + ExternalId).  Pulls two streams:

  1. **Audit events** from CloudTrail's Event History API — every
     control-plane API call against the customer's account, including
     IAM changes, security-group modifications, and AI-service control
     calls (Bedrock invoke-model, SageMaker create-endpoint, etc.).

  2. **Asset enumeration** from the AI services themselves — a periodic
     "what AI workloads exist in this account" scan that powers the
     shadow-AI discovery view in the dashboard.

Configuration (in ``AdapterConfig.options``):

    role_arn        str   required    IAM role to AssumeRole into
    external_id     str   required    cross-account ExternalId
    regions         list  optional    default ["us-east-1"]
    ai_services     list  optional    default ["bedrock", "sagemaker"]
    initial_lookback_minutes int      default 60

Stdlib-only HTTP — boto3 isn't pulled into the collector image to
keep it tiny.  STS AssumeRole is implemented directly against the
``sts.<region>.amazonaws.com`` endpoint with SigV4 in a follow-up
commit; for Sprint 7-8 the adapter ships scaffolding + the
normalization layer + tests against fixture payloads.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator

from ...config import AdapterConfig
from ...health import HealthState, HealthStatus
from ...schema import EventCategory, EventOutcome, NormalizedEvent
from ..base import BaseAdapter


# CloudTrail eventName prefixes → coarse EventCategory mapping.
_CATEGORY_RULES: tuple[tuple[str, EventCategory], ...] = (
    # AI invocation
    ("InvokeModel",          EventCategory.AI_INVOCATION),
    ("InvokeAgent",          EventCategory.AI_INVOCATION),
    ("CreateInvocation",     EventCategory.AI_INVOCATION),
    ("CreateModelInvocation", EventCategory.AI_INVOCATION),
    # IAM / permission changes
    ("AttachRolePolicy",     EventCategory.PERMISSION_CHANGE),
    ("DetachRolePolicy",     EventCategory.PERMISSION_CHANGE),
    ("PutRolePolicy",        EventCategory.PERMISSION_CHANGE),
    ("CreatePolicy",         EventCategory.PERMISSION_CHANGE),
    ("CreateRole",           EventCategory.PERMISSION_CHANGE),
    ("AddUserToGroup",       EventCategory.PERMISSION_CHANGE),
    # Authentication / federation
    ("AssumeRole",           EventCategory.AUTHENTICATION),
    ("ConsoleLogin",         EventCategory.AUTHENTICATION),
    ("GetSessionToken",      EventCategory.AUTHENTICATION),
    # Config changes
    ("Create",               EventCategory.CONFIG_CHANGE),
    ("Update",               EventCategory.CONFIG_CHANGE),
    ("Modify",               EventCategory.CONFIG_CHANGE),
    ("Put",                  EventCategory.CONFIG_CHANGE),
)


class AWSAdapterError(Exception):
    """Raised for AWS-specific failures the runner should log + retry."""


class AWSCloudTrailAdapter(BaseAdapter):
    """Reads CloudTrail Event History via STS-assumed read-only role."""

    @property
    def source_type(self) -> str:
        return "aws_cloudtrail"

    def __init__(self) -> None:
        self._role_arn: str | None = None
        self._external_id: str | None = None
        self._regions: list[str] = ["us-east-1"]
        self._cursor: dict[str, str] = {}
        self._tenant_id: str = ""
        self._collector_id: str = ""
        self._consecutive_failures = 0
        self._last_successful_poll: datetime | None = None

    # ── BaseAdapter ──────────────────────────────────────────────────────
    async def connect(self, config: AdapterConfig) -> None:
        opts = config.options
        role_arn = str(opts.get("role_arn") or "").strip()
        external_id = str(opts.get("external_id") or "").strip()
        if not role_arn or not external_id:
            raise AWSAdapterError(
                "AWS adapter requires 'role_arn' and 'external_id' in options"
            )
        self._role_arn = role_arn
        self._external_id = external_id
        self._regions = list(opts.get("regions") or ["us-east-1"])
        self._tenant_id = opts.get("tenant_id", "")
        self._collector_id = opts.get("collector_id", "")
        if not self._cursor:
            lookback = int(opts.get("initial_lookback_minutes", 60))
            cursor_iso = (
                datetime.now(timezone.utc) - timedelta(minutes=lookback)
            ).isoformat().replace("+00:00", "Z")
            for region in self._regions:
                self._cursor[region] = cursor_iso

    async def poll(self) -> AsyncIterator[NormalizedEvent]:
        # Fetch + normalize is implemented in a follow-up commit; for
        # Sprint 7-8 we yield nothing.  The contract is correct, the
        # cursor + health-tracking work, and the normalization helper
        # is reachable from tests.
        if False:
            yield  # type: ignore[unreachable]
        self._last_successful_poll = datetime.now(timezone.utc)
        self._consecutive_failures = 0

    async def health_check(self) -> HealthStatus:
        if self._consecutive_failures == 0:
            state = HealthState.HEALTHY
            detail = "aws adapter idle (Sprint 7-8 scaffolding; SigV4 STS in follow-up)"
        elif self._consecutive_failures < 3:
            state = HealthState.DEGRADED
            detail = f"{self._consecutive_failures} consecutive failures"
        else:
            state = HealthState.UNHEALTHY
            detail = f"{self._consecutive_failures} consecutive failures"
        return HealthStatus(
            state=state,
            detail=detail,
            last_successful_poll=self._last_successful_poll,
            consecutive_failures=self._consecutive_failures,
        )

    # ── Normalisation (testable in isolation) ───────────────────────────
    def normalize(self, raw: dict[str, Any]) -> NormalizedEvent | None:
        """Convert one CloudTrail Event record into a NormalizedEvent.

        ``raw`` is the JSON shape produced by CloudTrail:
        ``{"EventId": ..., "EventTime": ..., "EventName": ...,
        "Username": ..., "Resources": [...], ...}``
        """
        event_name = str(raw.get("EventName") or "")
        category = self._categorize(event_name)
        ts_raw = raw.get("EventTime")
        try:
            timestamp = (
                datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
                if isinstance(ts_raw, str)
                else datetime.now(timezone.utc)
            )
        except ValueError:
            timestamp = datetime.now(timezone.utc)

        subject = str(
            raw.get("Username")
            or raw.get("UserIdentity", {}).get("arn")
            or "unknown"
        )

        resources = raw.get("Resources") or []
        first_resource = resources[0] if resources else {}
        resource = str(
            first_resource.get("ResourceName")
            or first_resource.get("ResourceType")
            or raw.get("EventSource")
            or "unknown"
        )

        outcome = (
            EventOutcome.FAILURE
            if raw.get("ErrorCode") or raw.get("ErrorMessage")
            else EventOutcome.SUCCESS
        )

        detail = {
            "event_source": raw.get("EventSource"),
            "aws_region": raw.get("AwsRegion"),
            "source_ip": raw.get("SourceIPAddress"),
            "user_agent": raw.get("UserAgent"),
            "error_code": raw.get("ErrorCode"),
            "session_id": (raw.get("UserIdentity") or {}).get("sessionContext", {}).get("sessionIssuer", {}).get("userName"),
        }
        detail = {k: v for k, v in detail.items() if v is not None}

        event_id = str(raw.get("EventId") or f"aws-{event_name}-{timestamp.isoformat()}")
        return NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            source_type=self.source_type,
            event_category=category,
            subject=subject,
            action=event_name or "unknown",
            resource=resource,
            outcome=outcome,
            detail=detail,
            tenant_id=self._tenant_id,
            collector_id=self._collector_id,
        )

    def _categorize(self, event_name: str) -> EventCategory:
        for prefix, cat in _CATEGORY_RULES:
            if event_name.startswith(prefix):
                return cat
        return EventCategory.UNKNOWN
