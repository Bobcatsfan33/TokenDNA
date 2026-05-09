"""Tests for the AWS CloudTrail adapter."""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio

import pytest

from tokendna_collector.adapters.cloud.aws import (
    AWSAdapterError,
    AWSCloudTrailAdapter,
)
from tokendna_collector.config import AdapterConfig
from tokendna_collector.health import HealthState
from tokendna_collector.schema import EventCategory, EventOutcome


def _config(**overrides) -> AdapterConfig:
    opts = {
        "role_arn":     "arn:aws:iam::123456789012:role/TokenDNARead",
        "external_id":  "abc123",
        "regions":      ["us-east-1"],
        "tenant_id":    "t1",
        "collector_id": "c1",
        **overrides,
    }
    return AdapterConfig(source_type="aws_cloudtrail", name="aws-test", options=opts)


def test_connect_requires_role_and_external_id() -> None:
    a = AWSCloudTrailAdapter()
    with pytest.raises(AWSAdapterError):
        asyncio.run(a.connect(AdapterConfig(
            source_type="aws_cloudtrail", name="x", options={}
        )))


def test_normalize_invoke_model_event() -> None:
    a = AWSCloudTrailAdapter()
    asyncio.run(a.connect(_config()))
    raw = {
        "EventId":   "abc-1",
        "EventTime": "2026-05-08T12:00:00Z",
        "EventName": "InvokeModel",
        "EventSource": "bedrock.amazonaws.com",
        "AwsRegion": "us-east-1",
        "Username": "ai-app-role",
        "Resources": [{"ResourceName": "anthropic.claude-3-sonnet"}],
        "SourceIPAddress": "203.0.113.5",
    }
    ev = a.normalize(raw)
    assert ev is not None
    assert ev.source_type == "aws_cloudtrail"
    assert ev.event_category == EventCategory.AI_INVOCATION
    assert ev.subject == "ai-app-role"
    assert ev.resource == "anthropic.claude-3-sonnet"
    assert ev.outcome == EventOutcome.SUCCESS
    assert ev.detail["event_source"] == "bedrock.amazonaws.com"


def test_normalize_iam_change_event() -> None:
    a = AWSCloudTrailAdapter()
    asyncio.run(a.connect(_config()))
    raw = {
        "EventId":   "abc-2",
        "EventTime": "2026-05-08T12:00:00Z",
        "EventName": "AttachRolePolicy",
        "Username":  "admin",
        "Resources": [{"ResourceName": "AdminAccess"}],
    }
    ev = a.normalize(raw)
    assert ev is not None
    assert ev.event_category == EventCategory.PERMISSION_CHANGE


def test_normalize_marks_failure_when_error_code_present() -> None:
    a = AWSCloudTrailAdapter()
    asyncio.run(a.connect(_config()))
    raw = {
        "EventId":   "abc-3",
        "EventTime": "2026-05-08T12:00:00Z",
        "EventName": "InvokeModel",
        "Username":  "ai-app-role",
        "ErrorCode": "AccessDeniedException",
        "ErrorMessage": "no permission",
    }
    ev = a.normalize(raw)
    assert ev is not None
    assert ev.outcome == EventOutcome.FAILURE
    assert ev.detail["error_code"] == "AccessDeniedException"


def test_unknown_event_falls_through_to_unknown_category() -> None:
    a = AWSCloudTrailAdapter()
    asyncio.run(a.connect(_config()))
    raw = {
        "EventId":   "abc-4",
        "EventTime": "2026-05-08T12:00:00Z",
        "EventName": "TotallyMadeUpEventName",
        "Username":  "alice",
    }
    ev = a.normalize(raw)
    assert ev is not None
    assert ev.event_category == EventCategory.UNKNOWN


def test_health_starts_healthy_after_connect() -> None:
    a = AWSCloudTrailAdapter()
    asyncio.run(a.connect(_config()))
    h = asyncio.run(a.health_check())
    assert h.state == HealthState.HEALTHY
