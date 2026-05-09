"""Tests for the Azure Activity Log adapter."""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio

import pytest

from tokendna_collector.adapters.cloud.azure import (
    AzureActivityLogAdapter,
    AzureAdapterError,
)
from tokendna_collector.config import AdapterConfig
from tokendna_collector.schema import EventCategory, EventOutcome


def _config(**overrides) -> AdapterConfig:
    opts = {
        "tenant":           "11111111-2222-3333-4444-555555555555",
        "client_id":        "aaaa-bbbb-cccc-dddd",
        "client_secret":    "very-secret",
        "subscription_ids": ["00000000-0000-0000-0000-000000000000"],
        "tenant_id":        "t1",
        "collector_id":     "c1",
        **overrides,
    }
    return AdapterConfig(source_type="azure_activity_log", name="azure-test", options=opts)


def test_connect_requires_full_credential_set() -> None:
    a = AzureActivityLogAdapter()
    with pytest.raises(AzureAdapterError):
        asyncio.run(a.connect(AdapterConfig(
            source_type="azure_activity_log", name="x", options={"tenant": "t"}
        )))


def test_normalize_inference_event() -> None:
    a = AzureActivityLogAdapter()
    asyncio.run(a.connect(_config()))
    raw = {
        "operationName":     {"value": "Microsoft.CognitiveServices/accounts/inference"},
        "eventTimestamp":    "2026-05-08T12:00:00Z",
        "caller":            "alice@example.com",
        "resourceId":        "/subscriptions/x/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/openai-prod",
        "status":            {"value": "Succeeded"},
        "subscriptionId":    "00000000-0000-0000-0000-000000000000",
        "eventDataId":       "evt-abc",
    }
    ev = a.normalize(raw)
    assert ev is not None
    assert ev.event_category == EventCategory.AI_INVOCATION
    assert ev.subject == "alice@example.com"
    assert ev.outcome == EventOutcome.SUCCESS


def test_normalize_role_assignment_event() -> None:
    a = AzureActivityLogAdapter()
    asyncio.run(a.connect(_config()))
    raw = {
        "operationName":  {"value": "Microsoft.Authorization/roleAssignments/write"},
        "eventTimestamp": "2026-05-08T12:00:00Z",
        "caller":         "admin@example.com",
        "resourceId":     "/subscriptions/x",
        "status":         {"value": "Succeeded"},
        "eventDataId":    "evt-def",
    }
    ev = a.normalize(raw)
    assert ev is not None
    assert ev.event_category == EventCategory.PERMISSION_CHANGE
