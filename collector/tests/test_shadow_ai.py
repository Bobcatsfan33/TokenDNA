"""Tests for the shadow-AI DNS classifier."""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from tokendna_collector.adapters.cloud.shadow_ai import (
    classify_ai_domain,
    normalize_dns_batch,
    normalize_dns_record,
)
from tokendna_collector.schema import EventCategory


def test_classify_known_vendors() -> None:
    assert classify_ai_domain("api.openai.com") == "openai"
    assert classify_ai_domain("API.ANTHROPIC.com.") == "anthropic"
    assert classify_ai_domain("api.cohere.com") == "cohere"
    assert classify_ai_domain("bedrock-runtime.us-east-1.amazonaws.com") == "aws_bedrock"
    assert classify_ai_domain("aiplatform.googleapis.com") == "google_vertex"


def test_classify_unknown_domain_returns_none() -> None:
    assert classify_ai_domain("www.example.com") is None
    assert classify_ai_domain("") is None


def test_normalize_dns_record_creates_event_for_ai_provider() -> None:
    record = {
        "timestamp":      "2026-05-08T12:00:00Z",
        "client_ip":      "10.0.0.5",
        "queried_domain": "api.openai.com",
    }
    ev = normalize_dns_record(record, tenant_id="t1", collector_id="c1")
    assert ev is not None
    assert ev.event_category == EventCategory.AI_INVOCATION
    assert ev.action == "dns_query:openai"
    assert ev.subject == "10.0.0.5"
    assert ev.resource == "api.openai.com"
    assert ev.detail["vendor"] == "openai"


def test_normalize_dns_record_returns_none_for_non_ai_domain() -> None:
    record = {"timestamp": "x", "client_ip": "10.0.0.5", "queried_domain": "github.com"}
    assert normalize_dns_record(record, tenant_id="t1", collector_id="c1") is None


def test_normalize_dns_batch_filters_non_ai() -> None:
    batch = [
        {"timestamp": "2026-05-08T12:00:00Z", "client_ip": "10.0.0.5",
         "queried_domain": "api.openai.com"},
        {"timestamp": "2026-05-08T12:00:01Z", "client_ip": "10.0.0.5",
         "queried_domain": "github.com"},
        {"timestamp": "2026-05-08T12:00:02Z", "client_ip": "10.0.0.6",
         "queried_domain": "api.anthropic.com"},
    ]
    events = normalize_dns_batch(batch, tenant_id="t1", collector_id="c1")
    assert len(events) == 2
    assert {ev.detail["vendor"] for ev in events} == {"openai", "anthropic"}


def test_normalize_dns_record_accepts_alternate_field_names() -> None:
    """Different SIEMs use different field names — adapter is tolerant."""
    record = {
        "@timestamp": "2026-05-08T12:00:00Z",
        "src_ip": "10.0.0.5",
        "query": "api.openai.com",
    }
    ev = normalize_dns_record(record, tenant_id="t1", collector_id="c1")
    assert ev is not None
    assert ev.subject == "10.0.0.5"
