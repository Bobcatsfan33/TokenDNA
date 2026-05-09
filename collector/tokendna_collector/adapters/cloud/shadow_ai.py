"""Shadow-AI discovery — find AI traffic the security team doesn't know about.

Scans DNS + proxy logs for outbound calls to AI provider domains
(OpenAI, Anthropic, Google AI, Cohere, Mistral, Azure OpenAI, Bedrock,
self-hosted LLM gateways, etc.) and emits ``NormalizedEvent`` rows
that the cloud's intelligence engines can compare against the
inventory of *known* AI workloads.

The output is the data behind the dashboard's "shadow AI" finding:
"X workloads in your environment are calling AI providers without
appearing in your asset inventory."

This module does not connect to any source on its own — it ships as
a translator from generic DNS/proxy log entries to NormalizedEvents.
A separate adapter (e.g. one that reads Splunk DNS searches) feeds
records into ``classify()`` and ``normalize_dns_record()``.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from ...schema import EventCategory, EventOutcome, NormalizedEvent


# Domain → vendor classification.  Order matters; the longest match wins.
_AI_DOMAINS: tuple[tuple[str, str], ...] = (
    ("openai.azure.com",        "azure_openai"),
    ("api.openai.com",          "openai"),
    ("api.anthropic.com",       "anthropic"),
    ("generativelanguage.googleapis.com", "google_genai"),
    ("us-central1-aiplatform.googleapis.com", "google_vertex"),
    ("aiplatform.googleapis.com", "google_vertex"),
    ("api.cohere.ai",           "cohere"),
    ("api.cohere.com",          "cohere"),
    ("api.mistral.ai",          "mistral"),
    ("api.together.xyz",        "together"),
    ("api.replicate.com",       "replicate"),
    ("api.perplexity.ai",       "perplexity"),
    ("bedrock-runtime",         "aws_bedrock"),     # bedrock-runtime.<region>.amazonaws.com
    ("bedrock.us-",             "aws_bedrock"),
    ("bedrock.eu-",             "aws_bedrock"),
    ("runtime.sagemaker",       "aws_sagemaker"),
)


def classify_ai_domain(domain: str) -> str | None:
    """Return the vendor key for ``domain`` or None if not an AI provider."""
    domain = (domain or "").lower().strip(".")
    for needle, vendor in _AI_DOMAINS:
        if needle in domain:
            return vendor
    return None


def normalize_dns_record(
    record: dict,
    *,
    tenant_id: str,
    collector_id: str,
    source_type: str = "shadow_ai",
) -> NormalizedEvent | None:
    """Translate a DNS-log record into a NormalizedEvent if it's an AI call.

    Expected ``record`` shape (any one of these is enough):

        {"timestamp": ISO-str, "client_ip": str, "queried_domain": str}
        {"@timestamp": ..., "src_ip": ..., "query": ...}
        {"time": ..., "src": ..., "host": ...}
    """
    domain = (
        record.get("queried_domain")
        or record.get("query")
        or record.get("host")
        or record.get("dns_query")
        or ""
    )
    vendor = classify_ai_domain(domain)
    if vendor is None:
        return None

    ts_raw = (
        record.get("timestamp")
        or record.get("@timestamp")
        or record.get("time")
    )
    try:
        timestamp = (
            datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
            if isinstance(ts_raw, str)
            else datetime.now(timezone.utc)
        )
    except ValueError:
        timestamp = datetime.now(timezone.utc)

    subject = str(
        record.get("client_ip")
        or record.get("src_ip")
        or record.get("src")
        or "unknown-host"
    )

    return NormalizedEvent(
        event_id=f"shadow-{vendor}-{subject}-{int(timestamp.timestamp())}",
        timestamp=timestamp,
        source_type=source_type,
        event_category=EventCategory.AI_INVOCATION,
        subject=subject,
        action=f"dns_query:{vendor}",
        resource=domain,
        outcome=EventOutcome.SUCCESS,
        detail={"vendor": vendor, "domain": domain},
        tenant_id=tenant_id,
        collector_id=collector_id,
    )


def normalize_dns_batch(
    records: Iterable[dict],
    *,
    tenant_id: str,
    collector_id: str,
    source_type: str = "shadow_ai",
) -> list[NormalizedEvent]:
    """Convenience: normalize many records and drop the non-AI ones."""
    out: list[NormalizedEvent] = []
    for record in records:
        ev = normalize_dns_record(
            record,
            tenant_id=tenant_id,
            collector_id=collector_id,
            source_type=source_type,
        )
        if ev is not None:
            out.append(ev)
    return out
