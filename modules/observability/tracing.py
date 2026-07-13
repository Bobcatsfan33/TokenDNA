"""
TokenDNA — OpenTelemetry tracing initialization.

This module is intentionally a thin shim: it imports OpenTelemetry only when
``OTEL_EXPORTER_OTLP_ENDPOINT`` is set and the optional packages are
installed. In every other case it is a no-op so dev/test runs do not need
the OTel dependency tree.

Configuration (env vars, all optional):

* ``OTEL_SERVICE_NAME``  — defaults to ``tokendna``.
* ``OTEL_EXPORTER_OTLP_ENDPOINT`` — OTLP/HTTP collector. When unset, tracing
  is disabled entirely.
* ``OTEL_EXPORTER_OTLP_HEADERS`` — comma-separated ``key=value`` pairs.
* ``OTEL_TRACES_SAMPLER_ARG`` — float in ``[0.0, 1.0]`` for parent-based
  trace ID ratio sampling. Defaults to ``0.1``.

Returns ``True`` from :func:`init_tracing` when tracing was wired up,
``False`` otherwise.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger("tokendna.tracing")

_INITIALIZED = False


def is_enabled() -> bool:
    return _INITIALIZED


def init_tracing(app: Any | None = None) -> bool:
    """
    Initialize OpenTelemetry. Returns ``True`` when an exporter was wired up.

    ``app`` is an optional FastAPI app — when provided and the OTel FastAPI
    instrumentation is installed, request spans are auto-emitted.
    """
    global _INITIALIZED

    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    if not endpoint:
        return False

    try:
        from opentelemetry import trace  # type: ignore[import-not-found]
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # type: ignore[import-not-found]
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource  # type: ignore[import-not-found]
        from opentelemetry.sdk.trace import TracerProvider  # type: ignore[import-not-found]
        from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore[import-not-found]
        from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased  # type: ignore[import-not-found]
    except Exception as exc:
        logger.warning("OpenTelemetry not installed; tracing disabled (%s)", exc)
        return False

    sample_rate = _safe_float(os.getenv("OTEL_TRACES_SAMPLER_ARG", "0.1"), default=0.1)
    sample_rate = max(0.0, min(1.0, sample_rate))

    resource = Resource.create(
        {
            "service.name": os.getenv("OTEL_SERVICE_NAME", "tokendna"),
            "service.version": os.getenv("APP_VERSION", "dev"),
            "deployment.environment": os.getenv("ENVIRONMENT", "dev"),
        }
    )
    provider = TracerProvider(
        resource=resource,
        sampler=ParentBased(TraceIdRatioBased(sample_rate)),
    )
    headers = _parse_headers(os.getenv("OTEL_EXPORTER_OTLP_HEADERS", ""))
    exporter = OTLPSpanExporter(endpoint=endpoint, headers=headers or None)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    if app is not None:
        try:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # type: ignore[import-not-found]
            FastAPIInstrumentor().instrument_app(app)
        except Exception as exc:  # pragma: no cover - optional sub-dep
            logger.warning("FastAPI instrumentation unavailable: %s", exc)

    _INITIALIZED = True
    logger.info("OpenTelemetry tracing enabled — endpoint=%s sample_rate=%s", endpoint, sample_rate)
    return True


def _parse_headers(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in raw.split(","):
        if "=" in part:
            key, _, value = part.partition("=")
            key = key.strip()
            value = value.strip()
            if key:
                out[key] = value
    return out


def _safe_float(raw: str, *, default: float) -> float:
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default
