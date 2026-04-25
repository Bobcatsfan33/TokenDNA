"""TokenDNA observability — metrics, tracing, error reporting.

Three sub-modules:

* :mod:`metrics` — Prometheus counters and histograms. Falls back to a
  stdlib-only no-op when ``prometheus_client`` is not installed.
* :mod:`tracing` — OpenTelemetry initialization. No-op when ``opentelemetry``
  is not installed.
* :mod:`error_reporting` — Sentry SDK initialization. No-op when
  ``sentry-sdk`` is not installed.

The fall-back pattern keeps the SDK and tests dependency-free while still
exposing the production endpoints (``/metrics``, ``/healthz``, ``/readyz``).
"""

from .metrics import (
    HTTP_REQUESTS,
    HTTP_LATENCY,
    UIS_EVENTS_RECEIVED,
    POLICY_DECISIONS,
    SECRET_GATE_FAILURES,
    record_http_request,
    record_uis_event,
    record_policy_decision,
    render_metrics,
    is_real_prometheus,
)

__all__ = [
    "HTTP_REQUESTS",
    "HTTP_LATENCY",
    "UIS_EVENTS_RECEIVED",
    "POLICY_DECISIONS",
    "SECRET_GATE_FAILURES",
    "record_http_request",
    "record_uis_event",
    "record_policy_decision",
    "render_metrics",
    "is_real_prometheus",
]
