"""
TokenDNA — Prometheus metrics with stdlib fallback.

When ``prometheus_client`` is installed the real Counter/Histogram are used
and ``/metrics`` returns the standard exposition format. When it is not
installed (notably in tests and the SDK package), the module exposes
counter-shaped no-ops so call sites never need a guard.

Metric naming follows OpenMetrics conventions:

* ``tokendna_http_requests_total`` — HTTP request counts, labeled
  ``method``, ``route``, ``status_class`` (``2xx``/``3xx``/``4xx``/``5xx``).
* ``tokendna_http_request_duration_seconds`` — request latency histogram,
  same labels minus ``status_class``.
* ``tokendna_uis_events_total`` — UIS events ingested, labeled ``protocol``,
  ``decision``.
* ``tokendna_policy_decisions_total`` — policy enforcement outcomes,
  labeled ``module``, ``decision``.
* ``tokendna_secret_gate_failures_total`` — increments whenever the secret
  gate fails to validate a production secret. Operationally critical:
  this should never increment in steady state.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from time import perf_counter
from typing import Iterator

logger = logging.getLogger("tokendna.metrics")


try:  # pragma: no cover - import shape exercised by tests via monkeypatch
    from prometheus_client import (  # type: ignore[import-not-found]
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        Counter,
        Histogram,
        generate_latest,
    )

    _PROMETHEUS_AVAILABLE = True
    _REGISTRY = CollectorRegistry()

except Exception:  # pragma: no cover - exercised when dep missing
    _PROMETHEUS_AVAILABLE = False
    _REGISTRY = None  # type: ignore[assignment]
    CONTENT_TYPE_LATEST = "text/plain; charset=utf-8"

    class _Stub:
        """Counter/Histogram-shaped no-op used when prometheus_client is missing."""

        def __init__(self, *_a, **_kw) -> None:
            self._count = 0

        def labels(self, **_kw) -> "_Stub":
            return self

        def inc(self, amount: float = 1.0) -> None:
            self._count += int(amount)

        def observe(self, _value: float) -> None:
            self._count += 1

        @contextmanager
        def time(self) -> Iterator[None]:
            yield

    def generate_latest(_registry=None) -> bytes:  # type: ignore[no-redef]
        return b"# prometheus_client not installed\n"

    Counter = _Stub  # type: ignore[assignment, misc]
    Histogram = _Stub  # type: ignore[assignment, misc]


def is_real_prometheus() -> bool:
    """True when the real prometheus_client is providing the metrics."""
    return _PROMETHEUS_AVAILABLE


# ── Metric definitions ────────────────────────────────────────────────────────

_kw = {"registry": _REGISTRY} if _PROMETHEUS_AVAILABLE else {}

HTTP_REQUESTS = Counter(
    "tokendna_http_requests_total",
    "Count of HTTP requests served, by method, route, and status class.",
    ["method", "route", "status_class"],
    **_kw,
)

HTTP_LATENCY = Histogram(
    "tokendna_http_request_duration_seconds",
    "HTTP request latency, by method and route.",
    ["method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    **_kw,
)

UIS_EVENTS_RECEIVED = Counter(
    "tokendna_uis_events_total",
    "UIS events ingested, by protocol and decision.",
    ["protocol", "decision"],
    **_kw,
)

POLICY_DECISIONS = Counter(
    "tokendna_policy_decisions_total",
    "Policy decisions emitted, by module and decision.",
    ["module", "decision"],
    **_kw,
)

SECRET_GATE_FAILURES = Counter(
    "tokendna_secret_gate_failures_total",
    "Secret gate validation failures observed at startup or rotation.",
    ["env_var"],
    **_kw,
)


# ── Convenience helpers ───────────────────────────────────────────────────────


def _status_class(status_code: int) -> str:
    if status_code < 200:
        return "1xx"
    if status_code < 300:
        return "2xx"
    if status_code < 400:
        return "3xx"
    if status_code < 500:
        return "4xx"
    return "5xx"


def record_http_request(method: str, route: str, status_code: int, duration_seconds: float) -> None:
    HTTP_REQUESTS.labels(
        method=method.upper(),
        route=route,
        status_class=_status_class(status_code),
    ).inc()
    HTTP_LATENCY.labels(method=method.upper(), route=route).observe(duration_seconds)


def record_uis_event(protocol: str, decision: str) -> None:
    UIS_EVENTS_RECEIVED.labels(
        protocol=protocol or "unknown",
        decision=decision or "unknown",
    ).inc()


def record_policy_decision(module: str, decision: str) -> None:
    POLICY_DECISIONS.labels(module=module, decision=decision).inc()


def render_metrics() -> tuple[bytes, str]:
    """Return ``(body, content_type)`` for the ``/metrics`` endpoint."""
    body = generate_latest(_REGISTRY) if _PROMETHEUS_AVAILABLE else generate_latest()
    return body, CONTENT_TYPE_LATEST


@contextmanager
def time_block(method: str, route: str) -> Iterator[dict[str, int]]:
    """Context manager that records the wrapped request as one metric sample.

    Usage::

        with time_block("GET", "/api/stats") as ctx:
            ...
            ctx["status"] = 200
    """
    start = perf_counter()
    ctx: dict[str, int] = {"status": 200}
    try:
        yield ctx
    except Exception:
        ctx["status"] = 500
        raise
    finally:
        record_http_request(method, route, int(ctx.get("status", 200)), perf_counter() - start)
