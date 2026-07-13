from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.observability import metrics
from modules.observability.error_reporting import _before_send
from modules.observability.tracing import init_tracing


def test_metrics_module_exposes_helpers():
    metrics.record_http_request("GET", "/healthz", 200, 0.012)
    metrics.record_uis_event("oidc", "allow")
    metrics.record_policy_decision("policy_guard", "ALLOW")
    body, content_type = metrics.render_metrics()
    assert isinstance(body, bytes)
    assert isinstance(content_type, str)


def test_metrics_no_op_when_prometheus_missing():
    body, content_type = metrics.render_metrics()
    assert isinstance(body, bytes)
    assert isinstance(content_type, str)


def test_init_tracing_disabled_without_endpoint(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    assert init_tracing(app=None) is False


def test_before_send_redacts_known_headers():
    event = {
        "request": {
            "headers": {
                "Authorization": "Bearer abc.def.ghi",
                "X-API-Key": "secret",
                "User-Agent": "tokendna-tests",
            }
        },
        "contexts": {
            "env": {
                "TOKENDNA_DELEGATION_SECRET": "supersecret",
                "PATH": "/usr/bin",
            }
        },
        "message": "Bearer leaked-token-1234567890",
    }
    out = _before_send(event, {})
    assert out is not None
    assert out["request"]["headers"]["Authorization"] == "[redacted]"
    assert out["request"]["headers"]["X-API-Key"] == "[redacted]"
    assert out["request"]["headers"]["User-Agent"] == "tokendna-tests"
    assert out["contexts"]["env"]["TOKENDNA_DELEGATION_SECRET"] == "[redacted]"
    assert out["contexts"]["env"]["PATH"] == "/usr/bin"
    assert "Bearer [redacted]" in out["message"]
    assert "leaked-token" not in out["message"]


@pytest.fixture
def api_client():
    """TestClient without the ``with`` context manager — we deliberately do
    not invoke the FastAPI lifespan because earlier reload-based tests can
    leave module-level _DB_PATH constants pointing at torn-down tmpdirs.
    The routes under test (``/healthz``, ``/readyz``, ``/metrics``) do not
    depend on startup wiring."""
    from fastapi.testclient import TestClient
    import api as api_module

    return TestClient(api_module.app, raise_server_exceptions=False)


def test_healthz_endpoint_returns_ok(api_client):
    r = api_client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_metrics_endpoint_serves_prometheus_or_stub(api_client):
    r = api_client.get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers.get("content-type", "")


def test_readyz_returns_status_field(api_client):
    r = api_client.get("/readyz")
    assert r.status_code in (200, 503)
    body = r.json()
    assert "status" in body
    assert body["status"] in ("ready", "degraded")
