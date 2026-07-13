from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from stress_harness import _percentile, evaluate_gate, run_stress  # type: ignore


def test_percentile_basic():
    assert _percentile([], 95) == 0.0
    assert _percentile([1.0], 95) == 1.0
    # 100 evenly spaced values — nearest-rank percentile selection,
    # so p50 lands at index 50 (the 51st value) and p95 at index 94.
    values = [float(i) for i in range(1, 101)]
    p50 = _percentile(values, 50)
    p95 = _percentile(values, 95)
    assert 50.0 <= p50 <= 51.0
    assert 94.0 <= p95 <= 96.0


def test_evaluate_gate_returns_violations():
    report = {
        "overall": {"error_pct": 2.5},
        "endpoints": {
            "/healthz": {"p95_ms": 80.0},
            "/api/x":   {"p95_ms": 30.0},
        },
    }
    gate = {"max_error_pct": 1.0, "max_p95_ms": {"/healthz": 50, "/api/x": 100}}
    violations = evaluate_gate(report, gate)
    assert any("error_pct" in v for v in violations)
    assert any("/healthz p95" in v for v in violations)
    assert not any("/api/x" in v for v in violations)


def test_evaluate_gate_clean():
    report = {
        "overall": {"error_pct": 0.1},
        "endpoints": {"/healthz": {"p95_ms": 30.0}},
    }
    gate = {"max_error_pct": 1.0, "max_p95_ms": {"/healthz": 50}}
    assert evaluate_gate(report, gate) == []


# ── Live HTTP smoke test ──────────────────────────────────────────────────────


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silence
        pass

    def do_GET(self):  # noqa: N802
        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        elif self.path == "/error":
            self.send_response(500)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    yield f"http://{host}:{port}"
    server.shutdown()
    server.server_close()


def test_run_stress_against_local_server(local_server):
    profile = [
        {"endpoint": "/healthz", "weight": 4, "method": "GET"},
        {"endpoint": "/error",   "weight": 1, "method": "GET"},
    ]
    report = run_stress(
        base_url=local_server,
        profile=profile,
        duration_seconds=0.5,
        concurrency=4,
        timeout=2.0,
    )
    assert report["overall"]["completed"] >= 1
    assert "p95_ms" in report["overall"]
    assert "/healthz" in report["endpoints"]
    healthz = report["endpoints"]["/healthz"]
    assert healthz["count"] >= 1
    assert healthz["fail"] == 0
    error_ep = report["endpoints"]["/error"]
    # /error returns 500 — counted as failure (5xx is not the "expected 4xx" carve-out).
    if error_ep["count"] > 0:
        assert error_ep["fail"] >= 1


def test_run_stress_rejects_empty_profile():
    with pytest.raises(ValueError):
        run_stress(
            base_url="http://localhost:1",
            profile=[],
            duration_seconds=0.1,
            concurrency=1,
            timeout=0.1,
        )


def test_profiles_and_gate_files_exist():
    repo = Path(__file__).resolve().parents[1]
    assert (repo / "scripts" / "stress_profiles" / "smoke.json").exists()
    assert (repo / "scripts" / "stress_profiles" / "sustained.json").exists()
    assert (repo / "scripts" / "stress_profiles" / "gate.smoke.json").exists()
    # Files must be valid JSON.
    for f in ("smoke.json", "sustained.json", "gate.smoke.json"):
        json.loads((repo / "scripts" / "stress_profiles" / f).read_text())
