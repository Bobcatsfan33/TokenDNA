"""Smoke + contract test for the detection-efficacy benchmark.

Runs the benchmark as a subprocess (it must set DEV_MODE/env BEFORE importing
the app, so it cannot share this test process's already-imported modules) and
asserts the strict gate passes and the report has the expected shape: 100%
detection on the three RSA scenarios and zero false positives on the benign
baseline.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "efficacy_benchmark.py"


def _run(tmp_path: Path) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k not in {"DEV_MODE"}}
    env["TOKENDNA_ENV"] = "ci"
    env["PYTHONPATH"] = str(REPO_ROOT)
    return subprocess.run(
        [sys.executable, str(SCRIPT),
         "--iterations", "3", "--out-dir", str(tmp_path), "--json-only", "--strict"],
        cwd=str(REPO_ROOT), env=env, capture_output=True, text=True, timeout=300,
    )


def test_benchmark_strict_passes_and_report_shape(tmp_path):
    result = _run(tmp_path)
    assert result.returncode == 0, (
        f"benchmark --strict failed (exit {result.returncode})\n"
        f"STDOUT:\n{result.stdout[-2000:]}\nSTDERR:\n{result.stderr[-2000:]}"
    )

    report_path = tmp_path / "efficacy_report.json"
    md_path = tmp_path / "efficacy_report.md"
    assert report_path.is_file(), "JSON report not written"
    assert md_path.is_file(), "Markdown report not written"

    report = json.loads(report_path.read_text())
    summary = report["summary"]

    assert summary["detection_rate"] == 1.0, f"expected full detection, got {summary}"
    assert summary["false_positive_rate"] == 0.0, f"expected zero FP, got {summary}"

    scenarios = report["scenarios"]
    assert set(scenarios) == {
        "permission_drift", "policy_self_modification", "mcp_chain_attack"
    }
    for name, data in scenarios.items():
        assert data["detection_rate"] == 1.0, f"{name} under-detected: {data}"
        assert data["false_positive_rate"] == 0.0, f"{name} false-positived: {data}"
        assert "p95" in data["latency_ms"]

    # Latency is reported and compared to the SLO but never gated (advisory).
    assert "edge_decision_slo_ms" in summary
    assert "p95_within_slo" in summary
