"""
Sprint B — smoke test for scripts/demo_runtime_risk_engine.py.

Validates that the demo arc script imports cleanly, parses --dry-run, and
exercises every scene without raising.  Does NOT hit a live API; the
integration test in test_rsa_narrative_e2e.py covers the real-network path.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import sys


_DEMO = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "demo_runtime_risk_engine.py"


def test_demo_script_exists():
    assert _DEMO.is_file(), f"missing {_DEMO}"


def test_demo_script_imports_cleanly():
    spec = importlib.util.spec_from_file_location("demo_runtime", _DEMO)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Every scene helper must be a callable.
    for name in (
        "scene_baseline", "scene_drift", "scene_self_modification",
        "scene_mcp_chain", "scene_deception", "scene_blast", "scene_verdict",
    ):
        assert callable(getattr(mod, name)), f"missing or non-callable: {name}"


def test_demo_script_dry_run_completes():
    """Dry-run prints every scene header and returns 0 — no network calls."""
    result = subprocess.run(
        [sys.executable, str(_DEMO), "--dry-run"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    out = result.stdout
    # All seven scenes must appear in the dry-run transcript.
    for scene in (
        "SCENE 1.  Baseline",
        "SCENE 2.  Permission Drift",
        "SCENE 3.  Self-Modification",
        "SCENE 4.  MCP Tool Chain",
        "SCENE 5.  Deception",
        "SCENE 6.  Blast Radius",
        "SCENE 7.  Verdict",
    ):
        assert scene in out, f"missing scene header: {scene}"
    assert "Demo arc complete." in out
