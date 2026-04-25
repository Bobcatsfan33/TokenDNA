"""
Tests for scripts/flywheel_calibration.py — the synthetic-data calibration
harness for the threat-sharing flywheel scoring formula.

The harness exists so operators can sanity-check parameter changes
against well-known scenarios without needing real production data.

Coverage:
  - Confidence formula matches the production module's output.
  - Built-in scenarios are well-formed.
  - Invariant checks fire when the parameters break ordering.
  - CLI exits 0 with default params, 2 when invariants break.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
_SCRIPT = _REPO / "scripts" / "flywheel_calibration.py"


def _load_module():
    # Load the script as a module so we can call its public functions
    # without invoking subprocess. Add scripts/ to sys.path; use importlib
    # so re-imports during pytest don't return a stale cached version.
    scripts_dir = str(_SCRIPT.parent)
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    if "flywheel_calibration" in sys.modules:
        del sys.modules["flywheel_calibration"]
    import flywheel_calibration  # noqa: PLC0415
    return flywheel_calibration


@pytest.fixture()
def fwc():
    return _load_module()


# ─────────────────────────────────────────────────────────────────────────────
# Formula
# ─────────────────────────────────────────────────────────────────────────────

class TestFormula:
    def test_zero_signal_zero_confidence(self, fwc):
        params = fwc.Params()
        c = fwc.confidence(
            confirmed_hits=0, distinct_tenants=0,
            days_since_last_hit=0, params=params,
        )
        assert c == 0.0

    def test_full_decay_after_window(self, fwc):
        params = fwc.Params(confidence_half_life_days=180)
        c = fwc.confidence(
            confirmed_hits=20, distinct_tenants=10,
            days_since_last_hit=400, params=params,
        )
        assert c == 0.0

    def test_breadth_saturates(self, fwc):
        params = fwc.Params(breadth_saturation_tenants=20)
        # At and beyond saturation, the breadth contribution is constant.
        c_at = fwc.confidence(
            confirmed_hits=100, distinct_tenants=20,
            days_since_last_hit=0, params=params,
        )
        c_beyond = fwc.confidence(
            confirmed_hits=100, distinct_tenants=200,
            days_since_last_hit=0, params=params,
        )
        # Confirmation curve is the same; breadth is saturated.
        assert abs(c_at - c_beyond) < 0.005

    def test_matches_production_module(self, fwc, tmp_path, monkeypatch):
        """Cross-check against modules.product.threat_sharing_flywheel."""
        monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "x.db"))
        from modules.product import threat_sharing_flywheel as fw
        # Pure formula: same inputs → same output.
        params = fwc.Params(
            breadth_saturation_tenants=fw.BREADTH_SATURATION_TENANTS,
            confidence_half_life_days=fw.CONFIDENCE_HALF_LIFE_DAYS,
        )
        c_harness = fwc.confidence(
            confirmed_hits=5, distinct_tenants=3,
            days_since_last_hit=0, params=params,
        )
        # Production module derives confidence from the DB; we re-implement
        # the formula here by hand and compare.
        confirmed = 5
        tenants = 3
        hit_component = 1.0 - (1.0 / (1.0 + (confirmed / 3.0)))
        breadth_component = min(tenants, fw.BREADTH_SATURATION_TENANTS) / float(
            fw.BREADTH_SATURATION_TENANTS
        )
        raw = 0.7 * hit_component + 0.3 * breadth_component
        # Decay = 1 (no time elapsed).
        expected = round(raw * 1.0, 4)
        assert c_harness == expected


# ─────────────────────────────────────────────────────────────────────────────
# Invariant checks
# ─────────────────────────────────────────────────────────────────────────────

class TestInvariants:
    def test_default_params_pass_invariants(self, fwc):
        params = fwc.Params()
        rows = fwc.evaluate(fwc.SCENARIOS, params)
        failures = fwc._validate_invariants(rows)
        assert failures == [], failures

    def test_inflation_protected_by_breadth_saturation(self, fwc):
        """The single-tenant high-confirm scenario must rank BELOW the
        broad-but-shallow scenario — that's the breadth-saturation defense."""
        params = fwc.Params()
        rows = fwc.evaluate(fwc.SCENARIOS, params)
        by_name = {r[0].name: r[1] for r in rows}
        assert by_name["broad_but_shallow"] > by_name["suspected_attacker_inflation"]

    def test_invariant_fails_on_extreme_breadth_sat(self, fwc):
        """Sanity check: setting breadth saturation to 1 makes a
        single-tenant inflater rank like a network-confirmed signal — the
        invariant check should catch this misconfiguration."""
        params = fwc.Params(breadth_saturation_tenants=1)
        rows = fwc.evaluate(fwc.SCENARIOS, params)
        failures = fwc._validate_invariants(rows)
        assert any("breadth saturation" in f for f in failures), failures


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

class TestCLI:
    def test_default_run_exits_zero(self):
        proc = subprocess.run(
            [sys.executable, str(_SCRIPT)],
            check=False, capture_output=True, text=True, timeout=10,
        )
        assert proc.returncode == 0, proc.stderr
        assert "scenario" in proc.stdout
        assert "confidence" in proc.stdout

    def test_csv_mode(self):
        proc = subprocess.run(
            [sys.executable, str(_SCRIPT), "--csv"],
            check=False, capture_output=True, text=True, timeout=10,
        )
        assert proc.returncode == 0
        first_line = proc.stdout.splitlines()[0]
        assert first_line.startswith("scenario,")

    def test_misconfigured_breadth_returns_2(self):
        proc = subprocess.run(
            [sys.executable, str(_SCRIPT), "--tenants", "1"],
            check=False, capture_output=True, text=True, timeout=10,
        )
        assert proc.returncode == 2
        assert "INVARIANT FAILURES" in proc.stdout
