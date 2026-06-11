"""T-3: tests for the fail-closed federal-profile FIPS gate.

The gate is in modules.security.fips.assert_fips_mode(). These run on a
non-FIPS host (CI runners, dev macs), so they assert the fail-closed contract:
no-op unless REQUIRE_FIPS=true; exit 78 when required but no validated provider.
"""
import subprocess
import sys

import pytest

from modules.security import fips


def _run_gate(require_fips: str) -> subprocess.CompletedProcess:
    """Run assert_fips_mode() in a fresh interpreter with REQUIRE_FIPS set.

    A subprocess is used because the gate calls sys.exit(), which would abort
    the test process otherwise.
    """
    code = "from modules.security.fips import assert_fips_mode; assert_fips_mode()"
    return subprocess.run(
        [sys.executable, "-c", code],
        env={"REQUIRE_FIPS": require_fips, "ENVIRONMENT": "dev", "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )


def test_gate_is_noop_when_not_required():
    # REQUIRE_FIPS unset/false -> no-op, exit 0.
    assert _run_gate("false").returncode == 0


def test_gate_is_noop_when_env_absent():
    code = "from modules.security.fips import assert_fips_mode; assert_fips_mode()"
    proc = subprocess.run(
        [sys.executable, "-c", code],
        env={"ENVIRONMENT": "dev", "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0


def test_gate_fails_closed_on_non_fips_host():
    # REQUIRE_FIPS=true on a non-FIPS host must exit 78 (EX_CONFIG).
    proc = _run_gate("true")
    assert proc.returncode == fips.EX_CONFIG == 78
    assert "REQUIRE_FIPS=true" in proc.stderr
    assert "FIPS provider is not active" in proc.stderr


def test_provider_active_false_on_non_fips_host(monkeypatch):
    # On this non-FIPS host neither signal should report an active provider.
    assert fips._fips_provider_active() is False


def test_provider_active_true_when_md5_blocked(monkeypatch):
    # Simulate an active FIPS provider: md5 probe raises ValueError.
    def _raise(*_a, **_k):
        raise ValueError("disabled for FIPS")

    monkeypatch.setattr(fips.hashlib, "md5", _raise)
    assert fips._fips_provider_active() is True


def test_provider_active_true_when_kernel_fips(monkeypatch):
    # Simulate kernel FIPS active; md5 probe does not raise.
    class _Status:
        kernel_fips = True

    monkeypatch.setattr(type(fips.fips), "status", property(lambda self: _Status()))
    assert fips._fips_provider_active() is True


def test_assert_passes_when_provider_active(monkeypatch):
    monkeypatch.setenv("REQUIRE_FIPS", "true")
    monkeypatch.setattr(fips, "_fips_provider_active", lambda: True)
    # Must not raise / exit.
    fips.assert_fips_mode()
