"""Regression matrix for the DEV_MODE production safety guard in config.py.

DEV_MODE bypasses ALL authentication. The guard is DENY-BY-DEFAULT: importing
``config`` with DEV_MODE=true must terminate (exit 1) unless the resolved
environment (TOKENDNA_ENV first, then ENVIRONMENT) is an explicit development
context.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[1]


def _boot(env_overrides: dict) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k not in {"TOKENDNA_ENV", "ENVIRONMENT", "DEV_MODE"}}
    env.update(env_overrides)
    env["PYTHONPATH"] = str(REPO_ROOT)
    return subprocess.run(
        [sys.executable, "-c", "import config"],
        cwd=str(REPO_ROOT), env=env, capture_output=True, text=True, timeout=30,
    )


PROD_LIKE = ["production", "prod", "staging", "stage", "il2", "il4", "il5", "il6", "", "unknown"]
DEV_LIKE = ["dev", "development", "test", "testing", "local", "ci"]


@pytest.mark.parametrize("env_var", ["TOKENDNA_ENV", "ENVIRONMENT"])
@pytest.mark.parametrize("value", PROD_LIKE)
def test_dev_mode_blocked_outside_dev(env_var, value):
    r = _boot({env_var: value, "DEV_MODE": "true"})
    assert r.returncode == 1, f"{env_var}={value!r} DEV_MODE=true should be fatal\n{r.stderr}"
    assert "FATAL" in r.stderr


def test_dev_mode_blocked_when_env_completely_unset():
    r = _boot({"DEV_MODE": "true"})
    assert r.returncode == 1, f"unset env + DEV_MODE=true should be fatal\n{r.stderr}"


def test_tokendna_env_takes_precedence_over_environment():
    r = _boot({"TOKENDNA_ENV": "production", "ENVIRONMENT": "dev", "DEV_MODE": "true"})
    assert r.returncode == 1, f"TOKENDNA_ENV must override ENVIRONMENT\n{r.stderr}"


@pytest.mark.parametrize("value", DEV_LIKE)
def test_dev_mode_allowed_in_dev(value):
    r = _boot({"TOKENDNA_ENV": value, "DEV_MODE": "true"})
    assert r.returncode == 0, f"DEV_MODE=true in {value!r} should boot\n{r.stderr}"


@pytest.mark.parametrize("value", PROD_LIKE)
def test_prod_boots_without_dev_mode(value):
    r = _boot({"TOKENDNA_ENV": value, "DEV_MODE": "false"})
    assert r.returncode == 0, f"{value!r} without DEV_MODE should boot\n{r.stderr}"
