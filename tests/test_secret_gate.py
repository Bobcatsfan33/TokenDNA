from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.security.secret_gate import (
    ConfigurationError,
    KNOWN_DEV_DEFAULTS,
    REQUIRED_PRODUCTION_SECRETS,
    assert_production_secrets,
    is_production,
    report,
    secret_value,
)


@pytest.fixture(autouse=True)
def _scrub_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TOKENDNA_ENV", raising=False)
    for var in REQUIRED_PRODUCTION_SECRETS:
        monkeypatch.delenv(var, raising=False)


def test_is_production_recognizes_canonical_values(monkeypatch):
    monkeypatch.setenv("TOKENDNA_ENV", "production")
    assert is_production() is True
    monkeypatch.setenv("TOKENDNA_ENV", "PROD")
    assert is_production() is True
    monkeypatch.setenv("TOKENDNA_ENV", "staging")
    assert is_production() is False


def test_secret_value_returns_dev_default_outside_prod():
    out = secret_value("TOKENDNA_DELEGATION_SECRET", "dev-fallback")
    assert out == "dev-fallback"


def test_secret_value_uses_env_when_set(monkeypatch):
    monkeypatch.setenv("TOKENDNA_DELEGATION_SECRET", "env-supplied-key-1234567890abcdef")
    out = secret_value("TOKENDNA_DELEGATION_SECRET", "dev-fallback")
    assert out == "env-supplied-key-1234567890abcdef"


def test_secret_value_in_prod_rejects_missing(monkeypatch):
    monkeypatch.setenv("TOKENDNA_ENV", "production")
    with pytest.raises(ConfigurationError) as exc:
        secret_value("TOKENDNA_DELEGATION_SECRET", "irrelevant")
    assert "not set" in str(exc.value)


def test_secret_value_in_prod_rejects_dev_default(monkeypatch):
    monkeypatch.setenv("TOKENDNA_ENV", "production")
    monkeypatch.setenv(
        "TOKENDNA_DELEGATION_SECRET",
        KNOWN_DEV_DEFAULTS["TOKENDNA_DELEGATION_SECRET"],
    )
    with pytest.raises(ConfigurationError) as exc:
        secret_value("TOKENDNA_DELEGATION_SECRET", "irrelevant")
    assert "dev default" in str(exc.value)


def test_secret_value_in_prod_rejects_short_secret(monkeypatch):
    monkeypatch.setenv("TOKENDNA_ENV", "production")
    monkeypatch.setenv("TOKENDNA_DELEGATION_SECRET", "short")
    with pytest.raises(ConfigurationError) as exc:
        secret_value("TOKENDNA_DELEGATION_SECRET", "irrelevant")
    assert "shorter than" in str(exc.value)


def test_assert_production_secrets_noop_outside_prod():
    assert_production_secrets()  # no env set, must not raise


def test_assert_production_secrets_raises_when_anything_missing(monkeypatch):
    monkeypatch.setenv("TOKENDNA_ENV", "production")
    for var in REQUIRED_PRODUCTION_SECRETS[:-1]:
        monkeypatch.setenv(var, "x" * 32)
    # Last one missing — must fail.
    with pytest.raises(ConfigurationError):
        assert_production_secrets()


def test_assert_production_secrets_passes_when_all_strong(monkeypatch):
    monkeypatch.setenv("TOKENDNA_ENV", "production")
    for var in REQUIRED_PRODUCTION_SECRETS:
        monkeypatch.setenv(var, "x" * 32)
    assert_production_secrets()  # must not raise


def test_report_does_not_leak_secret_value(monkeypatch):
    monkeypatch.setenv("TOKENDNA_DELEGATION_SECRET", "supersecretkeydonotleak")
    items = report()
    rendered = " ".join(repr(item) for item in items)
    assert "supersecretkeydonotleak" not in rendered
    found = next(i for i in items if i.env_var == "TOKENDNA_DELEGATION_SECRET")
    assert found.present is True
    assert found.is_dev_default is False
    assert found.length_bytes > 0
