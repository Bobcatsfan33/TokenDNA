"""Tests for the env-driven SdkConfig."""

from __future__ import annotations

from tokendna_sdk.config import (
    configure,
    current_config,
    reset_config,
)


def test_defaults_when_no_env(monkeypatch):
    cfg = current_config()
    assert cfg.api_base == ""
    assert cfg.api_key == ""
    assert cfg.timeout_seconds == 5.0
    assert cfg.enabled is True
    assert cfg.is_local()
    assert not cfg.is_online()


def test_tokendna_url_takes_precedence_over_legacy_alias(monkeypatch):
    monkeypatch.setenv("TOKENDNA_API_BASE", "https://legacy")
    monkeypatch.setenv("TOKENDNA_URL", "https://new")
    reset_config()
    cfg = current_config()
    assert cfg.api_base == "https://new"


def test_legacy_api_base_still_works_alone(monkeypatch):
    monkeypatch.setenv("TOKENDNA_API_BASE", "https://legacy")
    reset_config()
    cfg = current_config()
    assert cfg.api_base == "https://legacy"
    assert cfg.is_online()


def test_disabled_flag_takes_priority_over_url(monkeypatch):
    monkeypatch.setenv("TOKENDNA_URL", "https://server")
    monkeypatch.setenv("TOKENDNA_ENABLED", "false")
    reset_config()
    cfg = current_config()
    assert not cfg.is_online()


def test_configure_url_alias_updates_api_base():
    cfg = configure(url="https://x.example/")
    # trailing slash stripped
    assert cfg.api_base == "https://x.example"


def test_configure_partial_update_keeps_other_fields():
    configure(api_base="https://one", api_key="k1", tenant_id="t1")
    cfg = configure(timeout_seconds=10)
    assert cfg.api_base == "https://one"
    assert cfg.api_key == "k1"
    assert cfg.timeout_seconds == 10.0
    assert cfg.tenant_id == "t1"


def test_to_dict_omits_api_key():
    cfg = configure(api_base="https://one", api_key="super-secret")
    d = cfg.to_dict()
    assert "api_key" not in d
    assert d["mode"] == "remote"


def test_to_dict_reflects_local_mode():
    cfg = configure(api_base="")
    assert cfg.to_dict()["mode"] == "local"
