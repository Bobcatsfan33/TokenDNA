"""Tests for the make_client() auto-detect factory and __init__ exports."""

from __future__ import annotations

import tokendna_sdk
from tokendna_sdk import make_client
from tokendna_sdk.client import TokenDNAClient
from tokendna_sdk.config import configure
from tokendna_sdk.local import TokenDNALocalClient


def test_make_client_returns_local_when_url_unset(tmp_tokendna_root):
    c = make_client()
    assert isinstance(c, TokenDNALocalClient)
    assert c.mode == "local"


def test_make_client_returns_remote_when_url_set(monkeypatch):
    monkeypatch.setenv("TOKENDNA_URL", "https://api.example")
    monkeypatch.setenv("TOKENDNA_API_KEY", "k")
    from tokendna_sdk.config import reset_config
    reset_config()
    c = make_client()
    assert isinstance(c, TokenDNAClient)
    assert c.mode == "remote"


def test_make_client_takes_explicit_config_argument(tmp_tokendna_root):
    cfg = configure(api_base="https://override.example", api_key="k")
    c = make_client(config=cfg)
    assert isinstance(c, TokenDNAClient)


def test_public_version_string_is_v0_2():
    assert tokendna_sdk.__version__.startswith("0.2.")


def test_all_export_includes_v02_surface():
    expected = {
        "TokenDNAClient", "TokenDNALocalClient", "make_client",
        "AgentIdentity", "ToolCallEvent", "ModelCallEvent",
        "PolicyVerdict", "Attestation", "BehavioralBaseline",
        "TokenDNAError", "TokenDNAUnavailableError",
        "TokenDNAVerificationError", "TokenDNAAttestationError",
        "EventEmitter",
        # backwards-compat surface still present
        "identified", "tool", "get_agent_metadata", "Client",
    }
    missing = expected - set(tokendna_sdk.__all__)
    assert not missing, f"missing exports: {missing}"
