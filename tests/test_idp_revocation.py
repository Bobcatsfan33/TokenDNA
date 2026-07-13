"""Tests for IdP OAuth revocation connectors (Gap roadmap, Epic 2.1b)."""
from __future__ import annotations

import pytest

from modules.identity import idp_revocation as idp
from modules.identity import revocation_bus as rb


@pytest.fixture(autouse=True)
def clean():
    idp.clear_idp_configs()
    rb.reset_connectors()
    yield
    idp.clear_idp_configs()
    rb.reset_connectors()


class _FakeHTTP:
    """Records calls; returns configured status codes."""

    def __init__(self, status=200):
        self.calls = []
        self.status = status

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, headers, body))
        return self.status, "{}"


def _okta_cfg(agent_id="agent-1"):
    return idp.IdPConfig(
        provider="okta", base_url="https://acme.okta.com", api_token="SSWS-x",
        agents={agent_id: {"principal_id": "u123", "tokens": ["tokA", "tokB"],
                           "client_id": "cid", "client_secret": "csec"}},
    )


def _entra_cfg(agent_id="agent-1"):
    return idp.IdPConfig(
        provider="entra", base_url="https://graph.microsoft.com/v1.0", api_token="bearer-x",
        agents={agent_id: {"principal_id": "obj-456"}},
    )


# ── connectivity gating ─────────────────────────────────────────────────────────

def test_okta_not_connected_without_config():
    assert idp.OktaConnector().is_connected("t") is False


def test_okta_connected_with_config():
    idp.set_idp_config("t", _okta_cfg())
    assert idp.OktaConnector().is_connected("t") is True


# ── Okta ─────────────────────────────────────────────────────────────────────

def test_okta_revoke_tokens_and_deactivate():
    idp.set_idp_config("t", _okta_cfg())
    http = _FakeHTTP()
    c = idp.OktaConnector(http=http)
    detail = c.revoke("t", "agent-1", {"actor": "ops"})
    urls = [u for (_m, u, _h, _b) in http.calls]
    assert sum("/oauth2/v1/revoke" in u for u in urls) == 2   # 2 tokens
    assert any("/lifecycle/deactivate" in u for u in urls)
    assert "deactivated" in detail


def test_okta_http_error_raises():
    idp.set_idp_config("t", _okta_cfg())
    c = idp.OktaConnector(http=_FakeHTTP(status=500))
    with pytest.raises(RuntimeError):
        c.revoke("t", "agent-1", {"actor": "ops"})


def test_okta_unmapped_agent():
    idp.set_idp_config("t", _okta_cfg(agent_id="other"))
    c = idp.OktaConnector(http=_FakeHTTP())
    detail = c.revoke("t", "agent-1", {"actor": "ops"})
    assert "no tokens/principal" in detail


def test_okta_irreversible():
    c = idp.OktaConnector()
    assert "re-authenticate" in c.reverse("t", "a", {"actor": "ops"})


# ── Entra ────────────────────────────────────────────────────────────────────

def test_entra_revoke_sessions_and_disable():
    idp.set_idp_config("t", _entra_cfg())
    http = _FakeHTTP()
    c = idp.EntraConnector(http=http)
    detail = c.revoke("t", "agent-1", {"actor": "ops"})
    methods_urls = [(m, u) for (m, u, _h, _b) in http.calls]
    assert any(m == "POST" and "revokeSignInSessions" in u for m, u in methods_urls)
    assert any(m == "PATCH" and u.endswith("/users/obj-456") for m, u in methods_urls)
    assert "disabled" in detail


def test_entra_http_error_raises():
    idp.set_idp_config("t", _entra_cfg())
    c = idp.EntraConnector(http=_FakeHTTP(status=403))
    with pytest.raises(RuntimeError):
        c.revoke("t", "agent-1", {"actor": "ops"})


# ── bus integration ──────────────────────────────────────────────────────────

def test_bus_includes_idp_planes_after_reset():
    rb.reset_connectors()
    planes = {c.plane for c in rb.get_connectors()}
    assert "idp_okta" in planes and "idp_entra" in planes


def test_bus_skips_unconfigured_idp():
    receipt = rb.preview("tenant-noidp", "agent-1")
    okta = next(p for p in receipt.planes if p.plane == "idp_okta")
    assert okta.status == rb.NOT_CONNECTED


def test_bus_rip_includes_configured_okta(monkeypatch):
    # Configure okta + inject http into the registered connector instance.
    idp.set_idp_config("tenant-x", _okta_cfg(agent_id="rogue"))
    http = _FakeHTTP()
    rb.register_connector(idp.OktaConnector(http=http))  # replace with injected-http instance
    receipt = rb.rip_credentials("tenant-x", "rogue", actor="ops", reason="rogue")
    okta = next(p for p in receipt.planes if p.plane == "idp_okta")
    assert okta.status == rb.KILLED
    assert http.calls  # external revocation actually attempted
