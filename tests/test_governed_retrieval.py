"""Tests for governed retrieval (Gap roadmap Epic 3.3 / B3)."""
from __future__ import annotations

import importlib

import pytest


@pytest.fixture()
def gr(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "gr.db"))
    import modules.identity.governed_retrieval as m
    importlib.reload(m)
    m.init_db()
    return m


TENANT = "tenant-gr"
AGENT = "agent-research"


def test_default_deny_when_empty(gr):
    d = gr.check_retrieval(tenant_id=TENANT, agent_id=AGENT, source="snowflake://prod/pii")
    assert d["allowed"] is False  # fail-closed


def test_allow_exact_match(gr):
    gr.add_allowed_source(tenant_id=TENANT, agent_id=AGENT, pattern="https://api.weather.com/v1")
    d = gr.check_retrieval(tenant_id=TENANT, agent_id=AGENT, source="https://api.weather.com/v1")
    assert d["allowed"] is True
    assert d["matched_pattern"] == "https://api.weather.com/v1"


def test_allow_glob(gr):
    gr.add_allowed_source(tenant_id=TENANT, agent_id=AGENT, pattern="s3://reports/*")
    assert gr.check_retrieval(tenant_id=TENANT, agent_id=AGENT, source="s3://reports/q1.csv")["allowed"]
    assert not gr.check_retrieval(tenant_id=TENANT, agent_id=AGENT, source="s3://secrets/keys")["allowed"]


def test_wildcard_agent_policy(gr):
    gr.add_allowed_source(tenant_id=TENANT, agent_id=gr.ANY_AGENT, pattern="https://public/*")
    # applies to any agent
    assert gr.check_retrieval(tenant_id=TENANT, agent_id="any-agent", source="https://public/data")["allowed"]


def test_policy_scoped_to_agent(gr):
    gr.add_allowed_source(tenant_id=TENANT, agent_id=AGENT, pattern="db://x")
    assert not gr.check_retrieval(tenant_id=TENANT, agent_id="other", source="db://x")["allowed"]


def test_list_and_remove(gr):
    r = gr.add_allowed_source(tenant_id=TENANT, agent_id=AGENT, pattern="db://x")
    assert len(gr.list_allowed_sources(tenant_id=TENANT, agent_id=AGENT)) == 1
    gr.remove_allowed_source(tenant_id=TENANT, source_id=r["source_id"])
    assert gr.list_allowed_sources(tenant_id=TENANT, agent_id=AGENT) == []


def test_add_requires_pattern(gr):
    with pytest.raises(ValueError):
        gr.add_allowed_source(tenant_id=TENANT, agent_id=AGENT, pattern="")


# ── broker ────────────────────────────────────────────────────────────────────

def test_broker_allows_and_fetches(gr):
    gr.add_allowed_source(tenant_id=TENANT, agent_id=AGENT, pattern="db://allowed/*")
    out = gr.broker(tenant_id=TENANT, agent_id=AGENT, source="db://allowed/t",
                    fetch=lambda: "DATA")
    assert out == "DATA"


def test_broker_denies(gr):
    with pytest.raises(gr.RetrievalDenied):
        gr.broker(tenant_id=TENANT, agent_id=AGENT, source="db://forbidden",
                  fetch=lambda: "DATA")


def test_broker_does_not_fetch_when_denied(gr):
    called = []
    with pytest.raises(gr.RetrievalDenied):
        gr.broker(tenant_id=TENANT, agent_id=AGENT, source="db://x",
                  fetch=lambda: called.append(1))
    assert called == []


# ── audit ─────────────────────────────────────────────────────────────────────

def test_check_emits_audit(gr, monkeypatch):
    events = []
    import modules.security.audit_log as audit
    monkeypatch.setattr(audit, "log_event",
                        lambda et, *a, **k: events.append(getattr(et, "value", str(et))))
    gr.add_allowed_source(tenant_id=TENANT, agent_id=AGENT, pattern="ok://*")
    gr.check_retrieval(tenant_id=TENANT, agent_id=AGENT, source="ok://x")
    gr.check_retrieval(tenant_id=TENANT, agent_id=AGENT, source="bad://x")
    assert "retrieval.allowed" in events and "retrieval.denied" in events


# ── API ─────────────────────────────────────────────────────────────────────

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "gr_api.db"))
    import api as app_module
    from fastapi.testclient import TestClient
    from modules.product import commercial_tiers as ct
    from modules.tenants.models import Plan, TenantContext

    tenant = TenantContext(tenant_id="t", tenant_name="T", plan=Plan.ENTERPRISE,
                           api_key_id="k", role="owner")
    app_module.app.dependency_overrides[ct.get_tenant] = lambda: tenant
    yield TestClient(app_module.app, raise_server_exceptions=False)
    app_module.app.dependency_overrides.clear()


def test_api_add_then_check(client):
    r = client.post("/api/retrieval/sources", json={"agent_id": "a1", "pattern": "s3://ok/*"})
    assert r.status_code == 200, r.text
    allow = client.post("/api/retrieval/check", json={"agent_id": "a1", "source": "s3://ok/f"}).json()
    assert allow["allowed"] is True
    deny = client.post("/api/retrieval/check", json={"agent_id": "a1", "source": "s3://no/f"}).json()
    assert deny["allowed"] is False


def test_api_check_requires_fields(client):
    r = client.post("/api/retrieval/check", json={"agent_id": "a1"})
    assert r.status_code == 400
