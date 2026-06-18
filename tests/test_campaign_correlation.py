"""Tests for cross-session/agent/model campaign correlation (Epic 4.1 / A1)."""
from __future__ import annotations

import importlib

import pytest


@pytest.fixture()
def cc(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "cc.db"))
    import modules.identity.campaign_correlation as m
    importlib.reload(m)
    m.init_db()
    return m


TENANT = "tenant-cc"


def _sig(sid, ts, **dims):
    return {"signal_id": sid, "severity": dims.pop("severity", "medium"), "ts": ts, **dims}


# ── clustering ────────────────────────────────────────────────────────────────

def test_shared_agent_links_across_sessions(cc):
    signals = [
        _sig("s1", 1000, agent_id="A", session_id="sess-1", technique="recon"),
        _sig("s2", 1100, agent_id="A", session_id="sess-2", technique="exfil"),
    ]
    camps = cc.build_campaigns(tenant_id=TENANT, signals=signals, window_seconds=3600)
    assert len(camps) == 1
    c = camps[0]
    assert c["signal_count"] == 2
    assert c["spans_sessions"] is True   # the multi-session reassembly
    assert c["agents"] == 1


def test_unrelated_signals_not_clustered(cc):
    signals = [
        _sig("s1", 1000, agent_id="A", session_id="x"),
        _sig("s2", 1100, agent_id="B", session_id="y"),  # no shared dim
    ]
    camps = cc.build_campaigns(tenant_id=TENANT, signals=signals)
    assert camps == []  # neither cluster reaches min_signals=2


def test_window_separates_distant_signals(cc):
    signals = [
        _sig("s1", 1000, agent_id="A"),
        _sig("s2", 1000 + 10_000, agent_id="A"),  # outside 3600s window
    ]
    camps = cc.build_campaigns(tenant_id=TENANT, signals=signals, window_seconds=3600)
    assert camps == []


def test_spans_models_and_agents(cc):
    signals = [
        _sig("s1", 1000, agent_id="A", model_id="gpt", target="db", session_id="s1"),
        _sig("s2", 1050, agent_id="B", model_id="claude", target="db", session_id="s2"),
    ]
    camps = cc.build_campaigns(tenant_id=TENANT, signals=signals, window_seconds=3600)
    assert len(camps) == 1
    c = camps[0]
    assert c["spans_agents"] and c["spans_models"] and c["spans_sessions"]


def test_severity_is_max(cc):
    signals = [
        _sig("s1", 1000, agent_id="A", severity="low"),
        _sig("s2", 1010, agent_id="A", severity="critical"),
    ]
    c = cc.build_campaigns(tenant_id=TENANT, signals=signals)[0]
    assert c["severity"] == "critical"


def test_techniques_collected(cc):
    signals = [
        _sig("s1", 1000, agent_id="A", technique="recon"),
        _sig("s2", 1010, agent_id="A", technique="exfil"),
    ]
    c = cc.build_campaigns(tenant_id=TENANT, signals=signals)[0]
    assert set(c["techniques"]) == {"recon", "exfil"}


def test_min_signals_threshold(cc):
    signals = [_sig("s1", 1000, agent_id="A", technique="x")]
    assert cc.build_campaigns(tenant_id=TENANT, signals=signals, min_signals=2) == []


# ── intent-match conversion ────────────────────────────────────────────────────

def test_signals_from_intent_matches(cc):
    matches = [
        {"match_id": "m1", "severity": "high", "detected_at": "2026-06-18T00:00:00+00:00",
         "subject": "agent-A", "playbook_name": "exfil-chain",
         "context": {"session_id": "s1", "model_id": "gpt"}},
    ]
    sigs = cc.signals_from_intent_matches(matches)
    assert sigs[0]["agent_id"] == "agent-A"
    assert sigs[0]["session_id"] == "s1"
    assert sigs[0]["technique"] == "exfil-chain"


# ── persistence + audit ────────────────────────────────────────────────────────

def test_persist_and_get(cc):
    signals = [_sig("s1", 1000, agent_id="A", session_id="x"),
               _sig("s2", 1010, agent_id="A", session_id="y")]
    camps = cc.build_campaigns(tenant_id=TENANT, signals=signals)
    cid = camps[0]["campaign_id"]
    assert len(cc.list_campaigns(tenant_id=TENANT)) == 1
    detail = cc.get_campaign(tenant_id=TENANT, campaign_id=cid)
    assert len(detail["signals"]) == 2
    assert detail["spans_sessions"] is True


def test_multidim_campaign_emits_audit(cc, monkeypatch):
    events = []
    import modules.security.audit_log as audit
    monkeypatch.setattr(audit, "log_event",
                        lambda et, *a, **k: events.append(getattr(et, "value", str(et))))
    signals = [_sig("s1", 1000, agent_id="A", session_id="x"),
               _sig("s2", 1010, agent_id="A", session_id="y")]
    cc.build_campaigns(tenant_id=TENANT, signals=signals)
    assert "campaign.detected" in events


# ── API ─────────────────────────────────────────────────────────────────────

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "cc_api.db"))
    import api as app_module
    from fastapi.testclient import TestClient
    from modules.product import commercial_tiers as ct
    from modules.tenants.models import Plan, TenantContext

    tenant = TenantContext(tenant_id="t", tenant_name="T", plan=Plan.ENTERPRISE,
                           api_key_id="k", role="owner")
    app_module.app.dependency_overrides[ct.get_tenant] = lambda: tenant
    yield TestClient(app_module.app, raise_server_exceptions=False)
    app_module.app.dependency_overrides.clear()


def test_api_build_from_signals(client):
    r = client.post("/api/campaigns/build", json={"signals": [
        {"signal_id": "s1", "ts": 1000, "agent_id": "A", "session_id": "x", "severity": "high"},
        {"signal_id": "s2", "ts": 1010, "agent_id": "A", "session_id": "y", "severity": "high"},
    ]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] == 1
    assert body["campaigns"][0]["spans_sessions"] is True
    listing = client.get("/api/campaigns").json()
    assert listing["count"] >= 1
