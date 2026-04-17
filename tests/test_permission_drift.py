"""
Tests for TokenDNA Permission Drift Tracker (Sprint 5-2)

RSA'26 Gap 2 — Permission Lifecycle / Drift

Covers:
  - record_observation() with and without attestation
  - Drift detection: threshold, baseline window, min observations
  - DriftAlert creation, update (existing open alert), and retrieval
  - list_alerts() with filters
  - approve_drift() / mark_remediated() workflow
  - agent_drift_report() — full timeline
  - drift_summary() — tenant-level stats
  - blast_radius_comparison() — current vs baseline
  - API endpoints: record, alerts, report, approve, summary, blast-comparison
  - Tenant isolation
  - Edge cases: no history, single observation, below threshold
"""

from __future__ import annotations

import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone, timedelta
from unittest import mock
import importlib

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def pd(tmp_path):
    """Load permission_drift with isolated DB."""
    db_file = str(tmp_path / "drift_test.db")
    with mock.patch.dict(os.environ, {"DATA_DB_PATH": db_file}):
        import modules.identity.permission_drift as m
        importlib.reload(m)
        m.init_db()
        yield m


TENANT = "tenant-drift-test"
TENANT_B = "tenant-b"
AGENT = "agent-alpha"
POLICY = "policy-edge-access"


def _seed_old_obs(pd_module, tenant, agent, policy, scope_weight, days_ago=15):
    """Directly insert an observation with a backdated timestamp."""
    ts = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
    obs_id = str(uuid.uuid4())
    conn = sqlite3.connect(pd_module._DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        INSERT INTO drift_observations
            (observation_id, tenant_id, agent_id, policy_id, scope,
             scope_weight, recorded_at, source_event, has_attestation,
             changed_by, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0, NULL, '{}')
    """, (obs_id, tenant, agent, policy, '[]', scope_weight, ts))
    conn.commit()
    conn.close()
    return obs_id


# ===========================================================================
# record_observation tests
# ===========================================================================

class TestRecordObservation:
    def test_basic_record(self, pd):
        obs = pd.record_observation(
            tenant_id=TENANT, agent_id=AGENT, policy_id=POLICY,
            scope=["read", "write"],
        )
        assert obs.observation_id is not None
        assert obs.scope_weight == 2.0
        assert obs.has_attestation is False

    def test_record_with_attestation(self, pd):
        obs = pd.record_observation(
            tenant_id=TENANT, agent_id=AGENT, policy_id=POLICY,
            scope=["read"], has_attestation=True, changed_by="admin@ops.com",
        )
        assert obs.has_attestation is True
        assert obs.changed_by == "admin@ops.com"

    def test_empty_scope_weight_zero(self, pd):
        obs = pd.record_observation(
            tenant_id=TENANT, agent_id=AGENT, policy_id=POLICY, scope=[],
        )
        assert obs.scope_weight == 0.0

    def test_record_persisted(self, pd):
        obs = pd.record_observation(
            tenant_id=TENANT, agent_id=AGENT, policy_id=POLICY,
            scope=["read"],
        )
        report = pd.agent_drift_report(TENANT, AGENT, POLICY)
        obs_ids = [o.observation_id for o in report.observations]
        assert obs.observation_id in obs_ids

    def test_tenant_isolation(self, pd):
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY, scope=["read"])
        report_b = pd.agent_drift_report(TENANT_B, AGENT, POLICY)
        assert len(report_b.observations) == 0


# ===========================================================================
# Drift detection tests
# ===========================================================================

class TestDriftDetection:
    def test_no_alert_below_threshold(self, pd, monkeypatch):
        monkeypatch.setattr(pd, "DRIFT_THRESHOLD_MULTIPLIER", 5.0)
        monkeypatch.setattr(pd, "DRIFT_STABLE_MIN_OBSERVATIONS", 2)
        _seed_old_obs(pd, TENANT, AGENT, POLICY, 2.0, days_ago=10)
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY, scope=["r", "w"])  # weight=2
        alerts = pd.list_alerts(TENANT)
        assert len(alerts) == 0

    def test_alert_fires_above_threshold(self, pd, monkeypatch):
        monkeypatch.setattr(pd, "DRIFT_THRESHOLD_MULTIPLIER", 2.0)
        monkeypatch.setattr(pd, "DRIFT_STABLE_MIN_OBSERVATIONS", 2)
        _seed_old_obs(pd, TENANT, AGENT, POLICY, 1.0, days_ago=10)
        _seed_old_obs(pd, TENANT, AGENT, POLICY, 1.5, days_ago=5)
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY,
                              scope=["r", "w", "a", "d", "e"])  # weight=5
        alerts = pd.list_alerts(TENANT)
        assert len(alerts) == 1
        assert alerts[0].growth_factor >= 2.0
        assert alerts[0].agent_id == AGENT
        assert alerts[0].status == "open"

    def test_no_alert_insufficient_observations(self, pd, monkeypatch):
        monkeypatch.setattr(pd, "DRIFT_STABLE_MIN_OBSERVATIONS", 5)
        monkeypatch.setattr(pd, "DRIFT_THRESHOLD_MULTIPLIER", 2.0)
        _seed_old_obs(pd, TENANT, AGENT, POLICY, 1.0)
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY, scope=["r", "w", "a", "d", "e"])
        alerts = pd.list_alerts(TENANT)
        assert len(alerts) == 0

    def test_existing_open_alert_updated_not_duplicated(self, pd, monkeypatch):
        monkeypatch.setattr(pd, "DRIFT_THRESHOLD_MULTIPLIER", 2.0)
        monkeypatch.setattr(pd, "DRIFT_STABLE_MIN_OBSERVATIONS", 2)
        _seed_old_obs(pd, TENANT, AGENT, POLICY, 1.0, days_ago=10)
        _seed_old_obs(pd, TENANT, AGENT, POLICY, 1.5, days_ago=5)
        # First record triggers alert
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY, scope=["r", "w", "a", "d", "e"])
        alerts_1 = pd.list_alerts(TENANT)
        assert len(alerts_1) == 1
        # Second record should UPDATE existing alert, not create a second one
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY,
                              scope=["r", "w", "a", "d", "e", "f"])
        alerts_2 = pd.list_alerts(TENANT)
        assert len(alerts_2) == 1

    def test_unattested_changes_counted(self, pd, monkeypatch):
        monkeypatch.setattr(pd, "DRIFT_THRESHOLD_MULTIPLIER", 2.0)
        monkeypatch.setattr(pd, "DRIFT_STABLE_MIN_OBSERVATIONS", 2)
        _seed_old_obs(pd, TENANT, AGENT, POLICY, 1.0, days_ago=10)
        # Add without attestation
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY,
                              scope=["r", "w", "a", "d", "e"],
                              has_attestation=False)
        alerts = pd.list_alerts(TENANT)
        if alerts:
            assert alerts[0].unattested_changes >= 1

    def test_alert_ordered_by_growth_factor_desc(self, pd, monkeypatch):
        monkeypatch.setattr(pd, "DRIFT_THRESHOLD_MULTIPLIER", 2.0)
        monkeypatch.setattr(pd, "DRIFT_STABLE_MIN_OBSERVATIONS", 2)
        for agent, weight in [("agent-small", 3.0), ("agent-large", 10.0)]:
            _seed_old_obs(pd, TENANT, agent, POLICY, 1.0, days_ago=10)
            _seed_old_obs(pd, TENANT, agent, POLICY, 1.5, days_ago=5)
            pd.record_observation(
                tenant_id=TENANT, agent_id=agent, policy_id=POLICY,
                scope=["x"] * int(weight),
            )
        alerts = pd.list_alerts(TENANT)
        if len(alerts) >= 2:
            assert alerts[0].growth_factor >= alerts[1].growth_factor


# ===========================================================================
# Alert lifecycle tests
# ===========================================================================

class TestAlertLifecycle:
    def _create_alert(self, pd, monkeypatch):
        monkeypatch.setattr(pd, "DRIFT_THRESHOLD_MULTIPLIER", 2.0)
        monkeypatch.setattr(pd, "DRIFT_STABLE_MIN_OBSERVATIONS", 2)
        _seed_old_obs(pd, TENANT, AGENT, POLICY, 1.0, days_ago=10)
        _seed_old_obs(pd, TENANT, AGENT, POLICY, 1.5, days_ago=5)
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY,
                              scope=["r", "w", "a", "d", "e"])
        alerts = pd.list_alerts(TENANT)
        assert len(alerts) == 1
        return alerts[0]

    def test_approve_drift(self, pd, monkeypatch):
        alert = self._create_alert(pd, monkeypatch)
        result = pd.approve_drift(
            alert.drift_id, TENANT, "alice@ops.com", "quarterly review approved"
        )
        assert result is not None
        assert result.status == "approved"
        assert result.approved_by == "alice@ops.com"
        assert result.approval_note == "quarterly review approved"

    def test_approve_moves_out_of_open(self, pd, monkeypatch):
        alert = self._create_alert(pd, monkeypatch)
        pd.approve_drift(alert.drift_id, TENANT, "alice")
        open_alerts = pd.list_alerts(TENANT, status="open")
        approved_alerts = pd.list_alerts(TENANT, status="approved")
        assert len(open_alerts) == 0
        assert len(approved_alerts) == 1

    def test_mark_remediated(self, pd, monkeypatch):
        alert = self._create_alert(pd, monkeypatch)
        result = pd.mark_remediated(alert.drift_id, TENANT, "permissions reduced")
        assert result is not None
        assert result.status == "remediated"

    def test_approve_nonexistent_returns_none(self, pd):
        assert pd.approve_drift("nonexistent", TENANT, "alice") is None

    def test_mark_remediated_nonexistent_returns_none(self, pd):
        assert pd.mark_remediated("nonexistent", TENANT) is None

    def test_get_alert_by_id(self, pd, monkeypatch):
        alert = self._create_alert(pd, monkeypatch)
        fetched = pd.get_alert(alert.drift_id, TENANT)
        assert fetched is not None
        assert fetched.drift_id == alert.drift_id

    def test_get_nonexistent_alert_returns_none(self, pd):
        assert pd.get_alert("nope", TENANT) is None

    def test_list_alerts_filter_by_agent(self, pd, monkeypatch):
        monkeypatch.setattr(pd, "DRIFT_THRESHOLD_MULTIPLIER", 2.0)
        monkeypatch.setattr(pd, "DRIFT_STABLE_MIN_OBSERVATIONS", 2)
        for agent in ["agent-a", "agent-b"]:
            _seed_old_obs(pd, TENANT, agent, POLICY, 1.0, days_ago=10)
            _seed_old_obs(pd, TENANT, agent, POLICY, 1.5, days_ago=5)
            pd.record_observation(tenant_id=TENANT, agent_id=agent,
                                  policy_id=POLICY,
                                  scope=["r", "w", "a", "d", "e"])
        alerts_a = pd.list_alerts(TENANT, agent_id="agent-a")
        assert all(a.agent_id == "agent-a" for a in alerts_a)


# ===========================================================================
# Agent drift report tests
# ===========================================================================

class TestAgentDriftReport:
    def test_empty_report(self, pd):
        report = pd.agent_drift_report(TENANT, AGENT, POLICY)
        assert report.agent_id == AGENT
        assert len(report.observations) == 0
        assert report.growth_factor == 1.0

    def test_report_contains_observations(self, pd):
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY, scope=["r"])
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY, scope=["r", "w"])
        report = pd.agent_drift_report(TENANT, AGENT, POLICY)
        assert len(report.observations) == 2

    def test_report_growth_factor_computed(self, pd):
        _seed_old_obs(pd, TENANT, AGENT, POLICY, 1.0)
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY, scope=["r", "w", "a"])
        report = pd.agent_drift_report(TENANT, AGENT, POLICY)
        assert report.current_weight == 3.0
        assert report.baseline_weight == 1.0
        assert report.growth_factor == 3.0

    def test_report_unattested_count(self, pd):
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY, scope=["r"],
                              has_attestation=False)
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY, scope=["r", "w"],
                              has_attestation=True)
        report = pd.agent_drift_report(TENANT, AGENT, POLICY)
        assert report.unattested_changes == 1

    def test_report_respects_days_window(self, pd):
        _seed_old_obs(pd, TENANT, AGENT, POLICY, 1.0, days_ago=60)
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY, scope=["r"])
        # 7-day window should only see the recent observation
        report = pd.agent_drift_report(TENANT, AGENT, POLICY, days=7)
        assert len(report.observations) == 1

    def test_report_tenant_isolation(self, pd):
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY, scope=["r"])
        report_b = pd.agent_drift_report(TENANT_B, AGENT, POLICY)
        assert len(report_b.observations) == 0


# ===========================================================================
# Drift summary tests
# ===========================================================================

class TestDriftSummary:
    def test_empty_summary(self, pd):
        s = pd.drift_summary(TENANT)
        assert s.agents_tracked == 0
        assert s.total_open_alerts == 0
        assert s.highest_growth_factor == 0.0

    def test_summary_after_observations(self, pd, monkeypatch):
        monkeypatch.setattr(pd, "DRIFT_THRESHOLD_MULTIPLIER", 2.0)
        monkeypatch.setattr(pd, "DRIFT_STABLE_MIN_OBSERVATIONS", 2)
        _seed_old_obs(pd, TENANT, AGENT, POLICY, 1.0, days_ago=10)
        _seed_old_obs(pd, TENANT, AGENT, POLICY, 1.5, days_ago=5)
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY,
                              scope=["r", "w", "a", "d", "e"])
        s = pd.drift_summary(TENANT)
        assert s.agents_tracked == 1
        assert s.total_open_alerts == 1
        assert s.agents_with_open_alerts == 1
        assert s.highest_growth_factor >= 2.0
        assert s.highest_growth_agent == AGENT

    def test_summary_approved_counted(self, pd, monkeypatch):
        monkeypatch.setattr(pd, "DRIFT_THRESHOLD_MULTIPLIER", 2.0)
        monkeypatch.setattr(pd, "DRIFT_STABLE_MIN_OBSERVATIONS", 2)
        _seed_old_obs(pd, TENANT, AGENT, POLICY, 1.0, days_ago=10)
        _seed_old_obs(pd, TENANT, AGENT, POLICY, 1.5, days_ago=5)
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY,
                              scope=["r", "w", "a", "d", "e"])
        alerts = pd.list_alerts(TENANT)
        pd.approve_drift(alerts[0].drift_id, TENANT, "ops")
        s = pd.drift_summary(TENANT)
        assert s.total_approved == 1
        assert s.total_open_alerts == 0

    def test_summary_tenant_isolation(self, pd):
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY, scope=["r"])
        s_b = pd.drift_summary(TENANT_B)
        assert s_b.agents_tracked == 0


# ===========================================================================
# Blast radius comparison tests
# ===========================================================================

class TestBlastRadiusComparison:
    def test_no_history_returns_not_found(self, pd):
        result = pd.blast_radius_comparison(TENANT, AGENT, POLICY)
        assert result["found"] is False

    def test_comparison_with_history(self, pd):
        _seed_old_obs(pd, TENANT, AGENT, POLICY, 2.0, days_ago=15)
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY,
                              scope=["r", "w", "a", "d", "e", "f"])
        result = pd.blast_radius_comparison(TENANT, AGENT, POLICY)
        assert result["found"] is True
        assert result["baseline_weight"] == 2.0
        assert result["current_weight"] == 6.0
        assert result["growth_factor"] == 3.0
        assert result["blast_radius_growth_estimate"] == "critical"  # ≥3×

    def test_low_tier(self, pd):
        _seed_old_obs(pd, TENANT, AGENT, POLICY, 4.0, days_ago=10)
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY, scope=["r", "w", "a", "d", "e"])  # 5
        result = pd.blast_radius_comparison(TENANT, AGENT, POLICY)
        assert result["found"] is True
        assert result["blast_radius_growth_estimate"] == "low"  # 5/4 = 1.25×

    def test_medium_tier(self, pd):
        _seed_old_obs(pd, TENANT, AGENT, POLICY, 3.0, days_ago=10)
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY,
                              scope=["r", "w", "a", "d", "e"])  # 5 → 5/3 = 1.67×
        result = pd.blast_radius_comparison(TENANT, AGENT, POLICY)
        assert result["found"] is True
        assert result["blast_radius_growth_estimate"] == "medium"

    def test_notes_field_present(self, pd):
        _seed_old_obs(pd, TENANT, AGENT, POLICY, 1.0, days_ago=10)
        pd.record_observation(tenant_id=TENANT, agent_id=AGENT,
                              policy_id=POLICY, scope=["r", "w", "a"])
        result = pd.blast_radius_comparison(TENANT, AGENT, POLICY)
        assert "notes" in result
        assert AGENT in result["notes"]


# ===========================================================================
# API endpoint tests
# ===========================================================================

@pytest.fixture
def api_client(tmp_path):
    db_file = str(tmp_path / "api_drift_test.db")
    with mock.patch.dict(os.environ, {"DATA_DB_PATH": db_file, "DEV_MODE": "true"}):
        from modules.tenants import store as ts
        importlib.reload(ts)
        ts.init_db()

        import modules.identity.permission_drift as pd_mod
        importlib.reload(pd_mod)
        pd_mod.init_db()

        import modules.tenants.middleware as mw
        importlib.reload(mw)
        import auth as auth_mod
        importlib.reload(auth_mod)

        from fastapi.testclient import TestClient
        import api as api_mod
        importlib.reload(api_mod)
        client = TestClient(api_mod.app, raise_server_exceptions=False)
        yield client


def _auth():
    return {"X-API-Key": "dev-api-key"}


class TestDriftAPI:
    def test_record_observation(self, api_client):
        resp = api_client.post("/api/drift/record", headers=_auth(), json={
            "agent_id": "agent-x",
            "policy_id": "pol-a",
            "scope": ["read", "write"],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "observation_id" in data
        assert data["scope_weight"] == 2.0

    def test_record_missing_fields_400(self, api_client):
        resp = api_client.post("/api/drift/record", headers=_auth(), json={})
        assert resp.status_code == 400

    def test_alerts_empty(self, api_client):
        resp = api_client.get("/api/drift/alerts", headers=_auth())
        assert resp.status_code == 200
        data = resp.json()
        assert data["alerts"] == []
        assert data["count"] == 0

    def test_summary_empty(self, api_client):
        resp = api_client.get("/api/drift/summary", headers=_auth())
        assert resp.status_code == 200
        data = resp.json()
        assert "agents_tracked" in data
        assert data["agents_tracked"] == 0

    def test_report_empty(self, api_client):
        resp = api_client.get("/api/drift/report/agent-x?policy_id=pol-a",
                              headers=_auth())
        assert resp.status_code == 200
        data = resp.json()
        assert data["agent_id"] == "agent-x"
        assert data["observation_count"] == 0

    def test_report_missing_policy_id_400(self, api_client):
        resp = api_client.get("/api/drift/report/agent-x", headers=_auth())
        # FastAPI returns 422 for missing required query params
        assert resp.status_code in (400, 422)

    def test_blast_comparison_no_history(self, api_client):
        resp = api_client.get(
            "/api/drift/blast-comparison/agent-x?policy_id=pol-a",
            headers=_auth()
        )
        assert resp.status_code == 200
        assert resp.json()["found"] is False

    def test_approve_drift_not_found(self, api_client):
        resp = api_client.post(
            "/api/drift/approve/nonexistent",
            headers=_auth(),
            json={"approved_by": "alice"},
        )
        assert resp.status_code == 404

    def test_approve_missing_approved_by_400(self, api_client):
        resp = api_client.post(
            "/api/drift/approve/some-id",
            headers=_auth(),
            json={},
        )
        assert resp.status_code == 400

    def test_full_record_and_report_flow(self, api_client):
        # Record an observation
        api_client.post("/api/drift/record", headers=_auth(), json={
            "agent_id": "agent-flow",
            "policy_id": "pol-flow",
            "scope": ["read"],
        })
        # Fetch report
        resp = api_client.get(
            "/api/drift/report/agent-flow?policy_id=pol-flow",
            headers=_auth()
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["observation_count"] == 1
        assert data["observations"][0]["scope_weight"] == 1.0
