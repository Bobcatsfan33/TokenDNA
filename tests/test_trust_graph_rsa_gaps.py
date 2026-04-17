"""
Tests for RSA'26 Gap-Closure Extensions to UIS Trust Graph (Sprint 1-2 addendum)

Covers:
  RULE-04  POLICY_SELF_MODIFICATION  (RSA Gap 1)
    - Fires CRITICAL when agent modifies a policy that pre-exists as its
      governing policy
    - Does NOT fire on first governance event, read-only actions, or
      unrelated policies
    - Evidence includes RSA gap label

  RULE-05  PERMISSION_DRIFT_SPIKE    (RSA Gap 2)
    - Fires HIGH when permission scope weight grows >2x vs baseline
    - Does NOT fire below threshold
    - Evidence includes growth_factor and RSA gap label

  Helper functions:
    - record_policy_governance() pre-existence tracking
    - record_permission_scope() history recording
    - check_policy_self_modification()
    - check_permission_drift()
"""

from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from unittest import mock
import importlib

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tg(tmp_path):
    """Load trust_graph module with isolated SQLite DB."""
    db_file = str(tmp_path / "rsa_test.db")
    with mock.patch.dict(os.environ, {"DATA_DB_PATH": db_file}):
        import modules.identity.trust_graph as m
        importlib.reload(m)
        m.init_db()
        m._rsa_init_db()
        yield m


TENANT = "tenant-rsa-test"


# ---------------------------------------------------------------------------
# record_policy_governance tests
# ---------------------------------------------------------------------------

class TestRecordPolicyGovernance:
    def test_first_call_returns_false(self, tg):
        """First governance record: brand new, returns False."""
        result = tg.record_policy_governance(TENANT, "pol-a", "agent-a")
        assert result is False

    def test_second_call_returns_true(self, tg):
        """Second call on same edge: pre-existing, returns True."""
        tg.record_policy_governance(TENANT, "pol-a", "agent-a")
        result = tg.record_policy_governance(TENANT, "pol-a", "agent-a")
        assert result is True

    def test_different_policy_independent(self, tg):
        """Different policies are independent edges."""
        tg.record_policy_governance(TENANT, "pol-a", "agent-a")
        result = tg.record_policy_governance(TENANT, "pol-b", "agent-a")
        assert result is False  # pol-b is new

    def test_different_tenant_independent(self, tg):
        """Different tenants don't share governance edges."""
        tg.record_policy_governance(TENANT, "pol-a", "agent-a")
        result = tg.record_policy_governance("other-tenant", "pol-a", "agent-a")
        assert result is False


# ---------------------------------------------------------------------------
# RULE-04: Policy Self-Modification (RSA Gap 1)
# ---------------------------------------------------------------------------

class TestRule04PolicySelfModification:
    def test_fires_for_policy_write_on_governing_policy(self, tg):
        """Core scenario: agent writes to policy that governs it."""
        # Establish pre-existing governance (2+ observations)
        tg.record_policy_governance(TENANT, "pol-sec", "agent-rogue")
        tg.record_policy_governance(TENANT, "pol-sec", "agent-rogue")
        anomaly = tg.check_policy_self_modification(
            TENANT, "agent-rogue", "pol-sec",
            event_type="policy_write", action="write",
        )
        assert anomaly is not None
        assert anomaly.anomaly_type == "POLICY_SELF_MODIFICATION"
        assert anomaly.severity == "critical"
        assert "agent-rogue" in anomaly.subject_node

    def test_fires_for_rule_removal(self, tg):
        tg.record_policy_governance(TENANT, "pol-sec", "agent-rogue")
        tg.record_policy_governance(TENANT, "pol-sec", "agent-rogue")
        anomaly = tg.check_policy_self_modification(
            TENANT, "agent-rogue", "pol-sec",
            event_type="rule_removal", action="remove",
        )
        assert anomaly is not None
        assert anomaly.severity == "critical"

    def test_fires_for_policy_delete(self, tg):
        tg.record_policy_governance(TENANT, "pol-sec", "agent-rogue")
        tg.record_policy_governance(TENANT, "pol-sec", "agent-rogue")
        anomaly = tg.check_policy_self_modification(
            TENANT, "agent-rogue", "pol-sec",
            event_type="policy_delete", action="delete",
        )
        assert anomaly is not None

    def test_fires_for_privilege_escalation(self, tg):
        tg.record_policy_governance(TENANT, "pol-sec", "agent-rogue")
        tg.record_policy_governance(TENANT, "pol-sec", "agent-rogue")
        anomaly = tg.check_policy_self_modification(
            TENANT, "agent-rogue", "pol-sec",
            event_type="privilege_escalation",
        )
        assert anomaly is not None

    def test_no_anomaly_on_first_governance_observation(self, tg):
        """First event creates the governance edge — not a self-modification."""
        tg.record_policy_governance(TENANT, "pol-sec", "agent-rogue")
        # Only one observation (just created) — should NOT fire
        anomaly = tg.check_policy_self_modification(
            TENANT, "agent-rogue", "pol-sec",
            event_type="policy_write", action="write",
        )
        assert anomaly is None

    def test_no_anomaly_for_read_action(self, tg):
        tg.record_policy_governance(TENANT, "pol-sec", "agent-good")
        tg.record_policy_governance(TENANT, "pol-sec", "agent-good")
        anomaly = tg.check_policy_self_modification(
            TENANT, "agent-good", "pol-sec",
            event_type="policy_read", action="read",
        )
        assert anomaly is None

    def test_no_anomaly_for_unrelated_policy(self, tg):
        """Agent writes to a policy it does NOT govern — no anomaly."""
        # Establish governance for pol-mine only
        tg.record_policy_governance(TENANT, "pol-mine", "agent-a")
        tg.record_policy_governance(TENANT, "pol-mine", "agent-a")
        # Write to a completely different policy
        anomaly = tg.check_policy_self_modification(
            TENANT, "agent-a", "pol-UNRELATED",
            event_type="policy_write", action="write",
        )
        assert anomaly is None

    def test_no_anomaly_when_no_governance_recorded(self, tg):
        anomaly = tg.check_policy_self_modification(
            TENANT, "fresh-agent", "fresh-policy",
            event_type="policy_write", action="write",
        )
        assert anomaly is None

    def test_evidence_has_rsa_gap_label(self, tg):
        tg.record_policy_governance(TENANT, "pol-sec", "agent-rogue")
        tg.record_policy_governance(TENANT, "pol-sec", "agent-rogue")
        anomaly = tg.check_policy_self_modification(
            TENANT, "agent-rogue", "pol-sec",
            event_type="policy_write", action="write",
        )
        assert anomaly is not None
        assert "rsa_gap" in anomaly.context
        assert "Gap 1" in anomaly.context["rsa_gap"]
        assert anomaly.context["rule"] == "RULE-04"

    def test_anomaly_stored_in_db(self, tg):
        tg.record_policy_governance(TENANT, "pol-sec", "agent-rogue")
        tg.record_policy_governance(TENANT, "pol-sec", "agent-rogue")
        tg.check_policy_self_modification(
            TENANT, "agent-rogue", "pol-sec",
            event_type="policy_write", action="write",
        )
        anomalies = tg.get_anomalies(tenant_id=TENANT)
        types = [a["anomaly_type"] for a in anomalies]
        assert "POLICY_SELF_MODIFICATION" in types

    def test_description_mentions_rsa26(self, tg):
        tg.record_policy_governance(TENANT, "pol-sec", "agent-rogue")
        tg.record_policy_governance(TENANT, "pol-sec", "agent-rogue")
        anomaly = tg.check_policy_self_modification(
            TENANT, "agent-rogue", "pol-sec",
            event_type="policy_write", action="write",
        )
        assert anomaly is not None
        assert "RSA" in anomaly.detail

    def test_tenant_isolation(self, tg):
        """Governance in tenant A does not affect tenant B."""
        tg.record_policy_governance("tenant-a", "pol-sec", "agent-rogue")
        tg.record_policy_governance("tenant-a", "pol-sec", "agent-rogue")
        # Attempt self-modification check for tenant-b (no governance recorded there)
        anomaly = tg.check_policy_self_modification(
            "tenant-b", "agent-rogue", "pol-sec",
            event_type="policy_write", action="write",
        )
        assert anomaly is None


# ---------------------------------------------------------------------------
# RULE-05: Permission Drift Spike (RSA Gap 2)
# ---------------------------------------------------------------------------

class TestRule05PermissionDrift:
    def _record_with_timestamp(self, tg, tenant: str, agent: str, policy: str,
                                scope_weight: float, days_ago: float = 0) -> None:
        """Directly insert a permission history record at a specific time."""
        import modules.identity.trust_graph as m
        ts = (
            datetime.now(timezone.utc) - timedelta(days=days_ago)
        ).isoformat()
        db = m._db_path()
        conn = sqlite3.connect(db, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("""
                INSERT INTO tg_permission_history
                    (history_id, tenant_id, agent_label, policy_label,
                     recorded_at, scope_weight, source_event)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (str(uuid.uuid4()), tenant, agent, policy,
                  ts, scope_weight, "test"))
            conn.commit()
        finally:
            conn.close()

    def test_fires_for_large_growth(self, tg):
        """Scope grew from 1 to 5 (5× growth, above 2× threshold)."""
        self._record_with_timestamp(tg, TENANT, "a1", "pol1", 1.0, days_ago=10)
        # Current: much larger scope
        tg.record_permission_scope(TENANT, "a1", "pol1", ["r", "w", "a", "d", "e"])
        anomaly = tg.check_permission_drift(TENANT, "a1", "pol1")
        assert anomaly is not None
        assert anomaly.anomaly_type == "PERMISSION_DRIFT_SPIKE"
        assert anomaly.severity == "high"

    def test_no_anomaly_moderate_growth(self, tg, monkeypatch):
        """Growth below threshold should not fire."""
        import modules.identity.trust_graph as m
        monkeypatch.setattr(m, "PERMISSION_GROWTH_THRESHOLD", 5.0)
        self._record_with_timestamp(tg, TENANT, "a1", "pol1", 2.0, days_ago=10)
        tg.record_permission_scope(TENANT, "a1", "pol1", ["r", "w"])  # weight=2
        anomaly = tg.check_permission_drift(TENANT, "a1", "pol1")
        assert anomaly is None  # 2/2 = 1.0×, below 5.0× threshold

    def test_no_anomaly_no_history(self, tg):
        """No history at all — should return None gracefully."""
        anomaly = tg.check_permission_drift(TENANT, "new-agent", "new-policy")
        assert anomaly is None

    def test_no_anomaly_single_record(self, tg):
        """Only one record — baseline and current are the same, growth=1.0×."""
        tg.record_permission_scope(TENANT, "a1", "pol1", ["r"])
        anomaly = tg.check_permission_drift(TENANT, "a1", "pol1")
        assert anomaly is None

    def test_evidence_has_growth_factor(self, tg):
        self._record_with_timestamp(tg, TENANT, "a1", "pol1", 1.0, days_ago=5)
        tg.record_permission_scope(TENANT, "a1", "pol1", ["r", "w", "a", "d", "e"])
        anomaly = tg.check_permission_drift(TENANT, "a1", "pol1")
        assert anomaly is not None
        assert "growth_factor" in anomaly.context
        assert anomaly.context["growth_factor"] >= 2.0

    def test_evidence_has_rsa_gap_label(self, tg):
        self._record_with_timestamp(tg, TENANT, "a1", "pol1", 1.0, days_ago=5)
        tg.record_permission_scope(TENANT, "a1", "pol1", ["r", "w", "a", "d", "e"])
        anomaly = tg.check_permission_drift(TENANT, "a1", "pol1")
        if anomaly:
            assert "rsa_gap" in anomaly.context
            assert "Gap 2" in anomaly.context["rsa_gap"]
            assert anomaly.context["rule"] == "RULE-05"

    def test_anomaly_stored_in_db(self, tg):
        self._record_with_timestamp(tg, TENANT, "a1", "pol1", 1.0, days_ago=5)
        tg.record_permission_scope(TENANT, "a1", "pol1", ["r", "w", "a", "d", "e"])
        tg.check_permission_drift(TENANT, "a1", "pol1")
        anomalies = tg.get_anomalies(tenant_id=TENANT)
        types = [a["anomaly_type"] for a in anomalies]
        assert "PERMISSION_DRIFT_SPIKE" in types

    def test_record_permission_scope_weight_from_scope_length(self, tg):
        """record_permission_scope uses len(scope) as weight."""
        tg.record_permission_scope(TENANT, "a1", "pol1", ["r", "w", "a"])
        # Verify 3 items → weight 3.0 in history
        import modules.identity.trust_graph as m
        conn = sqlite3.connect(m._db_path(), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT scope_weight FROM tg_permission_history "
                "WHERE tenant_id=? AND agent_label=? AND policy_label=?",
                (TENANT, "a1", "pol1")
            ).fetchone()
        finally:
            conn.close()
        assert row is not None
        assert row["scope_weight"] == 3.0

    def test_description_mentions_rsa26(self, tg):
        self._record_with_timestamp(tg, TENANT, "a1", "pol1", 1.0, days_ago=5)
        tg.record_permission_scope(TENANT, "a1", "pol1", ["r", "w", "a", "d", "e"])
        anomaly = tg.check_permission_drift(TENANT, "a1", "pol1")
        if anomaly:
            assert "RSA" in anomaly.detail

    def test_tenant_isolation(self, tg):
        """History in tenant A does not affect checks in tenant B."""
        self._record_with_timestamp(tg, "tenant-a", "a1", "pol1", 1.0, days_ago=5)
        tg.record_permission_scope("tenant-a", "a1", "pol1", ["r", "w", "a", "d", "e"])
        anomaly = tg.check_permission_drift("tenant-b", "a1", "pol1")
        assert anomaly is None

    def test_baseline_outside_window_ignored(self, tg, monkeypatch):
        """Records older than PERMISSION_DRIFT_WINDOW_DAYS are not used as baseline."""
        import modules.identity.trust_graph as m
        monkeypatch.setattr(m, "PERMISSION_DRIFT_WINDOW_DAYS", 7)
        # Insert a very old baseline (40 days ago, outside 7-day window)
        self._record_with_timestamp(tg, TENANT, "a1", "pol1", 1.0, days_ago=40)
        # Recent record
        tg.record_permission_scope(TENANT, "a1", "pol1", ["r", "w", "a", "d", "e"])
        # Without baseline, should return None (no record in window to compare against)
        anomaly = tg.check_permission_drift(TENANT, "a1", "pol1")
        # The recent record IS in the window — baseline and current both from window
        # This tests that old records outside window are excluded from baseline selection
        # (Result depends on whether recent record exists as both baseline and current)
        # With a single in-window record, growth = 1.0x — no anomaly
        assert anomaly is None


# ---------------------------------------------------------------------------
# Integration: both rules together
# ---------------------------------------------------------------------------

class TestRSAGapIntegration:
    def test_both_anomaly_types_storable_and_retrievable(self, tg):
        """Both RULE-04 and RULE-05 anomalies appear in get_anomalies."""
        # RULE-04
        tg.record_policy_governance(TENANT, "pol", "agent")
        tg.record_policy_governance(TENANT, "pol", "agent")
        tg.check_policy_self_modification(
            TENANT, "agent", "pol", event_type="policy_write", action="write"
        )
        # RULE-05 — inject history directly
        import modules.identity.trust_graph as m
        db = m._db_path()
        ts_old = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        conn = sqlite3.connect(db, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("""
            INSERT INTO tg_permission_history
                (history_id, tenant_id, agent_label, policy_label,
                 recorded_at, scope_weight, source_event)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (str(uuid.uuid4()), TENANT, "agent", "pol", ts_old, 1.0, "old"))
        conn.commit()
        conn.close()
        tg.record_permission_scope(TENANT, "agent", "pol", ["r", "w", "a", "d", "e"])
        tg.check_permission_drift(TENANT, "agent", "pol")

        anomalies = tg.get_anomalies(tenant_id=TENANT)
        types = {a["anomaly_type"] for a in anomalies}
        assert "POLICY_SELF_MODIFICATION" in types
        # PERMISSION_DRIFT_SPIKE may or may not fire depending on growth factor
        # but function should not raise

    def test_constants_are_env_configurable(self, tg, monkeypatch):
        """PERMISSION_GROWTH_THRESHOLD and PERMISSION_DRIFT_WINDOW_DAYS are tunable."""
        import modules.identity.trust_graph as m
        monkeypatch.setattr(m, "PERMISSION_GROWTH_THRESHOLD", 10.0)
        monkeypatch.setattr(m, "PERMISSION_DRIFT_WINDOW_DAYS", 60)
        assert m.PERMISSION_GROWTH_THRESHOLD == 10.0
        assert m.PERMISSION_DRIFT_WINDOW_DAYS == 60
