"""
Tests for TokenDNA Phase 5-3 Part 2: Behavioral DNA Drift Detection

Covers:
  - Event recording and audit trail
  - Baseline learning (Welford algorithm)
  - Drift score computation
  - Drift alert creation and deduplication
  - Snapshot creation
  - Drift alert acknowledgement
  - API route registration smoke
"""

from __future__ import annotations

import os
import tempfile
import unittest

import pytest

from modules.identity import behavioral_dna

TENANT = "bd-tenant"
AGENT = "bd-agent-001"


def _tmp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return path


def _reset():
    behavioral_dna._db_initialized = False


# ─────────────────────────────────────────────────────────────────────────────
# 1. Event Recording
# ─────────────────────────────────────────────────────────────────────────────


class TestEventRecording(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        _reset()
        behavioral_dna.init_db(self.db)

    def tearDown(self):
        os.unlink(self.db)
        _reset()

    def _event(self, tool_name="read_file", action_type="read", resource="/data/file.txt"):
        return behavioral_dna.record_event(
            TENANT, AGENT, "tool_call",
            tool_name=tool_name, action_type=action_type, resource=resource,
            db_path=self.db
        )

    def test_event_returns_correct_fields(self):
        ev = self._event()
        assert ev["tenant_id"] == TENANT
        assert ev["agent_id"] == AGENT
        assert ev["event_type"] == "tool_call"
        assert ev["tool_name"] == "read_file"
        assert "event_id" in ev
        assert "created_at" in ev
        assert "hour_of_day" in ev
        assert "day_of_week" in ev

    def test_multiple_events_recorded(self):
        for _ in range(5):
            self._event()
        trail = behavioral_dna.get_audit_trail(TENANT, AGENT, db_path=self.db)
        assert len(trail) == 5

    def test_audit_trail_limit_respected(self):
        for _ in range(10):
            self._event()
        trail = behavioral_dna.get_audit_trail(TENANT, AGENT, limit=3, db_path=self.db)
        assert len(trail) == 3

    def test_audit_trail_ordered_newest_first(self):
        self._event(tool_name="tool_a")
        self._event(tool_name="tool_b")
        trail = behavioral_dna.get_audit_trail(TENANT, AGENT, db_path=self.db)
        assert trail[0]["tool_name"] == "tool_b"

    def test_params_hash_computed(self):
        ev = behavioral_dna.record_event(
            TENANT, AGENT, "tool_call",
            params={"path": "/tmp", "mode": "read"},
            db_path=self.db
        )
        assert ev["event_id"]  # just confirms no crash with params

    def test_tenant_isolation(self):
        self._event()
        behavioral_dna.record_event("other-tenant", "other-agent", "tool_call", db_path=self.db)
        trail = behavioral_dna.get_audit_trail(TENANT, AGENT, db_path=self.db)
        assert len(trail) == 1


# ─────────────────────────────────────────────────────────────────────────────
# 2. Baseline Learning
# ─────────────────────────────────────────────────────────────────────────────


class TestBaselineLearning(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        _reset()
        behavioral_dna.init_db(self.db)

    def tearDown(self):
        os.unlink(self.db)
        _reset()

    def _fire_events(self, n, tool_name="read_file", resource="/data"):
        for _ in range(n):
            behavioral_dna.record_event(
                TENANT, AGENT, "tool_call",
                tool_name=tool_name, resource=resource, action_type="read",
                db_path=self.db
            )

    def test_baseline_starts_empty(self):
        b = behavioral_dna.get_baseline(TENANT, AGENT, db_path=self.db)
        assert b["total_samples"] == 0
        assert b["stable"] is False

    def test_baseline_populated_after_events(self):
        self._fire_events(5)
        b = behavioral_dna.get_baseline(TENANT, AGENT, db_path=self.db)
        assert "tool_name" in b["dimensions"]
        assert any(e["value"] == "read_file" for e in b["dimensions"]["tool_name"])

    def test_baseline_sample_count_increments(self):
        self._fire_events(10)
        b = behavioral_dna.get_baseline(TENANT, AGENT, db_path=self.db)
        entry = next(e for e in b["dimensions"]["tool_name"] if e["value"] == "read_file")
        assert entry["sample_count"] == 10

    def test_baseline_stable_after_min_samples(self):
        min_s = behavioral_dna.MIN_BASELINE_SAMPLES
        self._fire_events(min_s)
        b = behavioral_dna.get_baseline(TENANT, AGENT, db_path=self.db)
        assert b["stable"] is True

    def test_multiple_tools_tracked_independently(self):
        self._fire_events(5, tool_name="read_file")
        self._fire_events(3, tool_name="write_file")
        b = behavioral_dna.get_baseline(TENANT, AGENT, db_path=self.db)
        tool_entries = {e["value"]: e for e in b["dimensions"]["tool_name"]}
        assert "read_file" in tool_entries
        assert "write_file" in tool_entries
        assert tool_entries["read_file"]["sample_count"] == 5
        assert tool_entries["write_file"]["sample_count"] == 3

    def test_hour_dimension_tracked(self):
        self._fire_events(5)
        b = behavioral_dna.get_baseline(TENANT, AGENT, db_path=self.db)
        assert "hour_of_day" in b["dimensions"]

    def test_baseline_per_agent_isolated(self):
        self._fire_events(5, tool_name="tool-a")
        behavioral_dna.record_event(TENANT, "other-agent", "tool_call", tool_name="tool-b", db_path=self.db)
        b = behavioral_dna.get_baseline(TENANT, AGENT, db_path=self.db)
        tool_names = [e["value"] for e in b["dimensions"].get("tool_name", [])]
        assert "tool-a" in tool_names
        assert "tool-b" not in tool_names


# ─────────────────────────────────────────────────────────────────────────────
# 3. Drift Scoring
# ─────────────────────────────────────────────────────────────────────────────


class TestDriftScoring(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        _reset()
        behavioral_dna.init_db(self.db)

    def tearDown(self):
        os.unlink(self.db)
        _reset()

    def test_drift_score_insufficient_data(self):
        result = behavioral_dna.compute_drift_score(TENANT, AGENT, db_path=self.db)
        assert result["drift_score"] == 0.0
        assert result["status"] == "insufficient_data"

    def test_drift_score_computed_after_min_samples(self):
        # Use two different tools to create non-trivial proportions
        for i in range(behavioral_dna.MIN_BASELINE_SAMPLES + 2):
            tool = "tool_a" if i % 2 == 0 else "tool_b"
            behavioral_dna.record_event(
                TENANT, AGENT, "tool_call",
                tool_name=tool, action_type="read",
                db_path=self.db
            )
        result = behavioral_dna.compute_drift_score(TENANT, AGENT, db_path=self.db)
        assert "drift_score" in result
        assert 0.0 <= result["drift_score"] <= 1.0

    def test_drift_score_returns_status(self):
        # Two tools create non-trivial proportions so drift score is computable
        for i in range(behavioral_dna.MIN_BASELINE_SAMPLES + 2):
            tool = "tool_a" if i % 3 == 0 else "tool_b"
            behavioral_dna.record_event(TENANT, AGENT, "tool_call", tool_name=tool, db_path=self.db)
        result = behavioral_dna.compute_drift_score(TENANT, AGENT, db_path=self.db)
        assert result["status"] in ("normal", "above_threshold")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Drift Alerts
# ─────────────────────────────────────────────────────────────────────────────


class TestDriftAlerts(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        _reset()
        behavioral_dna.init_db(self.db)
        # Force a low threshold so alerts fire easily in tests
        self._orig_threshold = behavioral_dna.DRIFT_ALERT_THRESHOLD
        self._orig_min = behavioral_dna.MIN_BASELINE_SAMPLES
        behavioral_dna.DRIFT_ALERT_THRESHOLD = 0.0
        behavioral_dna.MIN_BASELINE_SAMPLES = 2

    def tearDown(self):
        os.unlink(self.db)
        behavioral_dna.DRIFT_ALERT_THRESHOLD = self._orig_threshold
        behavioral_dna.MIN_BASELINE_SAMPLES = self._orig_min
        _reset()

    def _fire(self, n=6, agent=AGENT):
        """Fire events with two tools to create non-trivial proportions."""
        for i in range(n):
            tool = "common_tool" if i < n - 1 else "rare_tool"
            behavioral_dna.record_event(TENANT, agent, "tool_call", tool_name=tool, db_path=self.db)

    def test_drift_alert_created(self):
        self._fire()
        alerts = behavioral_dna.list_drift_alerts(TENANT, db_path=self.db)
        assert len(alerts) >= 1

    def test_drift_alert_not_duplicated_while_open(self):
        # Fire many events — should still have only one unacknowledged alert
        for i in range(12):
            tool = "tool_majority" if i < 9 else "tool_minority"
            behavioral_dna.record_event(TENANT, AGENT, "tool_call", tool_name=tool, db_path=self.db)
        alerts = behavioral_dna.list_drift_alerts(TENANT, db_path=self.db)
        assert len(alerts) == 1  # deduplication: only one unacknowledged alert

    def test_acknowledge_drift_alert(self):
        self._fire()
        alerts = behavioral_dna.list_drift_alerts(TENANT, db_path=self.db)
        ack = behavioral_dna.acknowledge_drift_alert(
            TENANT, alerts[0]["alert_id"], "analyst", db_path=self.db
        )
        assert ack["acknowledged"] is True
        assert ack["acknowledged_by"] == "analyst"

    def test_new_alert_after_acknowledgement(self):
        self._fire()
        alerts = behavioral_dna.list_drift_alerts(TENANT, db_path=self.db)
        behavioral_dna.acknowledge_drift_alert(TENANT, alerts[0]["alert_id"], "analyst", db_path=self.db)
        # New events create a new alert (no longer deduplicated — prior was acked)
        self._fire()
        new_alerts = behavioral_dna.list_drift_alerts(TENANT, db_path=self.db)
        assert len(new_alerts) >= 1

    def test_acknowledge_nonexistent_raises(self):
        with self.assertRaises(KeyError):
            behavioral_dna.acknowledge_drift_alert(TENANT, "bad-id", "analyst", db_path=self.db)

    def test_list_drift_alerts_filter_agent(self):
        self._fire(agent="agent-x") if False else None
        for _ in range(5):
            behavioral_dna.record_event(TENANT, "agent-x", "tool_call", tool_name="t", db_path=self.db)
            behavioral_dna.record_event(TENANT, "agent-y", "tool_call", tool_name="t", db_path=self.db)
        alerts_x = behavioral_dna.list_drift_alerts(TENANT, agent_id="agent-x", db_path=self.db)
        assert all(a["agent_id"] == "agent-x" for a in alerts_x)


# ─────────────────────────────────────────────────────────────────────────────
# 5. Snapshots
# ─────────────────────────────────────────────────────────────────────────────


class TestSnapshots(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        _reset()
        behavioral_dna.init_db(self.db)

    def tearDown(self):
        os.unlink(self.db)
        _reset()

    def test_take_snapshot_returns_profile(self):
        behavioral_dna.record_event(TENANT, AGENT, "tool_call", tool_name="t1", db_path=self.db)
        snap = behavioral_dna.take_snapshot(TENANT, AGENT, trigger="manual", db_path=self.db)
        assert snap["trigger"] == "manual"
        assert "snapshot_id" in snap
        assert "baseline" in snap["snapshot"]
        assert "drift" in snap["snapshot"]

    def test_snapshot_trigger_recorded(self):
        snap = behavioral_dna.take_snapshot(TENANT, AGENT, trigger="drift_detected", db_path=self.db)
        assert snap["trigger"] == "drift_detected"

    def test_empty_agent_snapshot_ok(self):
        # Should not raise even with no events
        snap = behavioral_dna.take_snapshot(TENANT, "new-agent", db_path=self.db)
        assert snap["snapshot"]["drift"]["drift_score"] == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# 6. API Route Registration Smoke
# ─────────────────────────────────────────────────────────────────────────────


class TestAPIRouteRegistration(unittest.TestCase):

    def test_api_imports_behavioral_dna(self):
        import api as api_mod
        assert hasattr(api_mod, "behavioral_dna")

    def test_behavioral_routes_registered(self):
        try:
            import api as api_mod
        except Exception:
            pytest.skip("api.py failed to import")
        routes = {r.path for r in api_mod.app.routes if hasattr(r, "path")}
        expected = [
            "/api/behavioral/event",
            "/api/behavioral/alerts",
        ]
        for path in expected:
            assert path in routes, f"Missing route: {path}"


if __name__ == "__main__":
    unittest.main()
