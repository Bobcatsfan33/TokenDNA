"""
Tests for TokenDNA Phase 5-1: MCP Security Gateway

Covers:
  - Session lifecycle (open, close, bind passport)
  - Enforcement modes (audit / flag / block)
  - Tool fingerprinting and drift detection
  - Anomaly detection (Welford baseline, z-score alerting)
  - API routes (where FastAPI app is available)
"""

from __future__ import annotations

import math
import os
import tempfile
import unittest
from unittest.mock import patch

import pytest

# ── Import module under test ─────────────────────────────────────────────────

from modules.identity import mcp_gateway

# ── Helpers ────────────────────────────────────────────────────────────────────


def _tmp_db() -> str:
    """Return a path to a fresh temporary DB for each test."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return path


TENANT = "test-tenant"
AGENT = "agent-001"
SERVER = "mcp://tools.example.com"


# ─────────────────────────────────────────────────────────────────────────────
# 1. Session lifecycle
# ─────────────────────────────────────────────────────────────────────────────


class TestSessionLifecycle(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        mcp_gateway.init_db(self.db)

    def tearDown(self):
        os.unlink(self.db)
        # Reset init flag so other tests start clean
        mcp_gateway._db_initialized = False

    def _open(self, **kwargs):
        defaults = dict(
            tenant_id=TENANT, agent_id=AGENT, server_id=SERVER, mode="audit"
        )
        defaults.update(kwargs)
        return mcp_gateway.open_session(**defaults, db_path=self.db)

    def test_open_session_returns_correct_fields(self):
        s = self._open()
        assert s["tenant_id"] == TENANT
        assert s["agent_id"] == AGENT
        assert s["server_id"] == SERVER
        assert s["mode"] == "audit"
        assert s["status"] == "open"
        assert s["passport_id"] is None
        assert "session_id" in s
        assert "opened_at" in s

    def test_open_session_invalid_mode_raises(self):
        with self.assertRaises(ValueError):
            self._open(mode="invalid")

    def test_close_session(self):
        s = self._open()
        closed = mcp_gateway.close_session(s["session_id"], TENANT, db_path=self.db)
        assert closed["status"] == "closed"
        assert closed["closed_at"] is not None

    def test_close_already_closed_is_idempotent(self):
        s = self._open()
        mcp_gateway.close_session(s["session_id"], TENANT, db_path=self.db)
        # Second close should not raise — row just won't be updated
        closed2 = mcp_gateway.close_session(s["session_id"], TENANT, db_path=self.db)
        assert closed2["status"] == "closed"

    def test_get_session_not_found_raises(self):
        with self.assertRaises(KeyError):
            mcp_gateway.get_session("nonexistent", TENANT, db_path=self.db)

    def test_list_sessions(self):
        s1 = self._open(agent_id="a1")
        s2 = self._open(agent_id="a2")
        mcp_gateway.close_session(s1["session_id"], TENANT, db_path=self.db)
        all_sessions = mcp_gateway.list_sessions(TENANT, db_path=self.db)
        ids = {s["session_id"] for s in all_sessions}
        assert s1["session_id"] in ids
        assert s2["session_id"] in ids

    def test_list_sessions_filter_by_status(self):
        s1 = self._open()
        s2 = self._open()
        mcp_gateway.close_session(s1["session_id"], TENANT, db_path=self.db)
        open_sessions = mcp_gateway.list_sessions(TENANT, status="open", db_path=self.db)
        ids = {s["session_id"] for s in open_sessions}
        assert s1["session_id"] not in ids
        assert s2["session_id"] in ids

    def test_list_sessions_filter_by_agent(self):
        self._open(agent_id="agt-x")
        self._open(agent_id="agt-y")
        result = mcp_gateway.list_sessions(TENANT, agent_id="agt-x", db_path=self.db)
        assert all(s["agent_id"] == "agt-x" for s in result)

    def test_bind_passport(self):
        s = self._open()
        updated = mcp_gateway.bind_passport(
            s["session_id"], TENANT, "passport-abc", db_path=self.db
        )
        assert updated["passport_id"] == "passport-abc"

    def test_bind_passport_session_not_found(self):
        with self.assertRaises(KeyError):
            mcp_gateway.bind_passport("no-such-session", TENANT, "pp-1", db_path=self.db)

    def test_modes_all_accepted(self):
        for mode in ("audit", "flag", "block"):
            s = self._open(mode=mode)
            assert s["mode"] == mode


# ─────────────────────────────────────────────────────────────────────────────
# 2. Enforcement — modes
# ─────────────────────────────────────────────────────────────────────────────


class TestEnforcementModes(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        mcp_gateway.init_db(self.db)
        mcp_gateway._db_initialized = False
        mcp_gateway.init_db(self.db)

    def tearDown(self):
        os.unlink(self.db)
        mcp_gateway._db_initialized = False

    def _session(self, mode="audit", passport_id=None):
        return mcp_gateway.open_session(
            tenant_id=TENANT,
            agent_id=AGENT,
            server_id=SERVER,
            mode=mode,
            passport_id=passport_id,
            db_path=self.db,
        )

    def _enforce(self, session, tool="read_file", params=None, risk_override=None):
        """Helper that patches inspector to return a known risk score."""
        params = params or {"path": "/etc/hosts"}

        def fake_init_db(*a, **kw):
            pass

        if risk_override is not None:

            def fake_inspect(**kwargs):
                return {"risk_score": risk_override, "violations": []}

            with patch("modules.identity.mcp_inspector.init_db", side_effect=fake_init_db), \
                 patch("modules.identity.mcp_inspector.inspect_call", side_effect=fake_inspect):
                return mcp_gateway.enforce(
                    session["session_id"], TENANT, tool, params, db_path=self.db
                )
        with patch("modules.identity.mcp_inspector.init_db", side_effect=fake_init_db):
            return mcp_gateway.enforce(
                session["session_id"], TENANT, tool, params, db_path=self.db
            )

    def test_audit_mode_always_allows(self):
        s = self._session(mode="audit")
        result = self._enforce(s, risk_override=0.99)
        assert result["outcome"] == "allow"
        assert result["blocked"] is False

    def test_flag_mode_below_threshold_allows(self):
        s = self._session(mode="flag")
        result = self._enforce(s, risk_override=0.1)
        assert result["outcome"] == "allow"

    def test_flag_mode_above_threshold_flags(self):
        s = self._session(mode="flag")
        result = self._enforce(s, risk_override=0.6)
        assert result["outcome"] == "flag"
        assert result["blocked"] is False

    def test_flag_mode_does_not_block_even_at_high_risk(self):
        s = self._session(mode="flag")
        result = self._enforce(s, risk_override=0.99)
        assert result["outcome"] == "flag"
        assert result["blocked"] is False

    def test_block_mode_low_risk_allows(self):
        s = self._session(mode="block", passport_id="pp-1")
        result = self._enforce(s, risk_override=0.1)
        assert result["outcome"] == "allow"

    def test_block_mode_medium_risk_flags(self):
        s = self._session(mode="block", passport_id="pp-1")
        result = self._enforce(s, risk_override=0.6)
        assert result["outcome"] == "flag"

    def test_block_mode_high_risk_blocks(self):
        s = self._session(mode="block", passport_id="pp-1")
        result = self._enforce(s, risk_override=0.9)
        assert result["outcome"] == "block"
        assert result["blocked"] is True

    def test_block_mode_no_passport_elevates_risk(self):
        """Block mode without passport binding should add risk."""
        s = self._session(mode="block", passport_id=None)
        result = self._enforce(s, risk_override=0.0)
        # passport_not_bound reason should be in the result
        assert "passport_not_bound" in result["reasons"]

    def test_unknown_session_returns_block(self):
        result = mcp_gateway.enforce("bad-session-id", TENANT, "some_tool", {}, db_path=self.db)
        assert result["outcome"] == "block"
        assert "session_not_found" in result["reasons"]

    def test_closed_session_elevates_risk(self):
        s = self._session(mode="audit")
        mcp_gateway.close_session(s["session_id"], TENANT, db_path=self.db)
        result = mcp_gateway.enforce(
            s["session_id"], TENANT, "read_file", {}, db_path=self.db
        )
        assert "session_closed" in result["reasons"]

    def test_enforcement_is_logged(self):
        s = self._session(mode="flag")
        self._enforce(s, risk_override=0.1)
        log = mcp_gateway.list_enforcements(TENANT, session_id=s["session_id"], db_path=self.db)
        assert len(log) == 1
        assert log[0]["tool_name"] == "read_file"

    def test_list_enforcements_filter_outcome(self):
        s = self._session(mode="block", passport_id="pp-1")
        self._enforce(s, tool="safe_tool", risk_override=0.1)
        self._enforce(s, tool="risky_tool", risk_override=0.9)
        blocks = mcp_gateway.list_enforcements(TENANT, outcome="block", db_path=self.db)
        assert all(e["outcome"] == "block" for e in blocks)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Tool Fingerprinting
# ─────────────────────────────────────────────────────────────────────────────


class TestToolFingerprinting(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        mcp_gateway._db_initialized = False
        mcp_gateway.init_db(self.db)

    def tearDown(self):
        os.unlink(self.db)
        mcp_gateway._db_initialized = False

    def _tools(self, version=1):
        return [
            {
                "name": "read_file",
                "description": f"Reads a file v{version}",
                "input_schema": {"path": "string"},
            },
            {
                "name": "write_file",
                "description": "Writes a file",
                "input_schema": {"path": "string", "content": "string"},
            },
        ]

    def test_first_registration_creates_fingerprints(self):
        result = mcp_gateway.register_manifest(TENANT, SERVER, self._tools(), db_path=self.db)
        assert result["tools_processed"] == 2
        assert result["drift_alerts_raised"] == 0
        statuses = {r["tool_name"]: r["status"] for r in result["registered"]}
        assert statuses["read_file"] == "new"
        assert statuses["write_file"] == "new"

    def test_unchanged_manifest_no_alert(self):
        mcp_gateway.register_manifest(TENANT, SERVER, self._tools(), db_path=self.db)
        result = mcp_gateway.register_manifest(TENANT, SERVER, self._tools(), db_path=self.db)
        assert result["drift_alerts_raised"] == 0
        statuses = {r["tool_name"]: r["status"] for r in result["registered"]}
        assert statuses["read_file"] == "unchanged"

    def test_changed_description_raises_drift_alert(self):
        mcp_gateway.register_manifest(TENANT, SERVER, self._tools(version=1), db_path=self.db)
        result = mcp_gateway.register_manifest(TENANT, SERVER, self._tools(version=2), db_path=self.db)
        assert result["drift_alerts_raised"] >= 1
        statuses = {r["tool_name"]: r["status"] for r in result["registered"]}
        assert statuses["read_file"] == "updated"

    def test_get_fingerprint_returns_current_state(self):
        mcp_gateway.register_manifest(TENANT, SERVER, self._tools(), db_path=self.db)
        fp = mcp_gateway.get_fingerprint(TENANT, SERVER, db_path=self.db)
        assert fp["tool_count"] == 2
        names = {t["tool_name"] for t in fp["tools"]}
        assert "read_file" in names
        assert "write_file" in names

    def test_drift_alerts_listed(self):
        mcp_gateway.register_manifest(TENANT, SERVER, self._tools(1), db_path=self.db)
        mcp_gateway.register_manifest(TENANT, SERVER, self._tools(2), db_path=self.db)
        alerts = mcp_gateway.list_fingerprint_alerts(TENANT, db_path=self.db)
        assert len(alerts) >= 1
        assert all(not a["resolved"] for a in alerts)

    def test_resolve_drift_alert(self):
        mcp_gateway.register_manifest(TENANT, SERVER, self._tools(1), db_path=self.db)
        mcp_gateway.register_manifest(TENANT, SERVER, self._tools(2), db_path=self.db)
        alerts = mcp_gateway.list_fingerprint_alerts(TENANT, db_path=self.db)
        alert_id = alerts[0]["alert_id"]
        resolved = mcp_gateway.resolve_fingerprint_alert(TENANT, alert_id, "admin", db_path=self.db)
        assert resolved["resolved"] is True
        assert resolved["resolved_by"] == "admin"

    def test_resolve_nonexistent_alert_raises(self):
        with self.assertRaises(KeyError):
            mcp_gateway.resolve_fingerprint_alert(TENANT, "bad-id", "admin", db_path=self.db)

    def test_tools_without_name_are_skipped(self):
        tools = [{"description": "no name here"}]
        result = mcp_gateway.register_manifest(TENANT, SERVER, tools, db_path=self.db)
        assert result["tools_processed"] == 0

    def test_multiple_servers_independent(self):
        server2 = "mcp://other.example.com"
        mcp_gateway.register_manifest(TENANT, SERVER, self._tools(1), db_path=self.db)
        mcp_gateway.register_manifest(TENANT, server2, self._tools(1), db_path=self.db)
        fp1 = mcp_gateway.get_fingerprint(TENANT, SERVER, db_path=self.db)
        fp2 = mcp_gateway.get_fingerprint(TENANT, server2, db_path=self.db)
        assert fp1["server_id"] != fp2["server_id"]
        assert fp1["tool_count"] == fp2["tool_count"]


# ─────────────────────────────────────────────────────────────────────────────
# 4. Anomaly Detection
# ─────────────────────────────────────────────────────────────────────────────


class TestAnomalyDetection(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        mcp_gateway._db_initialized = False
        mcp_gateway.init_db(self.db)

    def tearDown(self):
        os.unlink(self.db)
        mcp_gateway._db_initialized = False

    def _call_tool(self, tool_name, n=1, agent_id=AGENT, session_id="sess-001"):
        for _ in range(n):
            mcp_gateway._check_and_update_anomaly(
                tenant_id=TENANT,
                agent_id=agent_id,
                tool_name=tool_name,
                session_id=session_id,
                db_path=self.db,
            )

    def test_first_call_creates_baseline(self):
        self._call_tool("read_file")
        baselines = mcp_gateway.get_anomaly_baseline(TENANT, AGENT, db_path=self.db)
        assert len(baselines) == 1
        assert baselines[0]["tool_name"] == "read_file"
        assert baselines[0]["sample_count"] == 1

    def test_baseline_sample_count_increments(self):
        for _ in range(5):
            self._call_tool("read_file")
        baselines = mcp_gateway.get_anomaly_baseline(TENANT, AGENT, db_path=self.db)
        assert baselines[0]["sample_count"] == 5

    def test_no_anomaly_below_min_samples(self):
        # 4 calls — below ANOMALY_MIN_SAMPLES=5, no z-score alert should fire
        original_min = mcp_gateway.ANOMALY_MIN_SAMPLES
        mcp_gateway.ANOMALY_MIN_SAMPLES = 5
        for i in range(4):
            result = mcp_gateway._check_and_update_anomaly(
                tenant_id=TENANT,
                agent_id=AGENT,
                tool_name="write_file",
                session_id="s-1",
                db_path=self.db,
            )
            if i > 0:  # First call creates first_call alert; subsequent should be None
                assert result is None or result.get("first_call", False)
        mcp_gateway.ANOMALY_MIN_SAMPLES = original_min

    def test_anomaly_alert_listed(self):
        # Force an anomaly alert by mocking the z-score threshold
        original_z = mcp_gateway.ANOMALY_Z_THRESHOLD
        mcp_gateway.ANOMALY_Z_THRESHOLD = 0.0  # everything triggers
        mcp_gateway.ANOMALY_MIN_SAMPLES = 2

        for _ in range(10):
            mcp_gateway._check_and_update_anomaly(
                tenant_id=TENANT,
                agent_id=AGENT,
                tool_name="dangerous_tool",
                session_id="s-x",
                db_path=self.db,
            )
        alerts = mcp_gateway.list_anomaly_alerts(TENANT, db_path=self.db)
        assert len(alerts) >= 1
        mcp_gateway.ANOMALY_Z_THRESHOLD = original_z
        mcp_gateway.ANOMALY_MIN_SAMPLES = 5

    def test_acknowledge_anomaly_alert(self):
        original_z = mcp_gateway.ANOMALY_Z_THRESHOLD
        mcp_gateway.ANOMALY_Z_THRESHOLD = 0.0
        mcp_gateway.ANOMALY_MIN_SAMPLES = 2

        for _ in range(5):
            mcp_gateway._check_and_update_anomaly(
                tenant_id=TENANT,
                agent_id=AGENT,
                tool_name="sus_tool",
                session_id="s-y",
                db_path=self.db,
            )
        alerts = mcp_gateway.list_anomaly_alerts(TENANT, db_path=self.db)
        assert len(alerts) > 0
        alert_id = alerts[0]["alert_id"]
        ack = mcp_gateway.acknowledge_anomaly_alert(TENANT, alert_id, "analyst-1", db_path=self.db)
        assert ack["acknowledged"] is True
        assert ack["acknowledged_by"] == "analyst-1"
        mcp_gateway.ANOMALY_Z_THRESHOLD = original_z
        mcp_gateway.ANOMALY_MIN_SAMPLES = 5

    def test_acknowledge_nonexistent_alert_raises(self):
        with self.assertRaises(KeyError):
            mcp_gateway.acknowledge_anomaly_alert(TENANT, "no-such-id", "admin", db_path=self.db)

    def test_baseline_per_agent_independent(self):
        self._call_tool("tool_a", agent_id="agent-x")
        self._call_tool("tool_a", agent_id="agent-y")
        bx = mcp_gateway.get_anomaly_baseline(TENANT, "agent-x", db_path=self.db)
        by = mcp_gateway.get_anomaly_baseline(TENANT, "agent-y", db_path=self.db)
        assert len(bx) == 1
        assert len(by) == 1

    def test_list_anomaly_alerts_filter_by_agent(self):
        original_z = mcp_gateway.ANOMALY_Z_THRESHOLD
        mcp_gateway.ANOMALY_Z_THRESHOLD = 0.0
        mcp_gateway.ANOMALY_MIN_SAMPLES = 2

        for _ in range(5):
            mcp_gateway._check_and_update_anomaly(
                tenant_id=TENANT,
                agent_id="agent-filter-1",
                tool_name="t1",
                session_id="s1",
                db_path=self.db,
            )
            mcp_gateway._check_and_update_anomaly(
                tenant_id=TENANT,
                agent_id="agent-filter-2",
                tool_name="t1",
                session_id="s2",
                db_path=self.db,
            )

        alerts = mcp_gateway.list_anomaly_alerts(TENANT, agent_id="agent-filter-1", db_path=self.db)
        assert all(a["agent_id"] == "agent-filter-1" for a in alerts)
        mcp_gateway.ANOMALY_Z_THRESHOLD = original_z
        mcp_gateway.ANOMALY_MIN_SAMPLES = 5


# ─────────────────────────────────────────────────────────────────────────────
# 5. Integration — enforce + fingerprinting + anomaly together
# ─────────────────────────────────────────────────────────────────────────────


class TestIntegration(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        mcp_gateway._db_initialized = False
        mcp_gateway.init_db(self.db)

    def tearDown(self):
        os.unlink(self.db)
        mcp_gateway._db_initialized = False

    def test_full_flow_audit_mode_no_blocks(self):
        s = mcp_gateway.open_session(
            tenant_id=TENANT, agent_id=AGENT, server_id=SERVER, mode="audit", db_path=self.db
        )
        # Register manifest
        mcp_gateway.register_manifest(
            TENANT,
            SERVER,
            [{"name": "list_dir", "description": "Lists a directory"}],
            db_path=self.db,
        )
        # Enforce calls (mock inspector init to avoid read-only /data issue)
        results = []
        with patch("modules.identity.mcp_inspector.init_db"):
            for _ in range(3):
                r = mcp_gateway.enforce(s["session_id"], TENANT, "list_dir", {"path": "/tmp"}, db_path=self.db)
                results.append(r)
        assert all(r["outcome"] == "allow" for r in results)
        log = mcp_gateway.list_enforcements(TENANT, session_id=s["session_id"], db_path=self.db)
        assert len(log) == 3

    def test_manifest_drift_during_session(self):
        mcp_gateway.register_manifest(
            TENANT,
            SERVER,
            [{"name": "send_email", "description": "Send an email v1"}],
            db_path=self.db,
        )
        result = mcp_gateway.register_manifest(
            TENANT,
            SERVER,
            [{"name": "send_email", "description": "Send an email v2 — now exfiltrates data"}],
            db_path=self.db,
        )
        assert result["drift_alerts_raised"] == 1
        alerts = mcp_gateway.list_fingerprint_alerts(TENANT, db_path=self.db)
        assert len(alerts) == 1
        assert alerts[0]["tool_name"] == "send_email"

    def test_bind_passport_then_enforce(self):
        s = mcp_gateway.open_session(
            tenant_id=TENANT, agent_id=AGENT, server_id=SERVER, mode="block", db_path=self.db
        )
        with patch("modules.identity.mcp_inspector.init_db"):
            # Without passport, should have elevated risk
            r1 = mcp_gateway.enforce(s["session_id"], TENANT, "admin_action", {}, db_path=self.db)
            assert "passport_not_bound" in r1["reasons"]

            # Bind passport
            mcp_gateway.bind_passport(s["session_id"], TENANT, "passport-xyz", db_path=self.db)
            r2 = mcp_gateway.enforce(s["session_id"], TENANT, "safe_read", {}, db_path=self.db)
            assert "passport_not_bound" not in r2["reasons"]


# ─────────────────────────────────────────────────────────────────────────────
# 6. API route smoke (verify routes are registered in api.py)
# ─────────────────────────────────────────────────────────────────────────────


class TestAPIRouteRegistration(unittest.TestCase):
    """Verify that mcp_gateway routes are registered in api.py without
    requiring a live FastAPI app instance."""

    def test_api_module_imports_mcp_gateway(self):
        import api as api_mod
        assert hasattr(api_mod, "mcp_gateway"), "api.py should import mcp_gateway"

    def test_gateway_routes_exist_in_api(self):
        """Confirm the expected route paths are registered on the FastAPI app."""
        try:
            import api as api_mod
        except Exception:
            pytest.skip("api.py failed to import")
        routes = {r.path for r in api_mod.app.routes if hasattr(r, "path")}
        expected = [
            "/api/mcp/gateway/session/open",
            "/api/mcp/gateway/sessions",
            "/api/mcp/gateway/enforce",
            "/api/mcp/fingerprint/register",
            "/api/mcp/fingerprint/alerts",
            "/api/mcp/anomaly/alerts",
        ]
        for path in expected:
            assert path in routes, f"Missing route: {path}"


if __name__ == "__main__":
    unittest.main()
