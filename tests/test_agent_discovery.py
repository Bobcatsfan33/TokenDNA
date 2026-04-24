"""
Tests for TokenDNA Phase 5-2: Agent Discovery & Inventory

Covers:
  - Agent registration and metadata
  - Agent census (list, filter, summary)
  - Lifecycle state machine (all valid + invalid transitions)
  - Provider scan adapter injection + shadow agent detection
  - Metadata drift detection
  - Shadow alert acknowledgement
  - API route registration smoke test
"""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

import pytest

from modules.identity import agent_discovery
from modules.identity.agent_discovery import AgentRecord, ProviderAdapter

# ── Helpers ────────────────────────────────────────────────────────────────────

TENANT = "disc-tenant"
OWNER = "owner-001"


def _tmp_db() -> str:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return path


def _reset():
    agent_discovery._db_initialized = False


# ─────────────────────────────────────────────────────────────────────────────
# 1. Agent Registration
# ─────────────────────────────────────────────────────────────────────────────


class TestAgentRegistration(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        _reset()
        agent_discovery.init_db(self.db)

    def tearDown(self):
        os.unlink(self.db)
        _reset()

    def _register(self, **kwargs):
        defaults = dict(
            tenant_id=TENANT,
            name="test-agent",
            provider="anthropic",
            model="claude-3-opus",
            owner_id=OWNER,
        )
        defaults.update(kwargs)
        return agent_discovery.register_agent(**defaults, db_path=self.db)

    def test_register_returns_correct_fields(self):
        a = self._register()
        assert a["tenant_id"] == TENANT
        assert a["name"] == "test-agent"
        assert a["provider"] == "anthropic"
        assert a["model"] == "claude-3-opus"
        assert a["status"] == "provisioned"
        assert a["discovery_method"] == "registered"
        assert "agent_id" in a
        assert "registered_at" in a

    def test_register_invalid_provider_raises(self):
        with self.assertRaises(ValueError):
            self._register(provider="nonexistent-provider")

    def test_register_invalid_discovery_method_raises(self):
        with self.assertRaises(ValueError):
            agent_discovery.register_agent(
                tenant_id=TENANT, name="x", provider="openai",
                discovery_method="bad-method", db_path=self.db
            )

    def test_register_with_tools(self):
        a = self._register(tools=["web_search", "code_interpreter"])
        assert "web_search" in a["tools"]
        assert "code_interpreter" in a["tools"]

    def test_register_with_permissions(self):
        a = self._register(permissions={"read": True, "write": False})
        assert a["permissions"]["read"] is True

    def test_register_with_metadata(self):
        a = self._register(metadata={"environment": "production", "cost_center": "eng"})
        assert a["metadata"]["environment"] == "production"

    def test_get_agent_not_found_raises(self):
        with self.assertRaises(KeyError):
            agent_discovery.get_agent("no-such-id", TENANT, db_path=self.db)

    def test_get_agent_wrong_tenant_raises(self):
        a = self._register()
        with self.assertRaises(KeyError):
            agent_discovery.get_agent(a["agent_id"], "other-tenant", db_path=self.db)

    def test_all_providers_accepted(self):
        for p in agent_discovery.PROVIDERS:
            a = agent_discovery.register_agent(
                tenant_id=TENANT, name=f"agent-{p}", provider=p, db_path=self.db
            )
            assert a["provider"] == p

    def test_update_agent_name(self):
        a = self._register()
        updated = agent_discovery.update_agent(
            a["agent_id"], TENANT, name="renamed-agent", db_path=self.db
        )
        assert updated["name"] == "renamed-agent"

    def test_update_agent_model(self):
        a = self._register()
        updated = agent_discovery.update_agent(
            a["agent_id"], TENANT, model="claude-3-5-sonnet", db_path=self.db
        )
        assert updated["model"] == "claude-3-5-sonnet"

    def test_update_agent_partial_preserves_other_fields(self):
        a = self._register(tools=["tool-a", "tool-b"])
        updated = agent_discovery.update_agent(a["agent_id"], TENANT, model="gpt-4o", db_path=self.db)
        assert updated["tools"] == ["tool-a", "tool-b"]
        assert updated["model"] == "gpt-4o"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Agent Census
# ─────────────────────────────────────────────────────────────────────────────


class TestAgentCensus(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        _reset()
        agent_discovery.init_db(self.db)
        # Register a mix of agents
        agent_discovery.register_agent(
            tenant_id=TENANT, name="bedrock-1", provider="aws_bedrock",
            owner_id="alice", db_path=self.db
        )
        agent_discovery.register_agent(
            tenant_id=TENANT, name="openai-1", provider="openai",
            owner_id="bob", db_path=self.db
        )
        agent_discovery.register_agent(
            tenant_id=TENANT, name="anthropic-1", provider="anthropic",
            owner_id="alice", db_path=self.db
        )
        # Different tenant — should never appear in TENANT results
        agent_discovery.register_agent(
            tenant_id="other-tenant", name="other-1", provider="openai",
            db_path=self.db
        )

    def tearDown(self):
        os.unlink(self.db)
        _reset()

    def test_list_agents_all(self):
        agents = agent_discovery.list_agents(TENANT, db_path=self.db)
        assert len(agents) == 3

    def test_list_agents_filter_provider(self):
        agents = agent_discovery.list_agents(TENANT, provider="openai", db_path=self.db)
        assert len(agents) == 1
        assert agents[0]["provider"] == "openai"

    def test_list_agents_filter_owner(self):
        agents = agent_discovery.list_agents(TENANT, owner_id="alice", db_path=self.db)
        assert len(agents) == 2

    def test_list_agents_filter_status(self):
        agents = agent_discovery.list_agents(TENANT, status="provisioned", db_path=self.db)
        assert len(agents) == 3

    def test_tenant_isolation(self):
        other = agent_discovery.list_agents("other-tenant", db_path=self.db)
        assert len(other) == 1
        assert other[0]["name"] == "other-1"

    def test_census_summary_totals(self):
        summary = agent_discovery.census_summary(TENANT, db_path=self.db)
        assert summary["total_agents"] == 3
        assert summary["by_provider"]["openai"] == 1
        assert summary["by_provider"]["aws_bedrock"] == 1
        assert summary["by_status"]["provisioned"] == 3

    def test_census_summary_shadow_count(self):
        summary = agent_discovery.census_summary(TENANT, db_path=self.db)
        assert summary["shadow_alerts"] == 0

    def test_list_agents_limit_respected(self):
        agents = agent_discovery.list_agents(TENANT, limit=2, db_path=self.db)
        assert len(agents) <= 2


# ─────────────────────────────────────────────────────────────────────────────
# 3. Lifecycle State Machine
# ─────────────────────────────────────────────────────────────────────────────


class TestLifecycle(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        _reset()
        agent_discovery.init_db(self.db)
        self.agent = agent_discovery.register_agent(
            tenant_id=TENANT, name="lifecycle-agent", provider="openai",
            db_path=self.db
        )

    def tearDown(self):
        os.unlink(self.db)
        _reset()

    def _transition(self, to_status, actor="ops-team", approved_by=None, reason=""):
        return agent_discovery.transition_lifecycle(
            self.agent["agent_id"], TENANT, to_status, actor,
            reason=reason, approved_by=approved_by, db_path=self.db
        )

    def test_provisioned_to_active(self):
        updated = self._transition("active")
        assert updated["status"] == "active"

    def test_active_to_suspended(self):
        self._transition("active")
        updated = self._transition("suspended", reason="incident-response")
        assert updated["status"] == "suspended"

    def test_suspended_to_active(self):
        self._transition("active")
        self._transition("suspended")
        updated = self._transition("active", approved_by="security-lead")
        assert updated["status"] == "active"

    def test_active_to_decommissioned_requires_approved_by(self):
        self._transition("active")
        with self.assertRaises(ValueError):
            self._transition("decommissioned")  # no approved_by

    def test_active_to_decommissioned_with_approval(self):
        self._transition("active")
        updated = self._transition("decommissioned", approved_by="cto")
        assert updated["status"] == "decommissioned"

    def test_decommissioned_is_terminal(self):
        self._transition("active")
        self._transition("decommissioned", approved_by="cto")
        with self.assertRaises(ValueError):
            self._transition("active")  # can't leave decommissioned

    def test_invalid_transition_raises(self):
        # provisioned → suspended is not a valid transition
        with self.assertRaises(ValueError):
            self._transition("suspended")

    def test_transition_requires_actor(self):
        with self.assertRaises(ValueError):
            agent_discovery.transition_lifecycle(
                self.agent["agent_id"], TENANT, "active", "",
                db_path=self.db
            )

    def test_unknown_status_raises(self):
        with self.assertRaises(ValueError):
            self._transition("archived")

    def test_lifecycle_history_recorded(self):
        self._transition("active")
        self._transition("suspended", reason="security-hold")
        history = agent_discovery.get_lifecycle_history(
            self.agent["agent_id"], TENANT, db_path=self.db
        )
        assert len(history) == 2
        assert history[0]["from_status"] == "provisioned"
        assert history[0]["to_status"] == "active"
        assert history[1]["reason"] == "security-hold"

    def test_auto_transition_on_first_activity(self):
        agent_discovery.record_activity(self.agent["agent_id"], TENANT, db_path=self.db)
        updated = agent_discovery.get_agent(self.agent["agent_id"], TENANT, db_path=self.db)
        assert updated["status"] == "active"
        history = agent_discovery.get_lifecycle_history(
            self.agent["agent_id"], TENANT, db_path=self.db
        )
        assert history[-1]["actor_id"] == "system"

    def test_activity_on_nonexistent_agent_is_noop(self):
        # Should not raise
        agent_discovery.record_activity("no-such-agent", TENANT, db_path=self.db)

    def test_history_approval_recorded(self):
        self._transition("active")
        self._transition("decommissioned", approved_by="board-approval")
        history = agent_discovery.get_lifecycle_history(
            self.agent["agent_id"], TENANT, db_path=self.db
        )
        decomm = history[-1]
        assert decomm["approved_by"] == "board-approval"
        assert decomm["approved_at"] is not None


# ─────────────────────────────────────────────────────────────────────────────
# 4. Provider Scan + Shadow Detection
# ─────────────────────────────────────────────────────────────────────────────


class MockAdapter(ProviderAdapter):
    """Injected adapter that returns a controlled list of AgentRecords."""

    provider = "openai"

    def __init__(self, records):
        self._records = records

    def scan(self, credentials):
        return self._records


class TestProviderScan(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        _reset()
        agent_discovery.init_db(self.db)

    def tearDown(self):
        os.unlink(self.db)
        _reset()
        # Restore default adapter
        agent_discovery._ADAPTERS["openai"] = agent_discovery.OpenAIAdapter()

    def _inject(self, records):
        agent_discovery.register_adapter(MockAdapter(records))

    def test_scan_empty_provider_returns_complete(self):
        self._inject([])
        result = agent_discovery.run_scan(TENANT, "openai", {}, db_path=self.db)
        assert result["status"] == "complete"
        assert result["agents_found"] == 0

    def test_scan_new_agents_registered(self):
        self._inject([
            AgentRecord(name="gpt-assistant", provider="openai", model="gpt-4o", external_id="asst_001"),
        ])
        result = agent_discovery.run_scan(TENANT, "openai", {}, db_path=self.db)
        assert result["new_agents"] == 1
        agents = agent_discovery.list_agents(TENANT, db_path=self.db)
        assert len(agents) == 1
        assert agents[0]["name"] == "gpt-assistant"
        assert agents[0]["discovery_method"] == "scanned"

    def test_scan_new_agents_flagged_as_shadow(self):
        self._inject([
            AgentRecord(name="unknown-agent", provider="openai", external_id="asst_002"),
        ])
        agent_discovery.run_scan(TENANT, "openai", {}, db_path=self.db)
        alerts = agent_discovery.list_shadow_alerts(TENANT, db_path=self.db)
        assert len(alerts) == 1
        assert "discovered_by_scan_not_registered" in alerts[0]["reason"]

    def test_scan_unchanged_existing_no_shadow_alert(self):
        # Pre-register the agent that the scan will find
        agent_discovery.register_agent(
            tenant_id=TENANT, name="known-agent", provider="openai",
            model="gpt-4o", external_id="asst_003", db_path=self.db
        )
        self._inject([
            AgentRecord(name="known-agent", provider="openai", model="gpt-4o", external_id="asst_003"),
        ])
        agent_discovery.run_scan(TENANT, "openai", {}, db_path=self.db)
        alerts = agent_discovery.list_shadow_alerts(TENANT, db_path=self.db)
        assert len(alerts) == 0

    def test_scan_model_drift_raises_shadow_alert(self):
        agent_discovery.register_agent(
            tenant_id=TENANT, name="drifted-agent", provider="openai",
            model="gpt-4o", external_id="asst_004", db_path=self.db
        )
        # Scan returns the same external_id but different model
        self._inject([
            AgentRecord(
                name="drifted-agent", provider="openai",
                model="gpt-4-turbo",  # changed!
                external_id="asst_004"
            ),
        ])
        agent_discovery.run_scan(TENANT, "openai", {}, db_path=self.db)
        alerts = agent_discovery.list_shadow_alerts(TENANT, db_path=self.db)
        assert len(alerts) == 1
        assert "model_changed" in alerts[0]["reason"]

    def test_scan_multiple_agents_mixed(self):
        # One known, one new
        agent_discovery.register_agent(
            tenant_id=TENANT, name="known", provider="openai",
            external_id="asst_010", db_path=self.db
        )
        self._inject([
            AgentRecord(name="known", provider="openai", external_id="asst_010"),
            AgentRecord(name="unknown", provider="openai", external_id="asst_011"),
        ])
        result = agent_discovery.run_scan(TENANT, "openai", {}, db_path=self.db)
        assert result["agents_found"] == 2
        assert result["new_agents"] == 1
        assert result["shadow_agents"] == 1

    def test_scan_invalid_provider_raises(self):
        with self.assertRaises(ValueError):
            agent_discovery.run_scan(TENANT, "unknown-cloud", {}, db_path=self.db)

    def test_scan_history_recorded(self):
        self._inject([])
        agent_discovery.run_scan(TENANT, "openai", {}, db_path=self.db)
        scans = agent_discovery.list_scans(TENANT, db_path=self.db)
        assert len(scans) == 1
        assert scans[0]["provider"] == "openai"
        assert scans[0]["status"] == "complete"

    def test_get_scan_not_found_raises(self):
        with self.assertRaises(KeyError):
            agent_discovery.get_scan("no-such-scan", TENANT, db_path=self.db)


# ─────────────────────────────────────────────────────────────────────────────
# 5. Shadow Alert Management
# ─────────────────────────────────────────────────────────────────────────────


class TestShadowAlerts(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        _reset()
        agent_discovery.init_db(self.db)
        # Register + scan to create a shadow alert
        agent_discovery.register_adapter(MockAdapter([
            AgentRecord(name="shadow-agent", provider="openai", external_id="asst_shadow"),
        ]))
        agent_discovery.run_scan(TENANT, "openai", {}, db_path=self.db)

    def tearDown(self):
        os.unlink(self.db)
        _reset()
        agent_discovery._ADAPTERS["openai"] = agent_discovery.OpenAIAdapter()

    def test_shadow_alert_exists(self):
        alerts = agent_discovery.list_shadow_alerts(TENANT, db_path=self.db)
        assert len(alerts) == 1
        assert alerts[0]["acknowledged"] is False

    def test_acknowledge_shadow_alert(self):
        alerts = agent_discovery.list_shadow_alerts(TENANT, db_path=self.db)
        ack = agent_discovery.acknowledge_shadow_alert(
            TENANT, alerts[0]["alert_id"], "security-analyst", db_path=self.db
        )
        assert ack["acknowledged"] is True
        assert ack["acknowledged_by"] == "security-analyst"

    def test_acknowledged_alerts_not_in_default_list(self):
        alerts = agent_discovery.list_shadow_alerts(TENANT, db_path=self.db)
        agent_discovery.acknowledge_shadow_alert(
            TENANT, alerts[0]["alert_id"], "analyst", db_path=self.db
        )
        open_alerts = agent_discovery.list_shadow_alerts(TENANT, db_path=self.db)
        assert len(open_alerts) == 0

    def test_acknowledged_alerts_in_acknowledged_list(self):
        alerts = agent_discovery.list_shadow_alerts(TENANT, db_path=self.db)
        agent_discovery.acknowledge_shadow_alert(
            TENANT, alerts[0]["alert_id"], "analyst", db_path=self.db
        )
        acked = agent_discovery.list_shadow_alerts(TENANT, acknowledged=True, db_path=self.db)
        assert len(acked) == 1

    def test_acknowledge_nonexistent_raises(self):
        with self.assertRaises(KeyError):
            agent_discovery.acknowledge_shadow_alert(TENANT, "no-id", "analyst", db_path=self.db)


# ─────────────────────────────────────────────────────────────────────────────
# 6. API Route Registration Smoke
# ─────────────────────────────────────────────────────────────────────────────


class TestAPIRouteRegistration(unittest.TestCase):

    def test_api_module_imports_agent_discovery(self):
        import api as api_mod
        assert hasattr(api_mod, "agent_discovery")

    def test_discovery_routes_registered(self):
        try:
            import api as api_mod
        except Exception:
            pytest.skip("api.py failed to import")
        routes = {r.path for r in api_mod.app.routes if hasattr(r, "path")}
        expected = [
            "/api/discovery/agents/register",
            "/api/discovery/agents",
            "/api/discovery/agents/summary",
            "/api/discovery/scan",
            "/api/discovery/scans",
            "/api/discovery/shadow",
        ]
        for path in expected:
            assert path in routes, f"Missing route: {path}"


if __name__ == "__main__":
    unittest.main()
