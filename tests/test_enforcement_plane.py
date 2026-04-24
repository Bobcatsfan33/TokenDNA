"""
Tests for TokenDNA Phase 5-3 Part 1: Real-Time Policy Enforcement Plane

Covers:
  - Policy CRUD (create, get, list, update, deactivate)
  - Rule evaluation (all operators, logic modes)
  - Enforcement modes (shadow, enforce, canary)
  - Kill switch (activate, deactivate, status, blocks evaluation)
  - Shadow report
  - Decision logging
  - API route registration smoke
"""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

import pytest

from modules.identity import enforcement_plane

TENANT = "ep-tenant"
AGENT = "agent-ep-001"


def _tmp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return path


def _reset():
    enforcement_plane._db_initialized = False


# ─────────────────────────────────────────────────────────────────────────────
# 1. Policy CRUD
# ─────────────────────────────────────────────────────────────────────────────


class TestPolicyCRUD(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        _reset()
        enforcement_plane.init_db(self.db)

    def tearDown(self):
        os.unlink(self.db)
        _reset()

    def _rule(self, decision="block", op="eq", field="action_type", value="delete"):
        return {
            "conditions": [{"field": field, "op": op, "value": value}],
            "logic": "all",
            "decision": decision,
            "risk_score": 0.9,
        }

    def _policy(self, **kwargs):
        defaults = dict(
            tenant_id=TENANT, name="test-policy",
            rules=[self._rule()], mode="shadow",
        )
        defaults.update(kwargs)
        return enforcement_plane.create_policy(**defaults, db_path=self.db)

    def test_create_policy_fields(self):
        p = self._policy()
        assert p["name"] == "test-policy"
        assert p["mode"] == "shadow"
        assert p["status"] == "active"
        assert p["canary_pct"] == 0.0
        assert "policy_id" in p

    def test_invalid_mode_raises(self):
        with self.assertRaises(ValueError):
            self._policy(mode="invalid")

    def test_invalid_canary_pct_raises(self):
        with self.assertRaises(ValueError):
            self._policy(mode="canary", canary_pct=1.5)

    def test_invalid_rule_decision_raises(self):
        with self.assertRaises(ValueError):
            self._policy(rules=[{"conditions": [], "decision": "explode"}])

    def test_invalid_rule_op_raises(self):
        with self.assertRaises(ValueError):
            self._policy(rules=[{
                "conditions": [{"field": "x", "op": "regex", "value": ".*"}],
                "decision": "block",
            }])

    def test_get_policy_not_found_raises(self):
        with self.assertRaises(KeyError):
            enforcement_plane.get_policy("nope", TENANT, db_path=self.db)

    def test_list_policies_active(self):
        self._policy(name="p1")
        self._policy(name="p2")
        policies = enforcement_plane.list_policies(TENANT, db_path=self.db)
        assert len(policies) == 2

    def test_list_policies_filters_by_status(self):
        p = self._policy()
        enforcement_plane.deactivate_policy(p["policy_id"], TENANT, db_path=self.db)
        active = enforcement_plane.list_policies(TENANT, status="active", db_path=self.db)
        assert len(active) == 0

    def test_update_policy_mode(self):
        p = self._policy(mode="shadow")
        updated = enforcement_plane.update_policy(
            p["policy_id"], TENANT, mode="enforce", db_path=self.db
        )
        assert updated["mode"] == "enforce"

    def test_update_policy_rules(self):
        p = self._policy()
        new_rules = [self._rule(decision="audit")]
        updated = enforcement_plane.update_policy(
            p["policy_id"], TENANT, rules=new_rules, db_path=self.db
        )
        assert updated["rules"][0]["decision"] == "audit"

    def test_deactivate_policy(self):
        p = self._policy()
        deactivated = enforcement_plane.deactivate_policy(p["policy_id"], TENANT, db_path=self.db)
        assert deactivated["status"] == "inactive"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Rule Evaluation
# ─────────────────────────────────────────────────────────────────────────────


class TestRuleEvaluation(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        _reset()
        enforcement_plane.init_db(self.db)

    def tearDown(self):
        os.unlink(self.db)
        _reset()

    def _make_policy(self, conditions, logic="all", decision="block", mode="enforce"):
        rules = [{"conditions": conditions, "logic": logic, "decision": decision, "risk_score": 0.9}]
        return enforcement_plane.create_policy(
            tenant_id=TENANT, name="rule-test", rules=rules, mode=mode, db_path=self.db
        )

    def _eval(self, action_type="read", resource="", context=None):
        return enforcement_plane.evaluate(
            TENANT, AGENT, action_type, resource=resource,
            context=context or {}, db_path=self.db
        )

    def test_eq_match_blocks(self):
        self._make_policy([{"field": "action_type", "op": "eq", "value": "delete"}])
        result = self._eval(action_type="delete")
        assert result["decision"] == "block"

    def test_eq_no_match_allows(self):
        self._make_policy([{"field": "action_type", "op": "eq", "value": "delete"}])
        result = self._eval(action_type="read")
        assert result["decision"] == "allow"

    def test_neq_match(self):
        self._make_policy([{"field": "action_type", "op": "neq", "value": "read"}])
        result = self._eval(action_type="write")
        assert result["decision"] == "block"

    def test_in_operator(self):
        self._make_policy([{"field": "action_type", "op": "in", "value": ["write", "delete", "admin"]}])
        assert self._eval(action_type="write")["decision"] == "block"
        assert self._eval(action_type="read")["decision"] == "allow"

    def test_not_in_operator(self):
        self._make_policy([{"field": "action_type", "op": "not_in", "value": ["read", "list"]}])
        assert self._eval(action_type="delete")["decision"] == "block"
        assert self._eval(action_type="read")["decision"] == "allow"

    def test_startswith_on_resource(self):
        self._make_policy([{"field": "resource", "op": "startswith", "value": "/prod/"}])
        assert self._eval(resource="/prod/secrets")["decision"] == "block"
        assert self._eval(resource="/dev/secrets")["decision"] == "allow"

    def test_contains_operator(self):
        self._make_policy([{"field": "resource", "op": "contains", "value": "secret"}])
        assert self._eval(resource="/data/secrets/key")["decision"] == "block"
        assert self._eval(resource="/data/public/key")["decision"] == "allow"

    def test_context_field(self):
        self._make_policy([{"field": "context.env", "op": "eq", "value": "production"}])
        assert self._eval(context={"env": "production"})["decision"] == "block"
        assert self._eval(context={"env": "staging"})["decision"] == "allow"

    def test_logic_any_one_match_sufficient(self):
        self._make_policy([
            {"field": "action_type", "op": "eq", "value": "delete"},
            {"field": "action_type", "op": "eq", "value": "admin"},
        ], logic="any")
        assert self._eval(action_type="delete")["decision"] == "block"
        assert self._eval(action_type="read")["decision"] == "allow"

    def test_logic_all_requires_all_conditions(self):
        self._make_policy([
            {"field": "action_type", "op": "eq", "value": "write"},
            {"field": "resource", "op": "startswith", "value": "/prod/"},
        ], logic="all")
        assert self._eval(action_type="write", resource="/prod/db")["decision"] == "block"
        assert self._eval(action_type="write", resource="/dev/db")["decision"] == "allow"

    def test_audit_decision(self):
        self._make_policy([{"field": "action_type", "op": "eq", "value": "read"}], decision="audit")
        result = self._eval(action_type="read")
        assert result["decision"] == "audit"
        assert result["blocked"] is False

    def test_no_policies_allows_everything(self):
        result = self._eval(action_type="delete")
        assert result["decision"] == "allow"

    def test_inactive_policy_not_evaluated(self):
        p = self._make_policy([{"field": "action_type", "op": "eq", "value": "delete"}])
        enforcement_plane.deactivate_policy(p["policy_id"], TENANT, db_path=self.db)
        result = self._eval(action_type="delete")
        assert result["decision"] == "allow"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Enforcement Modes
# ─────────────────────────────────────────────────────────────────────────────


class TestEnforcementModes(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        _reset()
        enforcement_plane.init_db(self.db)

    def tearDown(self):
        os.unlink(self.db)
        _reset()

    def _block_rule(self):
        return [{
            "conditions": [{"field": "action_type", "op": "eq", "value": "delete"}],
            "logic": "all", "decision": "block", "risk_score": 0.9,
        }]

    def test_shadow_mode_never_blocks(self):
        enforcement_plane.create_policy(
            tenant_id=TENANT, name="shadow-pol", rules=self._block_rule(),
            mode="shadow", db_path=self.db
        )
        result = enforcement_plane.evaluate(TENANT, AGENT, "delete", db_path=self.db)
        assert result["decision"] == "allow"
        assert result["shadow_would"] == "block"

    def test_enforce_mode_blocks(self):
        enforcement_plane.create_policy(
            tenant_id=TENANT, name="enforce-pol", rules=self._block_rule(),
            mode="enforce", db_path=self.db
        )
        result = enforcement_plane.evaluate(TENANT, AGENT, "delete", db_path=self.db)
        assert result["decision"] == "block"
        assert result["blocked"] is True

    def test_canary_mode_at_zero_pct_never_blocks(self):
        enforcement_plane.create_policy(
            tenant_id=TENANT, name="canary-pol", rules=self._block_rule(),
            mode="canary", canary_pct=0.0, db_path=self.db
        )
        for _ in range(20):
            result = enforcement_plane.evaluate(TENANT, AGENT, "delete", db_path=self.db)
            assert result["decision"] == "allow"

    def test_canary_mode_at_full_pct_always_enforces(self):
        enforcement_plane.create_policy(
            tenant_id=TENANT, name="canary-full", rules=self._block_rule(),
            mode="canary", canary_pct=1.0, db_path=self.db
        )
        results = [
            enforcement_plane.evaluate(TENANT, AGENT, "delete", db_path=self.db)
            for _ in range(10)
        ]
        assert all(r["decision"] == "block" for r in results)

    def test_shadow_report_counts(self):
        enforcement_plane.create_policy(
            tenant_id=TENANT, name="shadow-r", rules=self._block_rule(),
            mode="shadow", db_path=self.db
        )
        for _ in range(5):
            enforcement_plane.evaluate(TENANT, AGENT, "delete", db_path=self.db)
        report = enforcement_plane.shadow_report(TENANT, db_path=self.db)
        assert report["shadow_would_block"] == 5
        assert report["actually_blocked"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# 4. Kill Switch
# ─────────────────────────────────────────────────────────────────────────────


class TestKillSwitch(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        _reset()
        enforcement_plane.init_db(self.db)

    def tearDown(self):
        os.unlink(self.db)
        _reset()

    def test_activate_kill_switch(self):
        ks = enforcement_plane.activate_kill_switch(
            TENANT, AGENT, "security-team", reason="incident-response", db_path=self.db
        )
        assert ks["active"] is True
        assert ks["activated_by"] == "security-team"
        assert ks["reason"] == "incident-response"

    def test_kill_switch_blocks_all_evaluations(self):
        enforcement_plane.activate_kill_switch(TENANT, AGENT, "ops", db_path=self.db)
        result = enforcement_plane.evaluate(TENANT, AGENT, "read", db_path=self.db)
        assert result["decision"] == "block"
        assert result["kill_switched"] is True
        assert result["risk_score"] == 1.0

    def test_kill_switch_blocks_regardless_of_policy(self):
        enforcement_plane.create_policy(
            tenant_id=TENANT, name="allow-all",
            rules=[{
                "conditions": [{"field": "action_type", "op": "eq", "value": "read"}],
                "logic": "all", "decision": "allow", "risk_score": 0.0,
            }],
            mode="enforce", db_path=self.db,
        )
        enforcement_plane.activate_kill_switch(TENANT, AGENT, "ops", db_path=self.db)
        result = enforcement_plane.evaluate(TENANT, AGENT, "read", db_path=self.db)
        assert result["decision"] == "block"

    def test_deactivate_kill_switch(self):
        enforcement_plane.activate_kill_switch(TENANT, AGENT, "ops", db_path=self.db)
        enforcement_plane.deactivate_kill_switch(TENANT, AGENT, "security-lead", db_path=self.db)
        result = enforcement_plane.evaluate(TENANT, AGENT, "read", db_path=self.db)
        assert result["decision"] == "allow"
        assert result["kill_switched"] is False

    def test_kill_switch_requires_actor(self):
        with self.assertRaises(ValueError):
            enforcement_plane.activate_kill_switch(TENANT, AGENT, "", db_path=self.db)

    def test_deactivate_requires_actor(self):
        enforcement_plane.activate_kill_switch(TENANT, AGENT, "ops", db_path=self.db)
        with self.assertRaises(ValueError):
            enforcement_plane.deactivate_kill_switch(TENANT, AGENT, "", db_path=self.db)

    def test_kill_switch_idempotent_reactivation(self):
        enforcement_plane.activate_kill_switch(TENANT, AGENT, "ops-1", db_path=self.db)
        enforcement_plane.activate_kill_switch(TENANT, AGENT, "ops-2", db_path=self.db)
        ks = enforcement_plane.get_kill_switch_status(TENANT, AGENT, db_path=self.db)
        assert ks["active"] is True

    def test_list_active_kill_switches(self):
        enforcement_plane.activate_kill_switch(TENANT, "agent-a", "ops", db_path=self.db)
        enforcement_plane.activate_kill_switch(TENANT, "agent-b", "ops", db_path=self.db)
        active = enforcement_plane.list_active_kill_switches(TENANT, db_path=self.db)
        assert len(active) == 2

    def test_no_kill_switch_returns_inactive(self):
        ks = enforcement_plane.get_kill_switch_status(TENANT, "no-agent", db_path=self.db)
        assert ks["active"] is False

    def test_decisions_logged_with_kill_switch_flag(self):
        enforcement_plane.activate_kill_switch(TENANT, AGENT, "ops", db_path=self.db)
        enforcement_plane.evaluate(TENANT, AGENT, "read", db_path=self.db)
        decisions = enforcement_plane.list_decisions(TENANT, agent_id=AGENT, db_path=self.db)
        assert decisions[0]["kill_switched"] is True


# ─────────────────────────────────────────────────────────────────────────────
# 5. API Route Registration Smoke
# ─────────────────────────────────────────────────────────────────────────────


class TestAPIRouteRegistration(unittest.TestCase):

    def test_api_imports_enforcement_plane(self):
        import api as api_mod
        assert hasattr(api_mod, "enforcement_plane")

    def test_enforcement_routes_registered(self):
        try:
            import api as api_mod
        except Exception:
            pytest.skip("api.py failed to import")
        routes = {r.path for r in api_mod.app.routes if hasattr(r, "path")}
        expected = [
            "/api/enforcement/policies",
            "/api/enforcement/evaluate",
            "/api/enforcement/decisions",
            "/api/enforcement/shadow/report",
            "/api/enforcement/killswitch",
        ]
        for path in expected:
            assert path in routes, f"Missing route: {path}"


if __name__ == "__main__":
    unittest.main()
