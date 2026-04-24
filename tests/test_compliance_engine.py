"""
Tests for TokenDNA Phase 5-4: Real-Time Regulatory Compliance Engine

Covers:
  - Framework catalog (list, controls)
  - Risk classification (scoring, override, all frameworks)
  - Compliance assessment (gap analysis, score, native controls)
  - Compliance dashboard
  - Compliance-as-enforcement policy generation
  - Audit export
  - API route registration smoke
"""

from __future__ import annotations

import os
import tempfile
import unittest

import pytest

from modules.identity import compliance_engine

TENANT = "ce-tenant"
AGENT = "ce-agent-001"


def _tmp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return path


def _reset():
    compliance_engine._db_initialized = False


# ─────────────────────────────────────────────────────────────────────────────
# 1. Framework Catalog
# ─────────────────────────────────────────────────────────────────────────────


class TestFrameworkCatalog(unittest.TestCase):

    def test_list_frameworks_returns_all_four(self):
        frameworks = compliance_engine.list_frameworks()
        ids = {f["framework_id"] for f in frameworks}
        assert "eu_ai_act" in ids
        assert "nist_ai_600_1" in ids
        assert "soc2_ai" in ids
        assert "iso_42001" in ids

    def test_framework_has_required_fields(self):
        for fw in compliance_engine.list_frameworks():
            assert "framework_id" in fw
            assert "name" in fw
            assert "version" in fw
            assert "control_count" in fw
            assert fw["control_count"] > 0

    def test_get_eu_ai_act_controls(self):
        controls = compliance_engine.get_framework_controls("eu_ai_act")
        articles = {c["article"] for c in controls}
        assert "Article 14" in articles  # human oversight
        assert "Article 9" in articles   # risk management

    def test_get_controls_unknown_framework_raises(self):
        with self.assertRaises(KeyError):
            compliance_engine.get_framework_controls("nonexistent_reg")

    def test_every_control_has_check_key(self):
        for fid in compliance_engine.FRAMEWORKS:
            for ctrl in compliance_engine.get_framework_controls(fid):
                assert "check_key" in ctrl
                assert "required_for" in ctrl
                assert "weight" in ctrl


# ─────────────────────────────────────────────────────────────────────────────
# 2. Risk Classification
# ─────────────────────────────────────────────────────────────────────────────


class TestRiskClassification(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        _reset()
        compliance_engine.init_db(self.db)

    def tearDown(self):
        os.unlink(self.db)
        _reset()

    def _classify(self, factors=None, framework="eu_ai_act", override=None):
        return compliance_engine.classify_agent(
            TENANT, AGENT, framework,
            factors=factors or {},
            override_risk_level=override,
            db_path=self.db,
        )

    def test_minimal_risk_no_factors(self):
        result = self._classify(factors={})
        assert result["risk_level"] == "minimal_risk"
        assert result["risk_score"] < 0.2

    def test_high_risk_multiple_factors(self):
        result = self._classify(factors={
            "has_admin_tools": True,
            "autonomous_mode": True,
            "pii_data_access": True,
        })
        assert result["risk_level"] == "high_risk"

    def test_limited_risk_moderate_factors(self):
        # pii_data_access (0.2) + public_facing (0.1) = 0.3 → limited_risk
        result = self._classify(factors={"pii_data_access": True, "public_facing": True})
        assert result["risk_level"] == "limited_risk"

    def test_override_to_prohibited(self):
        result = self._classify(override="prohibited")
        assert result["risk_level"] == "prohibited"
        assert result["risk_score"] == 1.0

    def test_override_to_high_risk(self):
        result = self._classify(factors={}, override="high_risk")
        assert result["risk_level"] == "high_risk"

    def test_invalid_override_raises(self):
        with self.assertRaises(ValueError):
            self._classify(override="extreme")

    def test_unknown_framework_raises(self):
        with self.assertRaises(ValueError):
            compliance_engine.classify_agent(TENANT, AGENT, "made_up_reg", {}, db_path=self.db)

    def test_classification_persisted(self):
        self._classify(factors={"autonomous_mode": True, "has_admin_tools": True})
        result = compliance_engine.get_classification(TENANT, AGENT, "eu_ai_act", db_path=self.db)
        assert result is not None
        assert result["risk_level"] in compliance_engine.RISK_LEVELS

    def test_get_classification_latest_returned(self):
        self._classify(factors={})
        self._classify(factors={"has_admin_tools": True, "autonomous_mode": True})
        result = compliance_engine.get_classification(TENANT, AGENT, "eu_ai_act", db_path=self.db)
        assert result["risk_level"] == "high_risk"

    def test_get_classification_missing_returns_none(self):
        result = compliance_engine.get_classification(TENANT, "no-agent", "eu_ai_act", db_path=self.db)
        assert result is None

    def test_all_frameworks_accept_classification(self):
        for fid in compliance_engine.FRAMEWORKS:
            result = compliance_engine.classify_agent(TENANT, AGENT, fid, {}, db_path=self.db)
            assert result["framework_id"] == fid

    def test_list_classifications_tenant_scoped(self):
        compliance_engine.classify_agent(TENANT, "agent-a", "eu_ai_act", {}, db_path=self.db)
        compliance_engine.classify_agent(TENANT, "agent-b", "eu_ai_act", {}, db_path=self.db)
        compliance_engine.classify_agent("other-tenant", "agent-c", "eu_ai_act", {}, db_path=self.db)
        results = compliance_engine.list_classifications(TENANT, db_path=self.db)
        agents = {r["agent_id"] for r in results}
        assert "agent-a" in agents
        assert "agent-b" in agents
        assert "agent-c" not in agents

    def test_list_classifications_filter_risk_level(self):
        compliance_engine.classify_agent(
            TENANT, "agent-hi", "eu_ai_act",
            {"has_admin_tools": True, "autonomous_mode": True, "pii_data_access": True},
            db_path=self.db
        )
        compliance_engine.classify_agent(TENANT, "agent-lo", "eu_ai_act", {}, db_path=self.db)
        high = compliance_engine.list_classifications(TENANT, risk_level="high_risk", db_path=self.db)
        assert all(r["risk_level"] == "high_risk" for r in high)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Compliance Assessment
# ─────────────────────────────────────────────────────────────────────────────


class TestComplianceAssessment(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        _reset()
        compliance_engine.init_db(self.db)
        # Classify as high_risk so controls are required
        compliance_engine.classify_agent(
            TENANT, AGENT, "eu_ai_act",
            {"has_admin_tools": True, "autonomous_mode": True, "pii_data_access": True},
            db_path=self.db
        )

    def tearDown(self):
        os.unlink(self.db)
        _reset()

    def test_assessment_with_all_controls_met(self):
        controls = {
            "has_risk_management": True,
            "has_data_governance": True,
            "has_transparency_docs": True,
            "has_human_oversight": True,
            "has_accuracy_monitoring": True,
        }
        result = compliance_engine.assess_compliance(
            TENANT, AGENT, "eu_ai_act", controls, db_path=self.db
        )
        assert result["score"] == 100.0
        assert len(result["controls_gap"]) == 0

    def test_assessment_with_no_controls_has_gaps(self):
        result = compliance_engine.assess_compliance(
            TENANT, AGENT, "eu_ai_act", {}, db_path=self.db
        )
        # Some controls will be met natively by TokenDNA
        assert len(result["controls_gap"]) >= 1
        assert result["score"] < 100.0

    def test_tokendna_native_controls_auto_met(self):
        result = compliance_engine.assess_compliance(
            TENANT, AGENT, "eu_ai_act", {}, db_path=self.db
        )
        met_keys = {c.get("check_key", c.get("control_id")) for c in result["controls_met"]}
        # has_transparency_docs is native
        met_native = any(c.get("native") for c in result["controls_met"])
        assert met_native

    def test_assessment_score_between_0_and_100(self):
        result = compliance_engine.assess_compliance(
            TENANT, AGENT, "eu_ai_act", {"has_human_oversight": True}, db_path=self.db
        )
        assert 0.0 <= result["score"] <= 100.0

    def test_assessment_persisted(self):
        compliance_engine.assess_compliance(TENANT, AGENT, "eu_ai_act", {}, db_path=self.db)
        result = compliance_engine.get_latest_assessment(TENANT, AGENT, "eu_ai_act", db_path=self.db)
        assert result is not None
        assert "score" in result

    def test_get_assessment_missing_returns_none(self):
        result = compliance_engine.get_latest_assessment(TENANT, "no-agent", "eu_ai_act", db_path=self.db)
        assert result is None

    def test_unknown_framework_raises(self):
        with self.assertRaises(ValueError):
            compliance_engine.assess_compliance(TENANT, AGENT, "fake_reg", {}, db_path=self.db)

    def test_all_frameworks_assessable(self):
        for fid in compliance_engine.FRAMEWORKS:
            compliance_engine.classify_agent(TENANT, AGENT, fid, {}, db_path=self.db)
            result = compliance_engine.assess_compliance(TENANT, AGENT, fid, {}, db_path=self.db)
            assert result["framework_id"] == fid


# ─────────────────────────────────────────────────────────────────────────────
# 4. Compliance Dashboard
# ─────────────────────────────────────────────────────────────────────────────


class TestComplianceDashboard(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        _reset()
        compliance_engine.init_db(self.db)

    def tearDown(self):
        os.unlink(self.db)
        _reset()

    def test_empty_dashboard(self):
        result = compliance_engine.compliance_dashboard(TENANT, db_path=self.db)
        assert result["agents_classified"] == 0
        assert result["compliance_policies"] == 0

    def test_dashboard_counts_agents(self):
        for aid in ["a1", "a2", "a3"]:
            compliance_engine.classify_agent(TENANT, aid, "eu_ai_act", {}, db_path=self.db)
        result = compliance_engine.compliance_dashboard(TENANT, db_path=self.db)
        assert result["agents_classified"] == 3

    def test_dashboard_risk_distribution(self):
        compliance_engine.classify_agent(
            TENANT, "hi-agent", "eu_ai_act",
            {"has_admin_tools": True, "autonomous_mode": True, "pii_data_access": True},
            db_path=self.db
        )
        compliance_engine.classify_agent(TENANT, "lo-agent", "eu_ai_act", {}, db_path=self.db)
        result = compliance_engine.compliance_dashboard(TENANT, db_path=self.db)
        assert "high_risk" in result["risk_distribution"]
        assert "minimal_risk" in result["risk_distribution"]

    def test_dashboard_includes_framework_scores(self):
        compliance_engine.classify_agent(TENANT, AGENT, "eu_ai_act", {}, db_path=self.db)
        compliance_engine.assess_compliance(TENANT, AGENT, "eu_ai_act", {}, db_path=self.db)
        result = compliance_engine.compliance_dashboard(TENANT, db_path=self.db)
        assert "eu_ai_act" in result["avg_score_by_framework"]


# ─────────────────────────────────────────────────────────────────────────────
# 5. Compliance-as-Enforcement
# ─────────────────────────────────────────────────────────────────────────────


class TestComplianceEnforcement(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        _reset()
        compliance_engine.init_db(self.db)

    def tearDown(self):
        os.unlink(self.db)
        _reset()

    def test_enforcement_created_for_high_risk(self):
        compliance_engine.classify_agent(
            TENANT, AGENT, "eu_ai_act",
            {"has_admin_tools": True, "autonomous_mode": True, "pii_data_access": True},
            db_path=self.db
        )
        mappings = compliance_engine.create_compliance_enforcement(
            TENANT, AGENT, "eu_ai_act", db_path=self.db
        )
        assert len(mappings) >= 1
        control_ids = {m["control_id"] for m in mappings}
        assert "eu_ai_act:art14" in control_ids

    def test_no_enforcement_for_minimal_risk(self):
        # minimal_risk agents don't require Article 14 enforcement
        compliance_engine.classify_agent(TENANT, AGENT, "eu_ai_act", {}, db_path=self.db)
        mappings = compliance_engine.create_compliance_enforcement(
            TENANT, AGENT, "eu_ai_act", db_path=self.db
        )
        art14_mappings = [m for m in mappings if m["control_id"] == "eu_ai_act:art14"]
        assert len(art14_mappings) == 0

    def test_enforcement_policies_listed(self):
        compliance_engine.classify_agent(
            TENANT, AGENT, "eu_ai_act",
            {"has_admin_tools": True, "autonomous_mode": True, "pii_data_access": True},
            db_path=self.db
        )
        compliance_engine.create_compliance_enforcement(TENANT, AGENT, "eu_ai_act", db_path=self.db)
        policies = compliance_engine.list_compliance_policies(TENANT, AGENT, db_path=self.db)
        assert len(policies) >= 1

    def test_unknown_framework_raises(self):
        with self.assertRaises(ValueError):
            compliance_engine.create_compliance_enforcement(
                TENANT, AGENT, "fake_reg", db_path=self.db
            )


# ─────────────────────────────────────────────────────────────────────────────
# 6. Audit Export
# ─────────────────────────────────────────────────────────────────────────────


class TestAuditExport(unittest.TestCase):

    def setUp(self):
        self.db = _tmp_db()
        _reset()
        compliance_engine.init_db(self.db)
        # Set up some data
        compliance_engine.classify_agent(
            TENANT, AGENT, "eu_ai_act",
            {"autonomous_mode": True},
            db_path=self.db
        )
        compliance_engine.assess_compliance(TENANT, AGENT, "eu_ai_act", {}, db_path=self.db)

    def tearDown(self):
        os.unlink(self.db)
        _reset()

    def test_audit_export_structure(self):
        result = compliance_engine.generate_audit_export(TENANT, AGENT, db_path=self.db)
        assert "export_id" in result
        assert "generated_at" in result
        content = result["content"]
        assert "classifications" in content
        assert "assessments" in content
        assert "summary" in content

    def test_audit_export_filtered_by_framework(self):
        result = compliance_engine.generate_audit_export(
            TENANT, AGENT, "eu_ai_act", db_path=self.db
        )
        assert result["content"]["framework_filter"] == "eu_ai_act"

    def test_audit_export_summary_has_scores(self):
        result = compliance_engine.generate_audit_export(TENANT, AGENT, db_path=self.db)
        summary = result["content"]["summary"]
        assert "avg_score" in summary
        assert "risk_levels" in summary
        assert "open_gaps" in summary

    def test_audit_export_empty_agent_ok(self):
        result = compliance_engine.generate_audit_export(TENANT, "empty-agent", db_path=self.db)
        assert result["content"]["summary"]["frameworks_assessed"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# 7. API Route Registration Smoke
# ─────────────────────────────────────────────────────────────────────────────


class TestAPIRouteRegistration(unittest.TestCase):

    def test_api_imports_compliance_engine(self):
        import api as api_mod
        assert hasattr(api_mod, "compliance_engine")

    def test_compliance_routes_registered(self):
        try:
            import api as api_mod
        except Exception:
            pytest.skip("api.py failed to import")
        routes = {r.path for r in api_mod.app.routes if hasattr(r, "path")}
        expected = [
            "/api/compliance/frameworks",
            "/api/compliance/dashboard",
        ]
        for path in expected:
            assert path in routes, f"Missing route: {path}"


if __name__ == "__main__":
    unittest.main()
