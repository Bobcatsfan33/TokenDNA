"""
Tests for modules/identity/compliance_posture.py — signed posture
statements + signed incident reconstruction.

Coverage:
  - Posture: every framework produces controls; collector errors degrade
    a control to fail rather than crash the statement; signatures verify;
    digest tampering is detected by verify_posture_statement.
  - Incident: every section is best-effort (collector errors surface as
    section_error); signature digest pins content; cross-tenant lookup
    blocked.
  - Routes: generate → get → verify → list lifecycle works.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture()
def tmp_db(tmp_path, monkeypatch):
    db = str(tmp_path / "cp.db")
    monkeypatch.setenv("DATA_DB_PATH", db)
    monkeypatch.setenv("TOKENDNA_POSTURE_SECRET", "cp-test-secret")
    monkeypatch.setenv("TOKENDNA_DELEGATION_SECRET", "dr-test-secret")
    yield db


@pytest.fixture()
def cp_mod(tmp_db):
    import importlib
    import modules.identity.compliance_posture as m
    importlib.reload(m)
    m.init_db()
    return m


TENANT = "t-cp"


# ─────────────────────────────────────────────────────────────────────────────
# Posture statement
# ─────────────────────────────────────────────────────────────────────────────

class TestPostureGeneration:
    def test_unknown_framework_rejected(self, cp_mod):
        with pytest.raises(ValueError, match="unknown_framework"):
            cp_mod.generate_posture_statement(TENANT, "iso27001-but-typo")

    @pytest.mark.parametrize("fw", ["soc2", "iso42001", "nist_ai_rmf", "eu_ai_act"])
    def test_each_framework_emits_signed_statement(self, cp_mod, fw):
        out = cp_mod.generate_posture_statement(TENANT, fw)
        assert out.framework == fw
        assert out.signature and len(out.signature) == 64
        assert out.evidence_digest and len(out.evidence_digest) == 64
        assert isinstance(out.controls, list) and len(out.controls) >= 1
        for c in out.controls:
            assert "control_id" in c
            assert "passed" in c

    def test_collector_failure_yields_failed_control(self, cp_mod, monkeypatch):
        # Sabotage the drift collector so the corresponding control fails.
        from modules.identity import compliance_posture as cp_module
        def _explode(_t):
            return cp_module._safe_call(
                lambda: (_ for _ in ()).throw(RuntimeError("drift_unavailable")),
                "drift",
            )
        monkeypatch.setattr(cp_module, "_collect_drift", _explode)
        out = cp_mod.generate_posture_statement(TENANT, "soc2")
        # CC6.6.agent_attestation_drift uses the drift collector — should be failed.
        targets = [c for c in out.controls
                   if c["metric"] == "drift_alerts"]
        assert targets and not targets[0]["passed"]
        assert "collector_unavailable" in targets[0]["reason"]


class TestPostureVerification:
    def test_verify_clean_pass(self, cp_mod):
        out = cp_mod.generate_posture_statement(TENANT, "soc2")
        v = cp_mod.verify_posture_statement(out.statement_id, tenant_id=TENANT)
        assert v["valid"] is True

    def test_verify_unknown(self, cp_mod):
        v = cp_mod.verify_posture_statement("posture:bogus")
        assert v["valid"] is False
        assert v["reason"] == "not_found"

    def test_verify_cross_tenant(self, cp_mod):
        out = cp_mod.generate_posture_statement(TENANT, "soc2")
        v = cp_mod.verify_posture_statement(out.statement_id, tenant_id="other")
        assert v["valid"] is False
        assert v["reason"] == "cross_tenant"

    def test_verify_digest_tamper(self, cp_mod, tmp_db):
        out = cp_mod.generate_posture_statement(TENANT, "soc2")
        import json as _j
        import sqlite3
        conn = sqlite3.connect(tmp_db)
        # Mutate the controls JSON so the recomputed digest differs.
        conn.execute(
            "UPDATE compliance_posture_statements SET controls_json=? "
            "WHERE statement_id=?",
            (_j.dumps([{"tampered": True}], sort_keys=True), out.statement_id),
        )
        conn.commit()
        conn.close()
        v = cp_mod.verify_posture_statement(out.statement_id)
        assert v["valid"] is False
        assert v["reason"] == "digest_mismatch"


class TestPostureListing:
    def test_list_filters_by_framework(self, cp_mod):
        cp_mod.generate_posture_statement(TENANT, "soc2")
        cp_mod.generate_posture_statement(TENANT, "eu_ai_act")
        soc = cp_mod.list_posture_statements(TENANT, framework="soc2")
        eu = cp_mod.list_posture_statements(TENANT, framework="eu_ai_act")
        all_ = cp_mod.list_posture_statements(TENANT)
        assert len(soc) == 1
        assert len(eu) == 1
        assert len(all_) >= 2

    def test_get_cross_tenant_returns_none(self, cp_mod):
        out = cp_mod.generate_posture_statement(TENANT, "soc2")
        assert cp_mod.get_posture_statement(out.statement_id,
                                            tenant_id="other") is None


# ─────────────────────────────────────────────────────────────────────────────
# Incident reconstruction
# ─────────────────────────────────────────────────────────────────────────────

class TestIncidentReport:
    def test_incident_basic_shape(self, cp_mod):
        out = cp_mod.incident_reconstruction(
            tenant_id=TENANT, agent_id="agt-x",
            since="2026-04-01T00:00:00+00:00",
        )
        assert out["report_id"].startswith("incident:")
        assert out["agent_id"] == "agt-x"
        assert isinstance(out["sections"], list)
        # All section labels present.
        labels = {s["section"] for s in out["sections"]}
        assert {
            "delegation_receipts", "intent_matches", "blast_radius_latest",
            "drift_events", "policy_guard_violations",
        }.issubset(labels)

    def test_incident_signature_pins_digest(self, cp_mod):
        out = cp_mod.incident_reconstruction(
            tenant_id=TENANT, agent_id="agt-x",
            since="2026-04-01T00:00:00+00:00",
        )
        assert out["signature"] and len(out["signature"]) == 64
        # Same content → same digest (re-running on stable snapshot).
        out2 = cp_mod.incident_reconstruction(
            tenant_id=TENANT, agent_id="agt-x",
            since="2026-04-01T00:00:00+00:00",
            until=out["period_end"],
        )
        # Different generation produces different report_id but in the
        # absence of new events the content_digest should still match.
        assert out2["content_digest"] == out["content_digest"]

    def test_get_incident_cross_tenant(self, cp_mod):
        out = cp_mod.incident_reconstruction(
            TENANT, "agt-x", since="2026-04-01T00:00:00+00:00",
        )
        assert cp_mod.get_incident_report(out["report_id"],
                                          tenant_id="other") is None


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def app_client(tmp_db, cp_mod):
    import api as app_module
    from fastapi.testclient import TestClient
    from modules.tenants.middleware import get_tenant
    from modules.tenants.models import Plan, TenantContext

    tenant = TenantContext(
        tenant_id=TENANT, tenant_name="CP",
        plan=Plan.ENTERPRISE, api_key_id="k", role="owner",
    )

    def _override():
        return tenant

    import modules.product.commercial_tiers as _ct
    app_module.app.dependency_overrides[get_tenant] = _override
    app_module.app.dependency_overrides[_ct.get_tenant] = _override
    yield TestClient(app_module.app, raise_server_exceptions=False), cp_mod
    app_module.app.dependency_overrides.clear()


class TestRoutes:
    def test_posture_lifecycle(self, app_client):
        client, _ = app_client
        gen = client.post(
            "/api/compliance/posture/soc2/generate", json={},
        ).json()
        sid = gen["statement_id"]
        # Get
        got = client.get(f"/api/compliance/posture/statements/{sid}").json()
        assert got["statement_id"] == sid
        # Verify
        v = client.get(f"/api/compliance/posture/statements/{sid}/verify").json()
        assert v["valid"] is True
        # List
        listing = client.get("/api/compliance/posture/statements").json()
        assert listing["count"] >= 1

    def test_unknown_framework_400(self, app_client):
        client, _ = app_client
        resp = client.post("/api/compliance/posture/blockchain-vibes/generate",
                           json={})
        assert resp.status_code == 400

    def test_incident_lifecycle(self, app_client):
        client, _ = app_client
        rec = client.post(
            "/api/compliance/incident/agt-test/reconstruct",
            json={"since": "2026-04-01T00:00:00+00:00"},
        ).json()
        rid = rec["report_id"]
        got = client.get(f"/api/compliance/incident/reports/{rid}").json()
        assert got["agent_id"] == "agt-test"

    def test_incident_missing_since_400(self, app_client):
        client, _ = app_client
        resp = client.post("/api/compliance/incident/agt-x/reconstruct", json={})
        assert resp.status_code == 400
