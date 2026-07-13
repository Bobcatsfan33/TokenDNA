"""
Tests for modules/identity/workflow_attestation.py — multi-hop signed DAG +
replay + drift.

Coverage:
  - Canonicalization: order-independence inside hop, field whitelist,
    missing-required-field rejection.
  - Merkle root determinism + sensitivity (single-byte change ⇒ different
    root).
  - register_workflow: idempotent on (tenant, merkle_root); produces
    HMAC-SHA256 signature.
  - replay_workflow: signature pass; signature tampering caught;
    revoked-receipt at any hop flips overall_valid to false; retired
    workflow flips overall_valid to false even with intact signature.
  - record_observation: observed == canonical → no drift; structural diff
    surfaced when hops differ.
  - Cross-tenant isolation on get/replay/observe.
  - Routes: register → replay → observe-with-drift end-to-end.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture()
def tmp_db(tmp_path, monkeypatch):
    db = str(tmp_path / "wf.db")
    monkeypatch.setenv("DATA_DB_PATH", db)
    monkeypatch.setenv("TOKENDNA_WORKFLOW_SECRET", "wf-test-secret")
    monkeypatch.setenv("TOKENDNA_DELEGATION_SECRET", "dr-test-secret")
    yield db


@pytest.fixture()
def stack(tmp_db):
    import importlib

    import modules.identity.delegation_receipt as dr
    import modules.identity.workflow_attestation as wf

    for mod in (dr, wf):
        importlib.reload(mod)
    dr.init_db()
    wf.init_db()
    return {"dr": dr, "wf": wf}


TENANT = "t-wf"


# ─────────────────────────────────────────────────────────────────────────────
# Canonicalization + Merkle
# ─────────────────────────────────────────────────────────────────────────────

class TestCanonical:
    def test_field_order_irrelevant(self, stack):
        wf = stack["wf"]
        a = wf.merkle_root([{"actor": "a", "action": "read", "target": "t1"}])
        b = wf.merkle_root([{"target": "t1", "action": "read", "actor": "a"}])
        assert a == b

    def test_unknown_fields_dropped(self, stack):
        wf = stack["wf"]
        a = wf.merkle_root([{"actor": "a", "action": "read"}])
        b = wf.merkle_root([{"actor": "a", "action": "read", "junk": "ignored"}])
        assert a == b

    def test_missing_required_raises(self, stack):
        wf = stack["wf"]
        with pytest.raises(wf.WorkflowError, match="hop_missing_required_fields"):
            wf.merkle_root([{"action": "read"}])  # no actor

    def test_root_changes_on_action_swap(self, stack):
        wf = stack["wf"]
        a = wf.merkle_root([{"actor": "a", "action": "read"}])
        b = wf.merkle_root([{"actor": "a", "action": "write"}])
        assert a != b

    def test_root_changes_on_hop_reorder(self, stack):
        wf = stack["wf"]
        h1 = {"actor": "a", "action": "read"}
        h2 = {"actor": "b", "action": "write"}
        a = wf.merkle_root([h1, h2])
        b = wf.merkle_root([h2, h1])
        assert a != b


# ─────────────────────────────────────────────────────────────────────────────
# Register
# ─────────────────────────────────────────────────────────────────────────────

class TestRegister:
    def test_register_returns_signed_workflow(self, stack):
        out = stack["wf"].register_workflow(
            tenant_id=TENANT, name="ETL pipeline",
            hops=[{"actor": "ingester", "action": "read", "target": "raw"}],
        )
        assert out.workflow_id.startswith("wf:")
        assert out.merkle_root and len(out.merkle_root) == 64
        assert out.signature and len(out.signature) == 64

    def test_register_idempotent_on_root(self, stack):
        hops = [{"actor": "a", "action": "read", "target": "x"}]
        a = stack["wf"].register_workflow(TENANT, "n", hops)
        b = stack["wf"].register_workflow(TENANT, "n", hops)
        assert a.workflow_id == b.workflow_id

    def test_register_distinct_per_tenant(self, stack):
        hops = [{"actor": "a", "action": "read"}]
        a = stack["wf"].register_workflow("tA", "n", hops)
        b = stack["wf"].register_workflow("tB", "n", hops)
        assert a.workflow_id != b.workflow_id  # same shape, different tenant scope

    def test_empty_hops_rejected(self, stack):
        with pytest.raises(stack["wf"].WorkflowError, match="hops_must_be_non_empty"):
            stack["wf"].register_workflow(TENANT, "n", [])

    def test_blank_name_rejected(self, stack):
        with pytest.raises(stack["wf"].WorkflowError, match="name_required"):
            stack["wf"].register_workflow(TENANT, "  ",
                                          [{"actor": "a", "action": "read"}])


# ─────────────────────────────────────────────────────────────────────────────
# Replay
# ─────────────────────────────────────────────────────────────────────────────

class TestReplay:
    def test_replay_clean_workflow(self, stack):
        out = stack["wf"].register_workflow(
            TENANT, "clean",
            hops=[{"actor": "a", "action": "read", "target": "t"}],
        )
        result = stack["wf"].replay_workflow(out.workflow_id, tenant_id=TENANT)
        assert result.signature_valid is True
        assert result.overall_valid is True
        assert result.overall_reason == "ok"
        assert len(result.hops) == 1

    def test_replay_unknown(self, stack):
        result = stack["wf"].replay_workflow("wf:bogus")
        assert result.overall_valid is False
        assert result.overall_reason == "not_found_or_cross_tenant"

    def test_replay_cross_tenant(self, stack):
        out = stack["wf"].register_workflow(
            TENANT, "scoped",
            hops=[{"actor": "a", "action": "read"}],
        )
        result = stack["wf"].replay_workflow(out.workflow_id, tenant_id="other")
        assert result.overall_valid is False

    def test_replay_signature_tamper(self, stack, tmp_db):
        out = stack["wf"].register_workflow(
            TENANT, "tamper",
            hops=[{"actor": "a", "action": "read", "target": "t"}],
        )
        # Mutate the stored hops_json to break the Merkle root → signature mismatch.
        import json
        import sqlite3
        conn = sqlite3.connect(tmp_db)
        new_hops = json.dumps([{"action": "write", "actor": "a"}])
        conn.execute(
            "UPDATE workflows SET hops_json=? WHERE workflow_id=?",
            (new_hops, out.workflow_id),
        )
        conn.commit()
        conn.close()
        result = stack["wf"].replay_workflow(out.workflow_id, tenant_id=TENANT)
        assert result.signature_valid is False
        assert result.overall_valid is False
        assert result.overall_reason == "signature_invalid"

    def test_replay_with_revoked_receipt_fails(self, stack):
        # Build a delegation chain, reference its leaf in a workflow, then
        # cascade-revoke and confirm replay surfaces it.
        dr = stack["dr"]
        r1 = dr.issue_receipt(TENANT, "human:alice", "agt-A", ["db:*"], 3600)
        r2 = dr.issue_receipt(TENANT, "agt-A", "agt-B", ["db:read"], 3600,
                              parent_receipt_id=r1.receipt_id)
        out = stack["wf"].register_workflow(
            TENANT, "with-receipt",
            hops=[
                {"actor": "agt-A", "action": "read", "receipt_id": r1.receipt_id},
                {"actor": "agt-B", "action": "read", "receipt_id": r2.receipt_id},
            ],
        )
        result = stack["wf"].replay_workflow(out.workflow_id, tenant_id=TENANT)
        assert result.overall_valid is True

        dr.revoke_receipt(r1.receipt_id, "admin", cascade=True, tenant_id=TENANT)
        result = stack["wf"].replay_workflow(out.workflow_id, tenant_id=TENANT)
        assert result.overall_valid is False
        assert "receipt_revoked" in result.overall_reason

    def test_replay_retired_workflow_invalid(self, stack):
        out = stack["wf"].register_workflow(
            TENANT, "retire-me",
            hops=[{"actor": "a", "action": "read"}],
        )
        stack["wf"].retire_workflow(out.workflow_id, tenant_id=TENANT)
        result = stack["wf"].replay_workflow(out.workflow_id, tenant_id=TENANT)
        assert result.signature_valid is True
        assert result.overall_valid is False
        assert result.overall_reason == "workflow_retired"


# ─────────────────────────────────────────────────────────────────────────────
# Observations & drift
# ─────────────────────────────────────────────────────────────────────────────

class TestObservations:
    def _register(self, stack):
        return stack["wf"].register_workflow(
            TENANT, "etl",
            hops=[
                {"actor": "ingester", "action": "read", "target": "raw"},
                {"actor": "transformer", "action": "transform", "target": "staged"},
            ],
        )

    def test_clean_observation_no_drift(self, stack):
        wf_obj = self._register(stack)
        out = stack["wf"].record_observation(
            wf_obj.workflow_id,
            observed_hops=[
                {"actor": "ingester", "action": "read", "target": "raw"},
                {"actor": "transformer", "action": "transform", "target": "staged"},
            ],
            tenant_id=TENANT,
        )
        assert out["drift"] is False
        assert out["observed_root"] == wf_obj.merkle_root

    def test_drift_extra_hop_flagged(self, stack):
        wf_obj = self._register(stack)
        out = stack["wf"].record_observation(
            wf_obj.workflow_id,
            observed_hops=[
                {"actor": "ingester", "action": "read", "target": "raw"},
                {"actor": "INJECTED-AGENT", "action": "exfil", "target": "attacker.com"},
                {"actor": "transformer", "action": "transform", "target": "staged"},
            ],
            tenant_id=TENANT,
        )
        assert out["drift"] is True
        details = out["drift_details"]
        assert details["observed_hops"] == 3
        assert details["canonical_hops"] == 2
        assert details["extra_hops"] == 1

    def test_drift_field_change_flagged(self, stack):
        wf_obj = self._register(stack)
        out = stack["wf"].record_observation(
            wf_obj.workflow_id,
            observed_hops=[
                {"actor": "ingester", "action": "read", "target": "raw"},
                {"actor": "transformer", "action": "transform", "target": "staged-PROD"},
            ],
            tenant_id=TENANT,
        )
        assert out["drift"] is True
        assert "hop_diffs" in out["drift_details"]

    def test_get_observations_filter(self, stack):
        wf_obj = self._register(stack)
        # one clean, one drifted
        stack["wf"].record_observation(
            wf_obj.workflow_id,
            observed_hops=[
                {"actor": "ingester", "action": "read", "target": "raw"},
                {"actor": "transformer", "action": "transform", "target": "staged"},
            ],
            tenant_id=TENANT,
        )
        stack["wf"].record_observation(
            wf_obj.workflow_id,
            observed_hops=[{"actor": "rogue", "action": "read"}],
            tenant_id=TENANT,
        )
        all_ = stack["wf"].get_observations(wf_obj.workflow_id, tenant_id=TENANT)
        drifted = stack["wf"].get_observations(
            wf_obj.workflow_id, drift_only=True, tenant_id=TENANT,
        )
        assert len(all_) == 2
        assert len(drifted) == 1
        assert drifted[0]["drift"] is True

    def test_observe_unknown_workflow(self, stack):
        with pytest.raises(stack["wf"].WorkflowError):
            stack["wf"].record_observation(
                "wf:bogus",
                observed_hops=[{"actor": "a", "action": "read"}],
            )


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def app_client(tmp_db, stack):
    import api as app_module
    from fastapi.testclient import TestClient
    from modules.tenants.middleware import get_tenant
    from modules.tenants.models import Plan, TenantContext

    tenant = TenantContext(
        tenant_id=TENANT, tenant_name="WF",
        plan=Plan.ENTERPRISE, api_key_id="k", role="owner",
    )

    def _override():
        return tenant

    import modules.product.commercial_tiers as _ct
    app_module.app.dependency_overrides[get_tenant] = _override
    app_module.app.dependency_overrides[_ct.get_tenant] = _override
    yield TestClient(app_module.app, raise_server_exceptions=False), stack
    app_module.app.dependency_overrides.clear()


class TestRoutes:
    def test_register_replay_observe_flow(self, app_client):
        client, _ = app_client
        reg = client.post("/api/workflow/register", json={
            "name": "demo",
            "hops": [
                {"actor": "agt-A", "action": "read", "target": "doc"},
                {"actor": "agt-B", "action": "summarize", "target": "doc"},
            ],
        }).json()
        wid = reg["workflow_id"]

        replay = client.get(f"/api/workflow/{wid}/replay").json()
        assert replay["overall_valid"] is True

        observe = client.post(f"/api/workflow/{wid}/observe", json={
            "hops": [
                {"actor": "agt-A", "action": "read", "target": "doc"},
                {"actor": "INJECTED", "action": "exfil"},
                {"actor": "agt-B", "action": "summarize", "target": "doc"},
            ],
        }).json()
        assert observe["drift"] is True

        listing = client.get(f"/api/workflow/{wid}/observations",
                             params={"drift_only": True}).json()
        assert listing["count"] == 1

    def test_register_invalid_hops_400(self, app_client):
        client, _ = app_client
        resp = client.post("/api/workflow/register", json={"name": "x", "hops": []})
        assert resp.status_code == 400

    def test_unknown_workflow_404(self, app_client):
        client, _ = app_client
        assert client.get("/api/workflow/wf:bogus").status_code == 404

    def test_retire_then_replay_invalid(self, app_client):
        client, _ = app_client
        reg = client.post("/api/workflow/register", json={
            "name": "retire-flow",
            "hops": [{"actor": "a", "action": "read"}],
        }).json()
        wid = reg["workflow_id"]
        ok = client.post(f"/api/workflow/{wid}/retire")
        assert ok.status_code == 200
        replay = client.get(f"/api/workflow/{wid}/replay").json()
        assert replay["overall_valid"] is False
        assert replay["overall_reason"] == "workflow_retired"
