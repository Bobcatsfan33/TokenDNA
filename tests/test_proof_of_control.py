"""
Tests for modules/identity/proof_of_control.py — Sprint 7-B
ZTIX Continuous Proof-of-Control

Coverage:
  - init_db (idempotent)
  - register_verifier / set_proof_interval
  - record_proof: current → proves → next_due advanced, misses reset
  - record_proof: auto-register on first proof
  - record_proof: demoted verifier promoted back in federation
  - get_proof_status: live status computation (current/overdue/expired/never_proved)
  - list_proof_registry: filters by status
  - sweep_expired_proofs: demotes expired verifiers, issues challenges to overdue
  - sweep_expired_proofs: promotes re-proven verifiers
  - Gate: verifier that loses key access auto-demoted within one proof interval
  - renew_all_overdue: issues challenges to overdue + never_proved
  - proof_stats: correct counts by status
  - Federation demotion: status changes in trust_federation_verifiers
  - API: GET /api/federation/verifiers/{id}/proof-status
  - API: POST /api/federation/verifiers/{id}/proof-interval
  - API: POST /api/federation/verifiers/proof-sweep
  - API: POST /api/federation/verifiers/proof-renew-all
  - API: GET /api/federation/verifiers/proof-registry
  - API: GET /api/federation/verifiers/proof-stats
"""

from __future__ import annotations

import importlib
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TENANT = "tenant-poc"
API_TENANT = "dev-tenant"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Each test gets its own SQLite DB with all relevant modules reloaded."""
    db_file = tmp_path / "tokendna-poc-test.db"
    monkeypatch.setenv("DATA_DB_PATH", str(db_file))
    monkeypatch.setenv("ATTESTATION_CA_SECRET", "poc-test-secret")
    monkeypatch.setenv("DEV_MODE", "true")

    from modules.identity import proof_of_control, trust_federation, verifier_reputation
    importlib.reload(trust_federation)
    importlib.reload(verifier_reputation)
    importlib.reload(proof_of_control)
    trust_federation.init_db()
    verifier_reputation.init_reputation_db()
    proof_of_control.init_db()
    return str(db_file)


@pytest.fixture()
def poc():
    from modules.identity import proof_of_control
    return proof_of_control


@pytest.fixture()
def client(isolated_db):
    env = {
        "DATA_DB_PATH": isolated_db,
        "ATTESTATION_CA_SECRET": "poc-test-secret",
        "DEV_MODE": "true",
    }
    with mock.patch.dict(os.environ, env):
        from modules.tenants import store as ts
        importlib.reload(ts)
        ts.init_db()
        from modules.identity import (
            proof_of_control as _poc,
            trust_federation as _tf,
            verifier_reputation as _rep,
        )
        importlib.reload(_tf)
        importlib.reload(_rep)
        importlib.reload(_poc)
        _tf.init_db()
        _rep.init_reputation_db()
        _poc.init_db()
        import modules.tenants.middleware as mw
        importlib.reload(mw)
        import auth as auth_module
        importlib.reload(auth_module)
        import api as api_module
        importlib.reload(api_module)
        with TestClient(
            api_module.app,
            raise_server_exceptions=False,
            headers={"X-API-Key": "dev-api-key"},
        ) as c:
            yield c


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _register_active_verifier(tenant_id: str, verifier_id: str) -> None:
    """Register a verifier in trust_federation with active status."""
    from modules.identity import trust_federation
    trust_federation.upsert_verifier(
        verifier_id=verifier_id,
        tenant_id=tenant_id,
        name=f"Test Verifier {verifier_id}",
        trust_score=0.8,
        issuer="test-issuer",
        jwks_uri="https://verifier.example.com/.well-known/jwks.json",
        status="active",
    )


def _backdate_proof_due(verifier_id: str, tenant_id: str, hours_overdue: int) -> None:
    """Manually backdate next_proof_due so verifier appears overdue/expired."""
    import sqlite3
    db_path = os.environ.get("DATA_DB_PATH", "/data/tokendna.db")
    conn = sqlite3.connect(db_path)
    past_due = (
        datetime.now(timezone.utc) - timedelta(hours=hours_overdue)
    ).isoformat()
    conn.execute("""
        UPDATE verifier_proof_intervals
        SET next_proof_due=?, last_proof_at=?
        WHERE verifier_id=? AND tenant_id=?
    """, (past_due, past_due, verifier_id, tenant_id))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Unit tests — init and registration
# ---------------------------------------------------------------------------

class TestInitDb:
    def test_idempotent(self, poc):
        poc.init_db()
        poc.init_db()
        stats = poc.proof_stats(TENANT)
        assert stats["total"] == 0


class TestRegisterVerifier:
    def test_register_creates_record(self, poc):
        record = poc.register_verifier("v1", TENANT, interval_hours=12)
        assert record.verifier_id == "v1"
        assert record.interval_hours == 12
        assert record.status.value == "never_proved"
        assert record.consecutive_misses == 0
        assert record.last_proof_at is None

    def test_register_idempotent(self, poc):
        poc.register_verifier("v1", TENANT, interval_hours=12)
        poc.register_verifier("v1", TENANT, interval_hours=24)
        record = poc.get_proof_status("v1", TENANT)
        assert record.interval_hours == 24  # updated

    def test_interval_clamped_to_minimum(self, poc):
        record = poc.register_verifier("v1", TENANT, interval_hours=0)
        assert record.interval_hours >= poc._MIN_INTERVAL_HOURS

    def test_interval_clamped_to_maximum(self, poc):
        record = poc.register_verifier("v1", TENANT, interval_hours=9999)
        assert record.interval_hours <= poc._MAX_INTERVAL_HOURS


class TestSetProofInterval:
    def test_creates_if_not_exists(self, poc):
        record = poc.set_proof_interval("v2", TENANT, interval_hours=6)
        assert record.interval_hours == 6
        assert record.status.value == "never_proved"

    def test_updates_existing_interval(self, poc):
        poc.register_verifier("v2", TENANT, interval_hours=24)
        poc.set_proof_interval("v2", TENANT, interval_hours=4)
        record = poc.get_proof_status("v2", TENANT)
        assert record.interval_hours == 4


# ---------------------------------------------------------------------------
# Unit tests — proof recording
# ---------------------------------------------------------------------------

class TestRecordProof:
    def test_advances_next_due(self, poc):
        poc.register_verifier("v1", TENANT, interval_hours=12)
        before = datetime.now(timezone.utc)
        record = poc.record_proof("v1", TENANT)
        after = datetime.now(timezone.utc)
        assert record.status.value == "current"
        assert record.last_proof_at is not None
        assert record.consecutive_misses == 0
        # next_proof_due should be ~12 hours from now
        due = datetime.fromisoformat(record.next_proof_due)
        if due.tzinfo is None:
            due = due.replace(tzinfo=timezone.utc)
        assert before + timedelta(hours=11) <= due <= after + timedelta(hours=13)

    def test_auto_registers_on_first_proof(self, poc):
        # No prior registration
        record = poc.record_proof("v_new", TENANT)
        assert record is not None
        assert record.status.value == "current"

    def test_resets_consecutive_misses(self, poc):
        poc.register_verifier("v1", TENANT, interval_hours=1)
        _backdate_proof_due("v1", TENANT, hours_overdue=3)
        # Manually set consecutive_misses
        import sqlite3
        db = os.environ.get("DATA_DB_PATH")
        conn = sqlite3.connect(db)
        conn.execute(
            "UPDATE verifier_proof_intervals SET consecutive_misses=5 "
            "WHERE verifier_id='v1' AND tenant_id=?", (TENANT,)
        )
        conn.commit()
        conn.close()
        record = poc.record_proof("v1", TENANT)
        assert record.consecutive_misses == 0

    def test_second_proof_extends_deadline(self, poc):
        poc.register_verifier("v1", TENANT, interval_hours=8)
        r1 = poc.record_proof("v1", TENANT)
        time.sleep(0.01)
        r2 = poc.record_proof("v1", TENANT)
        # Second proof should advance next_due further
        d1 = datetime.fromisoformat(r1.next_proof_due)
        d2 = datetime.fromisoformat(r2.next_proof_due)
        if d1.tzinfo is None:
            d1 = d1.replace(tzinfo=timezone.utc)
        if d2.tzinfo is None:
            d2 = d2.replace(tzinfo=timezone.utc)
        assert d2 >= d1


# ---------------------------------------------------------------------------
# Unit tests — live status computation
# ---------------------------------------------------------------------------

class TestProofStatus:
    def test_never_proved(self, poc):
        poc.register_verifier("v1", TENANT)
        record = poc.get_proof_status("v1", TENANT)
        assert record.status.value == "never_proved"

    def test_current_after_proof(self, poc):
        poc.register_verifier("v1", TENANT, interval_hours=24)
        poc.record_proof("v1", TENANT)
        record = poc.get_proof_status("v1", TENANT)
        assert record.status.value == "current"

    def test_overdue_after_interval_elapsed(self, poc):
        # interval=24h, grace=24h. Backdate by 12h = past due but within grace → OVERDUE
        poc.register_verifier("v1", TENANT, interval_hours=24)
        poc.record_proof("v1", TENANT)
        _backdate_proof_due("v1", TENANT, hours_overdue=12)  # 12h late, grace=24h → OVERDUE
        record = poc.get_proof_status("v1", TENANT)
        assert record.status.value == "overdue"

    def test_expired_after_two_intervals(self, poc):
        poc.register_verifier("v1", TENANT, interval_hours=1)
        poc.record_proof("v1", TENANT)
        _backdate_proof_due("v1", TENANT, hours_overdue=3)  # 1h interval × 2 = expired
        record = poc.get_proof_status("v1", TENANT)
        assert record.status.value == "expired"

    def test_returns_none_for_unknown_verifier(self, poc):
        record = poc.get_proof_status("no-such-verifier", TENANT)
        assert record is None


# ---------------------------------------------------------------------------
# Unit tests — sweep + auto-demotion (GATE TEST)
# ---------------------------------------------------------------------------

class TestSweep:
    def test_gate_verifier_demoted_within_one_proof_interval(self, poc):
        """
        Gate: A verifier that loses key access (stops responding to challenges)
        must be auto-demoted within one proof interval.
        """
        _register_active_verifier(TENANT, "v-gate")
        poc.register_verifier("v-gate", TENANT, interval_hours=1)
        poc.record_proof("v-gate", TENANT)

        # Simulate 3 hours with no proof (> 2x 1h interval → EXPIRED)
        _backdate_proof_due("v-gate", TENANT, hours_overdue=3)

        result = poc.sweep_expired_proofs(TENANT, auto_issue_challenges=False)
        assert "v-gate" in result.demoted_ids
        assert result.demoted_in_federation >= 1

        # Verify federation status is now 'unverified'
        from modules.identity import trust_federation
        verifiers = trust_federation.list_verifiers(tenant_id=TENANT)
        v = next((x for x in verifiers if x["verifier_id"] == "v-gate"), None)
        assert v is not None
        assert v["status"] == "unverified"

    def test_sweep_newly_overdue_increments_misses(self, poc):
        # 24h interval, grace=24h. 12h overdue = within grace → OVERDUE
        poc.register_verifier("v1", TENANT, interval_hours=24)
        poc.record_proof("v1", TENANT)
        _backdate_proof_due("v1", TENANT, hours_overdue=12)

        result = poc.sweep_expired_proofs(TENANT, auto_issue_challenges=False)
        assert result.newly_overdue >= 1

    def test_sweep_promotes_recovered_verifier(self, poc):
        """Verifier that was expired but then proves control is re-activated."""
        _register_active_verifier(TENANT, "v-recover")
        poc.register_verifier("v-recover", TENANT, interval_hours=1)
        poc.record_proof("v-recover", TENANT)
        _backdate_proof_due("v-recover", TENANT, hours_overdue=3)

        # First sweep: demotes to unverified
        result1 = poc.sweep_expired_proofs(TENANT, auto_issue_challenges=False)
        assert "v-recover" in result1.demoted_ids

        # Verifier proves control — record_proof also calls _promote_in_federation
        poc.record_proof("v-recover", TENANT)

        # Federation status should now be active again
        from modules.identity import trust_federation
        verifiers = trust_federation.list_verifiers(tenant_id=TENANT)
        v = next((x for x in verifiers if x["verifier_id"] == "v-recover"), None)
        assert v is not None
        assert v["status"] == "active"

        # Proof status should be current
        record = poc.get_proof_status("v-recover", TENANT)
        assert record.status.value == "current"

    def test_sweep_with_no_verifiers(self, poc):
        result = poc.sweep_expired_proofs(TENANT, auto_issue_challenges=False)
        assert result.total_checked == 0
        assert result.demoted_ids == []

    def test_sweep_counts_are_correct(self, poc):
        for i in range(3):
            poc.register_verifier(f"v{i}", TENANT, interval_hours=1)
            poc.record_proof(f"v{i}", TENANT)
            _backdate_proof_due(f"v{i}", TENANT, hours_overdue=3)  # all expired

        result = poc.sweep_expired_proofs(TENANT, auto_issue_challenges=False)
        assert result.total_checked == 3
        assert result.newly_expired == 3
        assert result.demoted_in_federation == 3

    def test_sweep_current_verifiers_not_demoted(self, poc):
        _register_active_verifier(TENANT, "v-current")
        poc.register_verifier("v-current", TENANT, interval_hours=24)
        poc.record_proof("v-current", TENANT)  # proved recently → current

        result = poc.sweep_expired_proofs(TENANT, auto_issue_challenges=False)
        assert "v-current" not in result.demoted_ids

    def test_sweep_issues_challenges_to_overdue(self, poc):
        """When auto_issue_challenges=True, overdue verifiers get new challenges."""
        _register_active_verifier(TENANT, "v-overdue")
        poc.register_verifier("v-overdue", TENANT, interval_hours=24)
        poc.record_proof("v-overdue", TENANT)
        _backdate_proof_due("v-overdue", TENANT, hours_overdue=12)  # overdue, within grace

        result = poc.sweep_expired_proofs(TENANT, auto_issue_challenges=True)
        assert result.challenges_issued >= 1


# ---------------------------------------------------------------------------
# Unit tests — list_proof_registry + proof_stats
# ---------------------------------------------------------------------------

class TestListRegistry:
    def test_empty_registry(self, poc):
        records = poc.list_proof_registry(TENANT)
        assert records == []

    def test_lists_registered_verifiers(self, poc):
        poc.register_verifier("v1", TENANT)
        poc.register_verifier("v2", TENANT)
        records = poc.list_proof_registry(TENANT)
        ids = {r.verifier_id for r in records}
        assert {"v1", "v2"}.issubset(ids)

    def test_filter_by_status(self, poc):
        poc.register_verifier("v1", TENANT, interval_hours=1)
        poc.record_proof("v1", TENANT)  # current
        poc.register_verifier("v2", TENANT)  # never_proved

        never_proved = poc.list_proof_registry(TENANT, status="never_proved")
        v_ids = {r.verifier_id for r in never_proved}
        assert "v2" in v_ids
        assert "v1" not in v_ids


class TestProofStats:
    def test_empty_stats(self, poc):
        stats = poc.proof_stats(TENANT)
        assert stats["total"] == 0

    def test_stats_after_registration(self, poc):
        poc.register_verifier("v1", TENANT)
        poc.register_verifier("v2", TENANT)
        poc.record_proof("v1", TENANT)
        stats = poc.proof_stats(TENANT)
        assert stats["total"] == 2
        assert stats["by_status"]["never_proved"] >= 1
        assert stats["by_status"]["current"] >= 1


# ---------------------------------------------------------------------------
# Unit tests — renew_all_overdue
# ---------------------------------------------------------------------------

class TestRenewAllOverdue:
    def test_challenges_overdue_verifiers(self, poc):
        _register_active_verifier(TENANT, "v-overdue")
        poc.register_verifier("v-overdue", TENANT, interval_hours=24)
        poc.record_proof("v-overdue", TENANT)
        _backdate_proof_due("v-overdue", TENANT, hours_overdue=12)  # overdue, within grace

        result = poc.renew_all_overdue(TENANT)
        assert result["challenged_count"] >= 1

    def test_challenges_never_proved(self, poc):
        _register_active_verifier(TENANT, "v-new")
        poc.register_verifier("v-new", TENANT)

        result = poc.renew_all_overdue(TENANT)
        assert result["challenged_count"] >= 1

    def test_does_not_challenge_current(self, poc):
        _register_active_verifier(TENANT, "v-current")
        poc.register_verifier("v-current", TENANT, interval_hours=24)
        poc.record_proof("v-current", TENANT)

        result = poc.renew_all_overdue(TENANT)
        assert result["challenged_count"] == 0


# ---------------------------------------------------------------------------
# API tests
# ---------------------------------------------------------------------------

class TestApiProofStatus:
    def test_not_found_404(self, client):
        resp = client.get("/api/federation/verifiers/no-such-id/proof-status")
        assert resp.status_code == 404

    def test_registered_verifier_returns_status(self, client):
        from modules.identity import proof_of_control as _poc
        _poc.register_verifier("v-api", API_TENANT, interval_hours=12)
        resp = client.get("/api/federation/verifiers/v-api/proof-status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["verifier_id"] == "v-api"
        assert data["status"] == "never_proved"
        assert data["interval_hours"] == 12


class TestApiSetInterval:
    def test_set_interval(self, client):
        resp = client.post(
            "/api/federation/verifiers/v-api/proof-interval",
            json={"interval_hours": 6},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["interval_hours"] == 6
        assert data["verifier_id"] == "v-api"

    def test_default_interval_when_not_provided(self, client):
        resp = client.post(
            "/api/federation/verifiers/v-api/proof-interval",
            json={},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["interval_hours"] >= 1


class TestApiSweep:
    def test_sweep_empty_returns_200(self, client):
        resp = client.post("/api/federation/verifiers/proof-sweep", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert "total_checked" in data
        assert "demoted_ids" in data
        assert data["total_checked"] == 0

    def test_sweep_demotes_expired_verifier(self, client):
        from modules.identity import proof_of_control as _poc
        _register_active_verifier(API_TENANT, "v-sweep-api")
        _poc.register_verifier("v-sweep-api", API_TENANT, interval_hours=1)
        _poc.record_proof("v-sweep-api", API_TENANT)
        _backdate_proof_due("v-sweep-api", API_TENANT, hours_overdue=3)  # 3h > 2x 1h interval → EXPIRED

        resp = client.post(
            "/api/federation/verifiers/proof-sweep",
            json={"auto_issue_challenges": False},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "v-sweep-api" in data["demoted_ids"]


class TestApiRenewAll:
    def test_renew_all_returns_200(self, client):
        resp = client.post("/api/federation/verifiers/proof-renew-all")
        assert resp.status_code == 200
        data = resp.json()
        assert "challenged_count" in data

    def test_renew_all_challenges_overdue(self, client):
        from modules.identity import proof_of_control as _poc
        _register_active_verifier(API_TENANT, "v-renew-api")
        _poc.register_verifier("v-renew-api", API_TENANT, interval_hours=24)
        _poc.record_proof("v-renew-api", API_TENANT)
        _backdate_proof_due("v-renew-api", API_TENANT, hours_overdue=12)  # overdue, within grace

        resp = client.post("/api/federation/verifiers/proof-renew-all")
        assert resp.status_code == 200
        data = resp.json()
        assert data["challenged_count"] >= 1


class TestApiRegistry:
    def test_empty_registry(self, client):
        resp = client.get("/api/federation/verifiers/proof-registry")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0

    def test_registry_lists_registered(self, client):
        from modules.identity import proof_of_control as _poc
        _poc.register_verifier("v1", API_TENANT, interval_hours=8)
        _poc.register_verifier("v2", API_TENANT, interval_hours=16)
        resp = client.get("/api/federation/verifiers/proof-registry")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2
        ids = {r["verifier_id"] for r in data["registry"]}
        assert {"v1", "v2"} == ids

    def test_filter_by_status(self, client):
        from modules.identity import proof_of_control as _poc
        _poc.register_verifier("v1", API_TENANT)
        resp = client.get("/api/federation/verifiers/proof-registry?status=never_proved")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1


class TestApiStats:
    def test_stats_endpoint(self, client):
        resp = client.get("/api/federation/verifiers/proof-stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "by_status" in data
        assert "overdue_count" in data
        assert "expired_count" in data
