"""
Tests for the edge-enforcement parity backend endpoints + the supporting
``attestation_store.list_revoked_certs`` and
``permission_drift.edge_drift_snapshot`` helpers.

The Cloudflare Worker (edge/index.js) consumes these to populate its KV
caches; this test suite locks in the response contract.
"""
from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def isolated_db(monkeypatch, tmp_path):
    """Point every storage module at a throwaway sqlite db for the test."""
    db = tmp_path / "edge.db"
    monkeypatch.setenv("DATA_DB_PATH", str(db))
    monkeypatch.setenv("ATTESTATION_CA_SECRET", "test-ca-secret-32-bytes-aaaaaaa")
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("EDGE_SYNC_TOKEN", "edge-sync-secret-for-tests")
    yield db


@pytest.fixture
def client(isolated_db):
    import api as api_mod  # noqa: PLC0415
    return TestClient(api_mod.app)


# ── Auth ─────────────────────────────────────────────────────────────────────


def test_revoked_certs_requires_edge_sync_token(client):
    r = client.get("/api/edge/revoked-certs")
    assert r.status_code == 401
    assert "X-Edge-Sync-Token" in r.json()["detail"]


def test_drift_snapshot_requires_edge_sync_token(client):
    r = client.get("/api/edge/drift-snapshot")
    assert r.status_code == 401


def test_revoked_certs_rejects_wrong_token(client):
    r = client.get("/api/edge/revoked-certs", headers={"X-Edge-Sync-Token": "wrong"})
    assert r.status_code == 401


def test_revoked_certs_empty_list_when_no_revocations(client):
    r = client.get("/api/edge/revoked-certs",
                   headers={"X-Edge-Sync-Token": "edge-sync-secret-for-tests"})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 0
    assert body["certs"] == []
    assert "generated_at" in body


# ── Revoked certs end-to-end ─────────────────────────────────────────────────


def test_revoked_certs_lists_revoked_only(client, isolated_db):
    from modules.identity import attestation_certificates as ac  # noqa: PLC0415
    from modules.identity import attestation_store as store  # noqa: PLC0415
    store.init_db()

    # Issue + persist 3 certs
    cert_ids = []
    for i in range(3):
        cert = ac.issue_certificate(
            tenant_id="acme", attestation_id=f"att-{i}",
            subject=f"agent-{i}", issuer="trust-authority",
            claims={"role": "worker"},
        )
        store.insert_certificate("acme", cert)
        cert_ids.append(cert["certificate_id"])

    # Revoke certs 0 and 2
    for i in (0, 2):
        store.revoke_certificate(
            tenant_id="acme",
            certificate_id=cert_ids[i],
            revoked_at="2026-04-30T00:00:00Z",
            reason="key_compromise",
        )

    r = client.get("/api/edge/revoked-certs",
                   headers={"X-Edge-Sync-Token": "edge-sync-secret-for-tests"})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2
    returned_ids = {c["cert_id"] for c in body["certs"]}
    assert returned_ids == {cert_ids[0], cert_ids[2]}
    for c in body["certs"]:
        assert c["reason"] == "key_compromise"
        assert c["revoked_at"]


# ── Drift snapshot end-to-end ────────────────────────────────────────────────


def test_drift_snapshot_tier_buckets(isolated_db):
    """Direct unit test of the snapshot helper — easier to assert against
    than the HTTP endpoint."""
    from modules.identity import permission_drift as pd  # noqa: PLC0415
    pd.init_db()

    # Hand-craft drift_alerts rows with varied growth factors
    with pd._cursor() as cur:
        cur.execute("DELETE FROM drift_alerts")
        for agent_id, gf in (
            ("agent-block-1", 3.5),    # BLOCK tier
            ("agent-block-2", 5.5),    # BLOCK clamped to score=1.0
            ("agent-stepup", 2.4),     # STEP_UP
            ("agent-allow", 1.2),      # ALLOW
        ):
            cur.execute(
                """
                INSERT INTO drift_alerts
                  (drift_id, tenant_id, agent_id, policy_id,
                   baseline_weight, current_weight, growth_factor,
                   baseline_date, detected_at, status)
                VALUES (?, 't1', ?, 'p1', 1.0, ?, ?, '2026-01-01', '2026-04-01', 'open')
                """,
                (f"d-{agent_id}", agent_id, gf, gf),
            )
        # An agent with only a closed alert should NOT appear
        cur.execute(
            """
            INSERT INTO drift_alerts
              (drift_id, tenant_id, agent_id, policy_id,
               baseline_weight, current_weight, growth_factor,
               baseline_date, detected_at, status)
            VALUES ('d-x', 't1', 'agent-closed', 'p1', 1.0, 4.0, 4.0,
                    '2026-01-01', '2026-04-01', 'approved')
            """,
        )

    snap = pd.edge_drift_snapshot()
    by_id = {row["agent_id"]: row for row in snap}
    assert "agent-closed" not in by_id

    assert by_id["agent-block-1"]["tier"] == "BLOCK"
    assert by_id["agent-block-1"]["score"] == 0.7   # 3.5/5.0
    assert by_id["agent-block-2"]["tier"] == "BLOCK"
    assert by_id["agent-block-2"]["score"] == 1.0   # clamped
    assert by_id["agent-stepup"]["tier"] == "STEP_UP"
    assert 0.5 < by_id["agent-stepup"]["score"] < 0.8
    assert by_id["agent-allow"]["tier"] == "ALLOW"
    for row in snap:
        assert "growth_factor=" in row["reason"]


def test_drift_snapshot_endpoint_returns_well_formed_payload(client, isolated_db):
    r = client.get("/api/edge/drift-snapshot",
                   headers={"X-Edge-Sync-Token": "edge-sync-secret-for-tests"})
    assert r.status_code == 200
    body = r.json()
    assert "generated_at" in body
    assert "count" in body
    assert isinstance(body["agents"], list)
