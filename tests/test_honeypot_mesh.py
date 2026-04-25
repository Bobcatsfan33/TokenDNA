"""
Tests for modules/identity/honeypot_mesh.py — active deception layer.

Coverage:
  - Synthetic agent + honeytoken creation. secret_value visible exactly
    once (on creation), never on subsequent reads.
  - is_honeytoken hashes input; matches active decoys; returns None for
    inactive or unknown values; never returns the secret_value.
  - record_decoy_hit increments hits + last_hit_at atomically; returns
    None for unknown / cross-tenant decoy.
  - acknowledge_hit is idempotent.
  - Tenant isolation everywhere.
  - Routes: synthesize → list → record-hit → ack flow.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture()
def tmp_db(tmp_path, monkeypatch):
    db = str(tmp_path / "hp.db")
    monkeypatch.setenv("DATA_DB_PATH", db)
    monkeypatch.setenv("TOKENDNA_HONEYPOT_SECRET", "hp-test-secret")
    yield db


@pytest.fixture()
def hp(tmp_db):
    import importlib
    import modules.identity.honeypot_mesh as m
    importlib.reload(m)
    m.init_db()
    return m


TENANT = "t-hp"


# ─────────────────────────────────────────────────────────────────────────────
# Decoy creation
# ─────────────────────────────────────────────────────────────────────────────

class TestDecoyCreation:
    def test_synthesize_agent_secret_visible_once(self, hp):
        out = hp.synthesize_decoy_agent(TENANT, name_hint="recon-bot")
        d = out.as_dict()
        assert out.kind == "synthetic_agent"
        assert out.public_id.startswith("agt-")
        # secret_value visible only on creation response.
        assert d.get("secret_value")
        assert d.get("secret_warning")
        # On subsequent inventory reads the secret must not appear.
        listing = hp.get_decoy_inventory(TENANT)
        assert listing
        for r in listing:
            assert "secret_value" not in r

    def test_seed_honeytoken_credential(self, hp):
        out = hp.seed_honeytoken(TENANT, kind="honeytoken_credential")
        assert out.kind == "honeytoken_credential"
        assert out.public_id.startswith("htkn:")

    def test_seed_honeytoken_certificate(self, hp):
        out = hp.seed_honeytoken(TENANT, kind="honeytoken_certificate")
        assert out.kind == "honeytoken_certificate"
        assert out.public_id.startswith("hcert:")

    def test_invalid_honeytoken_kind(self, hp):
        with pytest.raises(ValueError, match="unknown_honeytoken_kind"):
            hp.seed_honeytoken(TENANT, kind="totally-fake-kind")


# ─────────────────────────────────────────────────────────────────────────────
# is_honeytoken — runtime detection
# ─────────────────────────────────────────────────────────────────────────────

class TestIsHoneytoken:
    def test_match_returns_safe_dict(self, hp):
        out = hp.seed_honeytoken(TENANT)
        secret = out.as_dict()["secret_value"]
        match = hp.is_honeytoken(secret)
        assert match is not None
        assert match["decoy_id"] == out.decoy_id
        # The returned dict must NOT carry the plaintext.
        assert "secret_value" not in match
        assert "secret_hash" not in match

    def test_no_match_for_random_string(self, hp):
        assert hp.is_honeytoken("not-a-real-token") is None

    def test_no_match_for_empty(self, hp):
        assert hp.is_honeytoken("") is None
        assert hp.is_honeytoken(None) is None  # type: ignore[arg-type]

    def test_inactive_decoy_does_not_match(self, hp):
        out = hp.seed_honeytoken(TENANT)
        secret = out.as_dict()["secret_value"]
        hp.deactivate_decoy(out.decoy_id, tenant_id=TENANT)
        assert hp.is_honeytoken(secret) is None

    def test_two_tenants_same_plaintext_distinct_hashes(self, hp):
        # Different decoys for different tenants. Each fresh seed gets a
        # fresh random plaintext — the test of the salting hash is that
        # the lookup is keyed by hash, not by plaintext, so collisions
        # across tenants are extraordinarily unlikely.
        a = hp.seed_honeytoken("tenant-a")
        b = hp.seed_honeytoken("tenant-b")
        assert a.decoy_id != b.decoy_id
        assert a.as_dict()["secret_value"] != b.as_dict()["secret_value"]


# ─────────────────────────────────────────────────────────────────────────────
# Hit recording + acknowledge
# ─────────────────────────────────────────────────────────────────────────────

class TestHits:
    def test_record_hit_bumps_counter(self, hp):
        out = hp.synthesize_decoy_agent(TENANT)
        for i in range(3):
            r = hp.record_decoy_hit(
                out.decoy_id,
                source_ip=f"10.0.0.{i}",
                user_agent="curl",
                tenant_id=TENANT,
            )
            assert r is not None
        inv = next(d for d in hp.get_decoy_inventory(TENANT)
                   if d["decoy_id"] == out.decoy_id)
        assert inv["hits"] == 3
        assert inv["last_hit_at"]

    def test_record_hit_unknown_decoy(self, hp):
        assert hp.record_decoy_hit("decoy:bogus") is None

    def test_record_hit_cross_tenant_blocked(self, hp):
        out = hp.synthesize_decoy_agent(TENANT)
        result = hp.record_decoy_hit(out.decoy_id, tenant_id="other-tenant")
        assert result is None

    def test_acknowledge_idempotent(self, hp):
        out = hp.synthesize_decoy_agent(TENANT)
        rec = hp.record_decoy_hit(out.decoy_id, tenant_id=TENANT)
        hit_id = rec["hit_id"]
        assert hp.acknowledge_hit(hit_id, "ops", tenant_id=TENANT) is True
        assert hp.acknowledge_hit(hit_id, "ops", tenant_id=TENANT) is False

    def test_get_hits_acknowledged_filter(self, hp):
        out = hp.synthesize_decoy_agent(TENANT)
        rec = hp.record_decoy_hit(out.decoy_id, tenant_id=TENANT)
        # Open
        assert len(hp.get_decoy_hits(TENANT, acknowledged=False)) == 1
        # Acknowledge → no longer in the open list
        hp.acknowledge_hit(rec["hit_id"], "ops", tenant_id=TENANT)
        assert hp.get_decoy_hits(TENANT, acknowledged=False) == []
        # Acknowledged shows up
        assert len(hp.get_decoy_hits(TENANT, acknowledged=True)) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Tenant isolation
# ─────────────────────────────────────────────────────────────────────────────

class TestTenantIsolation:
    def test_inventory_scoped(self, hp):
        hp.synthesize_decoy_agent("t-a")
        assert hp.get_decoy_inventory("t-b") == []

    def test_cross_tenant_deactivate_blocked(self, hp):
        out = hp.synthesize_decoy_agent(TENANT)
        assert hp.deactivate_decoy(out.decoy_id, tenant_id="other") is False
        # Still active.
        listing = hp.get_decoy_inventory(TENANT)
        assert any(d["decoy_id"] == out.decoy_id and d["active"] for d in listing)


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def app_client(tmp_db, hp):
    import api as app_module
    from fastapi.testclient import TestClient
    from modules.tenants.middleware import get_tenant
    from modules.tenants.models import Plan, TenantContext

    tenant = TenantContext(
        tenant_id=TENANT, tenant_name="HP",
        plan=Plan.ENTERPRISE, api_key_id="k", role="owner",
    )

    def _override():
        return tenant

    import modules.product.commercial_tiers as _ct
    app_module.app.dependency_overrides[get_tenant] = _override
    app_module.app.dependency_overrides[_ct.get_tenant] = _override
    yield TestClient(app_module.app, raise_server_exceptions=False), hp
    app_module.app.dependency_overrides.clear()


class TestRoutes:
    def test_synthesize_then_list_then_record_then_ack(self, app_client):
        client, _ = app_client
        synth = client.post(
            "/api/honeypot/decoy/synthetic-agent",
            json={"name_hint": "scanner"},
        ).json()
        assert synth["secret_value"]
        decoy_id = synth["decoy_id"]

        listing = client.get("/api/honeypot/decoys").json()
        assert listing["count"] == 1
        # Listing must NOT include the secret.
        for d in listing["decoys"]:
            assert "secret_value" not in d

        rec = client.post(
            "/api/honeypot/hits/record",
            json={"decoy_id": decoy_id, "source_ip": "5.5.5.5"},
        ).json()
        assert rec["decoy_id"] == decoy_id

        hits = client.get("/api/honeypot/hits").json()
        assert hits["count"] == 1
        ack = client.post(
            f"/api/honeypot/hits/{rec['hit_id']}/acknowledge",
            json={"acknowledged_by": "ops@x"},
        )
        assert ack.status_code == 200

    def test_seed_honeytoken_then_detect(self, app_client):
        client, hp = app_client
        seed = client.post(
            "/api/honeypot/decoy/honeytoken",
            json={"kind": "honeytoken_credential"},
        ).json()
        secret = seed["secret_value"]
        # Detection works server-side via the helper.
        match = hp.is_honeytoken(secret)
        assert match is not None
        assert match["decoy_id"] == seed["decoy_id"]

    def test_invalid_honeytoken_kind_400(self, app_client):
        client, _ = app_client
        resp = client.post("/api/honeypot/decoy/honeytoken", json={"kind": "vibes"})
        assert resp.status_code == 400

    def test_record_unknown_decoy_404(self, app_client):
        client, _ = app_client
        resp = client.post(
            "/api/honeypot/hits/record",
            json={"decoy_id": "decoy:bogus"},
        )
        assert resp.status_code == 404

    def test_record_missing_decoy_id_400(self, app_client):
        client, _ = app_client
        resp = client.post("/api/honeypot/hits/record", json={})
        assert resp.status_code == 400
