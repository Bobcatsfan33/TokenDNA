"""
Tests for modules/product/threat_sharing_flywheel.py — network-effect layer
on top of the threat-sharing catalog.

Coverage:
  - Hit recording is idempotent on (network_playbook_id, tenant_hash, match_id).
  - confirm_hit flips the flag once; second call is a no-op.
  - score_network_playbook combines confirmed-hit volume + tenant breadth +
    age decay; saturates correctly.
  - Industry tag round-trip + validation.
  - Industry digest excludes the requesting tenant via tenant_hash and
    returns confirmed-then-broad ordering.
  - auto_sync_subscribed pulls only playbooks above the threshold and is
    idempotent.
  - Tenant isolation on every surface.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture()
def tmp_db(tmp_path, monkeypatch):
    db = str(tmp_path / "fw.db")
    monkeypatch.setenv("DATA_DB_PATH", db)
    yield db


@pytest.fixture()
def stack(tmp_db):
    import importlib

    import modules.identity.intent_correlation as ic
    import modules.product.threat_sharing as ts
    import modules.product.threat_sharing_flywheel as fw

    for mod in (ic, ts, fw):
        importlib.reload(mod)
    fw.init_db()
    return {"ic": ic, "ts": ts, "fw": fw}


def _publish_one(stack, tenant_id="tenant-pub", name="Acme Pattern") -> str:
    """Helper — create a custom playbook and publish it so we have a
    network_playbook_id to score against."""
    ic = stack["ic"]
    ts = stack["ts"]
    pid = ic.add_playbook(
        tenant_id=tenant_id,
        name=name,
        description="Test pattern",
        severity="high",
        steps=[{"category": "auth_anomaly", "min_confidence": 0.5}],
        window_seconds=600,
    )
    ts.opt_in(tenant_id)
    return ts.publish_playbook(tenant_id, pid)["network_playbook_id"]


# ─────────────────────────────────────────────────────────────────────────────
# Hit recording
# ─────────────────────────────────────────────────────────────────────────────

class TestHitRecording:
    def test_record_hit_returns_row(self, stack):
        nid = _publish_one(stack)
        out = stack["fw"].record_network_hit("tenant-recv", nid, match_id="m1")
        assert out is not None
        assert out["network_playbook_id"] == nid
        assert out["confirmed"] is False
        # tenant_hash is exposed (anonymized handle), raw tenant_id is not.
        assert out["tenant_hash"] != "tenant-recv"
        assert len(out["tenant_hash"]) == 32

    def test_record_hit_idempotent(self, stack):
        nid = _publish_one(stack)
        first = stack["fw"].record_network_hit("tenant-recv", nid, match_id="m1")
        again = stack["fw"].record_network_hit("tenant-recv", nid, match_id="m1")
        assert first is not None
        assert again is None

    def test_record_hit_carries_industry(self, stack):
        nid = _publish_one(stack)
        stack["fw"].set_tenant_industry("tenant-recv", "finance")
        out = stack["fw"].record_network_hit("tenant-recv", nid)
        assert out["industry"] == "finance"


# ─────────────────────────────────────────────────────────────────────────────
# confirm_hit
# ─────────────────────────────────────────────────────────────────────────────

class TestConfirmHit:
    def test_confirm_once(self, stack):
        nid = _publish_one(stack)
        hit = stack["fw"].record_network_hit("tenant-r", nid, match_id="x")
        assert stack["fw"].confirm_hit(hit["hit_id"], "operator@x") is True
        assert stack["fw"].confirm_hit(hit["hit_id"], "operator@x") is False  # already

    def test_confirm_unknown(self, stack):
        assert stack["fw"].confirm_hit("nhit:bogus", "operator") is False


# ─────────────────────────────────────────────────────────────────────────────
# Scoring
# ─────────────────────────────────────────────────────────────────────────────

class TestScoring:
    def test_zero_hits_zero_confidence(self, stack):
        nid = _publish_one(stack)
        s = stack["fw"].score_network_playbook(nid)
        assert s.confidence == 0.0
        assert s.total_hits == 0

    def test_confirmed_hits_dominate(self, stack):
        nid = _publish_one(stack)
        # Three different tenants — each confirms.
        for t in ("tenant-a", "tenant-b", "tenant-c"):
            hit = stack["fw"].record_network_hit(t, nid, match_id=f"m-{t}")
            stack["fw"].confirm_hit(hit["hit_id"], "operator")
        s = stack["fw"].score_network_playbook(nid)
        assert s.confirmed_hits == 3
        assert s.distinct_tenants == 3
        assert s.confidence > 0.35  # confirmed + breadth contribute
        assert s.age_decay == pytest.approx(1.0, abs=0.01)

    def test_unconfirmed_hits_contribute_only_breadth(self, stack):
        nid = _publish_one(stack)
        for t in ("a", "b", "c"):
            stack["fw"].record_network_hit(t, nid, match_id=f"m-{t}")
        s = stack["fw"].score_network_playbook(nid)
        # No confirmations → hit_component is zero, only breadth matters.
        assert s.confirmed_hits == 0
        assert s.distinct_tenants == 3
        assert 0.0 < s.confidence < 0.5

    def test_breadth_saturation(self, stack):
        # Pre-saturation breadth still shouldn't blow past 1.0.
        nid = _publish_one(stack)
        for i in range(40):
            hit = stack["fw"].record_network_hit(f"tenant-{i}", nid, match_id=f"m{i}")
            stack["fw"].confirm_hit(hit["hit_id"], "ops")
        s = stack["fw"].score_network_playbook(nid)
        assert 0.0 < s.confidence <= 1.0


# ─────────────────────────────────────────────────────────────────────────────
# Industry tag + digest
# ─────────────────────────────────────────────────────────────────────────────

class TestIndustry:
    def test_tag_round_trip(self, stack):
        stack["fw"].set_tenant_industry("t-1", "finance")
        assert stack["fw"].get_tenant_industry("t-1") == "finance"

    def test_invalid_industry_rejected(self, stack):
        with pytest.raises(ValueError, match="unknown_industry"):
            stack["fw"].set_tenant_industry("t-1", "blockchain-cult")

    def test_digest_empty_when_no_industry(self, stack):
        out = stack["fw"].get_industry_digest("t-untagged")
        assert out["industry"] is None
        assert out["items"] == []

    def test_digest_excludes_requesting_tenant(self, stack):
        nid = _publish_one(stack)
        stack["fw"].set_tenant_industry("t-self", "finance")
        stack["fw"].set_tenant_industry("t-peer", "finance")
        # Self hit (should NOT appear in digest) + peer hit (should).
        h_self = stack["fw"].record_network_hit("t-self", nid, match_id="self-1")
        h_peer = stack["fw"].record_network_hit("t-peer", nid, match_id="peer-1")
        stack["fw"].confirm_hit(h_self["hit_id"], "ops")
        stack["fw"].confirm_hit(h_peer["hit_id"], "ops")

        digest = stack["fw"].get_industry_digest("t-self", days=30)
        assert digest["industry"] == "finance"
        assert len(digest["items"]) == 1
        item = digest["items"][0]
        assert item["network_playbook_id"] == nid
        assert item["peer_tenants"] == 1   # only t-peer counts
        assert item["confirmed_hits"] == 1

    def test_digest_excludes_other_industries(self, stack):
        nid = _publish_one(stack)
        stack["fw"].set_tenant_industry("t-self", "finance")
        stack["fw"].set_tenant_industry("t-other", "healthcare")
        stack["fw"].record_network_hit("t-other", nid)
        out = stack["fw"].get_industry_digest("t-self")
        assert out["items"] == []


# ─────────────────────────────────────────────────────────────────────────────
# Subscription + auto-sync
# ─────────────────────────────────────────────────────────────────────────────

class TestAutoSubscribe:
    def test_default_off(self, stack):
        sub = stack["fw"].get_subscription("t-x")
        assert sub["auto_subscribe"] is False

    def test_set_round_trip(self, stack):
        stack["fw"].set_auto_subscribe("t-x", enabled=True, min_confidence=0.6)
        sub = stack["fw"].get_subscription("t-x")
        assert sub["auto_subscribe"] is True
        assert sub["min_confidence"] == 0.6

    def test_off_falls_through_to_plain_sync(self, stack):
        nid = _publish_one(stack)
        stack["ts"].opt_in("t-recv")
        out = stack["fw"].auto_sync_subscribed("t-recv")
        assert out["auto_subscribe"] is False
        # Plain sync would have pulled the one available playbook.
        assert out["added"] >= 1

    def test_on_pulls_only_above_threshold(self, stack):
        nid_low = _publish_one(stack, name="Low Confidence")
        nid_high = _publish_one(stack, name="High Confidence")
        # Saturate confirmations on nid_high so it scores high.
        for i in range(10):
            h = stack["fw"].record_network_hit(f"tenant-{i}", nid_high, match_id=f"m{i}")
            stack["fw"].confirm_hit(h["hit_id"], "ops")
        # nid_low has zero hits → confidence 0.

        stack["ts"].opt_in("t-recv")
        stack["fw"].set_auto_subscribe("t-recv", enabled=True, min_confidence=0.4)
        out = stack["fw"].auto_sync_subscribed("t-recv")
        assert out["auto_subscribe"] is True
        # Only the high-confidence playbook should propagate.
        assert out["added"] == 1
        assert out["candidates_evaluated"] == 1

    def test_idempotent(self, stack):
        nid = _publish_one(stack)
        for i in range(10):
            h = stack["fw"].record_network_hit(f"t-{i}", nid, match_id=f"m{i}")
            stack["fw"].confirm_hit(h["hit_id"], "ops")
        stack["ts"].opt_in("t-recv")
        stack["fw"].set_auto_subscribe("t-recv", enabled=True, min_confidence=0.3)
        first = stack["fw"].auto_sync_subscribed("t-recv")
        second = stack["fw"].auto_sync_subscribed("t-recv")
        assert first["added"] >= 1
        assert second["added"] == 0


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
        tenant_id="t-routes", tenant_name="R",
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
    def test_industry_round_trip_and_digest(self, app_client):
        client, _ = app_client
        # Bad industry → 400.
        bad = client.post("/api/threat-sharing/industry",
                          json={"industry": "vibes-based-engineering"})
        assert bad.status_code == 400
        # Good industry → 200.
        ok = client.post("/api/threat-sharing/industry",
                         json={"industry": "finance"})
        assert ok.status_code == 200
        digest = client.get("/api/threat-sharing/industry/digest").json()
        assert digest["industry"] == "finance"

    def test_subscription_and_score_routes(self, app_client):
        client, stack = app_client
        nid = _publish_one(stack)
        sub = client.post("/api/threat-sharing/subscription",
                          json={"enabled": True, "min_confidence": 0.5}).json()
        assert sub["auto_subscribe"] is True
        score = client.get(f"/api/threat-sharing/network/{nid}/score").json()
        assert score["network_playbook_id"] == nid

    def test_hit_record_then_confirm(self, app_client):
        client, stack = app_client
        nid = _publish_one(stack)
        rec = client.post(
            f"/api/threat-sharing/network/{nid}/hit",
            json={"match_id": "match-001"},
        ).json()
        assert rec["recorded"] is True
        hit_id = rec["hit"]["hit_id"]
        ack = client.post(
            f"/api/threat-sharing/hits/{hit_id}/confirm",
            json={"confirmed_by": "ops@x"},
        )
        assert ack.status_code == 200
        # Second confirm → 404.
        again = client.post(
            f"/api/threat-sharing/hits/{hit_id}/confirm",
            json={"confirmed_by": "ops@x"},
        )
        assert again.status_code == 404
