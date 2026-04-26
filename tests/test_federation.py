"""
Tests for modules/identity/federation.py — Federated Agent Trust (FAT).

Coverage:
  - initiate_handshake creates a signed pending offer
  - verify_offer_signature roundtrips
  - accept_handshake establishes mutual trust + audit emission
  - reject_handshake records the decline
  - revoke_trust marks active trusts revoked
  - find_active_trust gates by status, expiry, and scope
  - list_trusts / list_handshakes filters
  - validation: required args, distinct orgs, non-empty scope
  - acceptance guards: only the named remote may accept; expired offers
    are rejected; signature must verify
"""

from __future__ import annotations

import importlib
import os
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest


@pytest.fixture
def fed(tmp_path, monkeypatch):
    db = tmp_path / "test_fed.db"
    monkeypatch.setenv("DATA_DB_PATH", str(db))
    import modules.identity.federation as m
    importlib.reload(m)
    m.init_db()
    return m


# ── Handshake initiation ──────────────────────────────────────────────────────


class TestInitiateHandshake:
    def test_creates_pending_offer_with_signature(self, fed):
        offer = fed.initiate_handshake(
            local_org_id="acme",
            remote_org_id="beta",
            accepted_scope=["agent-acme-*"],
            policy_summary={"soc2": True},
        )
        assert offer.handshake_id
        assert offer.status == "pending"
        assert offer.local_org_id == "acme"
        assert offer.remote_org_id == "beta"
        assert offer.accepted_scope == ["agent-acme-*"]
        assert offer.signature  # non-empty
        assert fed.verify_offer_signature(offer)

    def test_rejects_self_federation(self, fed):
        with pytest.raises(ValueError, match="distinct"):
            fed.initiate_handshake(
                local_org_id="acme", remote_org_id="acme",
                accepted_scope=["agent-*"],
            )

    def test_rejects_empty_scope(self, fed):
        with pytest.raises(ValueError, match="scope"):
            fed.initiate_handshake(
                local_org_id="acme", remote_org_id="beta",
                accepted_scope=[],
            )

    def test_rejects_missing_org_ids(self, fed):
        with pytest.raises(ValueError, match="required"):
            fed.initiate_handshake(
                local_org_id="", remote_org_id="beta",
                accepted_scope=["agent-*"],
            )

    def test_emits_initiated_audit(self, fed):
        with mock.patch.object(fed, "log_event") as fake:
            fed.initiate_handshake(
                local_org_id="acme", remote_org_id="beta",
                accepted_scope=["agent-acme-*"],
            )
        types = {c.args[0].value for c in fake.call_args_list}
        assert "federation.handshake.initiated" in types


# ── Signature verification ────────────────────────────────────────────────────


class TestSignatureVerification:
    def test_unmodified_offer_verifies(self, fed):
        offer = fed.initiate_handshake(
            local_org_id="a", remote_org_id="b",
            accepted_scope=["x-*"],
        )
        assert fed.verify_offer_signature(offer)

    def test_tampered_scope_fails_verification(self, fed):
        offer = fed.initiate_handshake(
            local_org_id="a", remote_org_id="b",
            accepted_scope=["x-*"],
        )
        offer.accepted_scope.append("y-*")  # tamper
        assert not fed.verify_offer_signature(offer)

    def test_tampered_remote_org_fails_verification(self, fed):
        offer = fed.initiate_handshake(
            local_org_id="a", remote_org_id="b",
            accepted_scope=["x-*"],
        )
        offer.remote_org_id = "evil"
        assert not fed.verify_offer_signature(offer)


# ── Acceptance ────────────────────────────────────────────────────────────────


class TestAcceptHandshake:
    def test_remote_can_accept_pending_offer(self, fed):
        offer = fed.initiate_handshake(
            local_org_id="acme", remote_org_id="beta",
            accepted_scope=["agent-acme-*"],
        )
        trust = fed.accept_handshake(
            handshake_id=offer.handshake_id,
            accepting_org_id="beta",
            remote_federation_key="beta-key",
            accepted_by="ops@beta.com",
        )
        assert trust.status == "active"
        assert trust.local_org_id == "beta"
        assert trust.remote_org_id == "acme"
        assert trust.accepted_scope == ["agent-acme-*"]

    def test_only_remote_org_may_accept(self, fed):
        offer = fed.initiate_handshake(
            local_org_id="acme", remote_org_id="beta",
            accepted_scope=["agent-acme-*"],
        )
        with pytest.raises(ValueError, match="only remote_org_id"):
            fed.accept_handshake(
                handshake_id=offer.handshake_id,
                accepting_org_id="evil-corp",
                remote_federation_key="x",
                accepted_by="x",
            )

    def test_expired_handshake_cannot_be_accepted(self, fed):
        offer = fed.initiate_handshake(
            local_org_id="acme", remote_org_id="beta",
            accepted_scope=["agent-acme-*"],
            ttl_hours=1,
        )
        # Backdate expiry to force the expiration check.
        with fed._cursor() as cur:
            past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
            cur.execute(
                "UPDATE federation_handshakes SET expires_at=? WHERE handshake_id=?",
                (past, offer.handshake_id),
            )
        with pytest.raises(ValueError, match="expired"):
            fed.accept_handshake(
                handshake_id=offer.handshake_id,
                accepting_org_id="beta",
                remote_federation_key="k",
                accepted_by="ops",
            )

    def test_already_accepted_cannot_be_re_accepted(self, fed):
        offer = fed.initiate_handshake(
            local_org_id="acme", remote_org_id="beta",
            accepted_scope=["agent-acme-*"],
        )
        fed.accept_handshake(
            handshake_id=offer.handshake_id,
            accepting_org_id="beta",
            remote_federation_key="k",
            accepted_by="ops",
        )
        with pytest.raises(ValueError, match="not pending"):
            fed.accept_handshake(
                handshake_id=offer.handshake_id,
                accepting_org_id="beta",
                remote_federation_key="k2",
                accepted_by="ops",
            )

    def test_acceptance_emits_two_audit_events(self, fed):
        offer = fed.initiate_handshake(
            local_org_id="acme", remote_org_id="beta",
            accepted_scope=["agent-acme-*"],
        )
        with mock.patch.object(fed, "log_event") as fake:
            fed.accept_handshake(
                handshake_id=offer.handshake_id,
                accepting_org_id="beta",
                remote_federation_key="k",
                accepted_by="ops",
            )
        types = {c.args[0].value for c in fake.call_args_list}
        assert "federation.handshake.accepted" in types
        assert "federation.trust.established" in types


# ── Rejection ─────────────────────────────────────────────────────────────────


class TestRejectHandshake:
    def test_remote_can_reject(self, fed):
        offer = fed.initiate_handshake(
            local_org_id="acme", remote_org_id="beta",
            accepted_scope=["agent-acme-*"],
        )
        fed.reject_handshake(
            handshake_id=offer.handshake_id,
            rejecting_org_id="beta",
            reason="policy mismatch",
        )
        latest = fed.get_handshake(offer.handshake_id)
        assert latest.status == "rejected"

    def test_rejection_emits_audit(self, fed):
        offer = fed.initiate_handshake(
            local_org_id="a", remote_org_id="b",
            accepted_scope=["x-*"],
        )
        with mock.patch.object(fed, "log_event") as fake:
            fed.reject_handshake(
                handshake_id=offer.handshake_id,
                rejecting_org_id="b",
                reason="x",
            )
        types = {c.args[0].value for c in fake.call_args_list}
        assert "federation.handshake.rejected" in types


# ── Revocation ────────────────────────────────────────────────────────────────


class TestRevokeTrust:
    def test_revoke_marks_trust_revoked(self, fed):
        offer = fed.initiate_handshake(
            local_org_id="acme", remote_org_id="beta",
            accepted_scope=["agent-acme-*"],
        )
        trust = fed.accept_handshake(
            handshake_id=offer.handshake_id,
            accepting_org_id="beta",
            remote_federation_key="k",
            accepted_by="ops",
        )
        revoked = fed.revoke_trust(
            trust_id=trust.trust_id,
            local_org_id="beta",
            revoked_by="ops@beta.com",
            reason="rotation",
        )
        assert revoked.status == "revoked"
        assert revoked.revoked_by == "ops@beta.com"
        assert revoked.revoked_reason == "rotation"

    def test_revocation_audit_event(self, fed):
        offer = fed.initiate_handshake(
            local_org_id="acme", remote_org_id="beta",
            accepted_scope=["agent-acme-*"],
        )
        trust = fed.accept_handshake(
            handshake_id=offer.handshake_id,
            accepting_org_id="beta",
            remote_federation_key="k",
            accepted_by="ops",
        )
        with mock.patch.object(fed, "log_event") as fake:
            fed.revoke_trust(
                trust_id=trust.trust_id,
                local_org_id="beta",
                revoked_by="ops",
                reason="x",
            )
        assert any(
            c.args[0].value == "federation.trust.revoked"
            for c in fake.call_args_list
        )

    def test_revoking_unknown_trust_returns_none(self, fed):
        result = fed.revoke_trust(
            trust_id="does-not-exist",
            local_org_id="acme",
            revoked_by="ops",
        )
        assert result is None


# ── Active trust lookup ───────────────────────────────────────────────────────


class TestFindActiveTrust:
    def _establish(self, fed, scope):
        offer = fed.initiate_handshake(
            local_org_id="acme", remote_org_id="beta",
            accepted_scope=scope,
        )
        return fed.accept_handshake(
            handshake_id=offer.handshake_id,
            accepting_org_id="beta",
            remote_federation_key="k",
            accepted_by="ops",
        )

    def test_returns_trust_for_in_scope_agent(self, fed):
        self._establish(fed, ["agent-acme-*"])
        # Look from beta's perspective — the trust we created has
        # local_org_id="beta", remote_org_id="acme".
        trust = fed.find_active_trust(
            local_org_id="beta",
            remote_org_id="acme",
            agent_label="agent-acme-finance",
        )
        assert trust is not None
        assert trust.local_org_id == "beta"
        assert trust.remote_org_id == "acme"

    def test_returns_none_for_out_of_scope_agent(self, fed):
        self._establish(fed, ["agent-acme-finance"])
        trust = fed.find_active_trust(
            local_org_id="beta",
            remote_org_id="acme",
            agent_label="agent-acme-eng",
        )
        assert trust is None

    def test_returns_none_when_revoked(self, fed):
        established = self._establish(fed, ["agent-acme-*"])
        fed.revoke_trust(
            trust_id=established.trust_id,
            local_org_id="beta",
            revoked_by="ops",
            reason="test",
        )
        trust = fed.find_active_trust(
            local_org_id="beta",
            remote_org_id="acme",
            agent_label="agent-acme-finance",
        )
        assert trust is None

    def test_returns_none_when_no_handshake_exists(self, fed):
        trust = fed.find_active_trust(
            local_org_id="orphan-a",
            remote_org_id="orphan-b",
            agent_label="x",
        )
        assert trust is None


# ── Listings ──────────────────────────────────────────────────────────────────


class TestListings:
    def test_list_trusts_filters_by_status(self, fed):
        offer = fed.initiate_handshake(
            local_org_id="acme", remote_org_id="beta",
            accepted_scope=["agent-acme-*"],
        )
        trust = fed.accept_handshake(
            handshake_id=offer.handshake_id,
            accepting_org_id="beta",
            remote_federation_key="k",
            accepted_by="ops",
        )
        active = fed.list_trusts(local_org_id="beta", status="active")
        assert any(t.trust_id == trust.trust_id for t in active)

        fed.revoke_trust(
            trust_id=trust.trust_id, local_org_id="beta",
            revoked_by="ops", reason="x",
        )
        active_after = fed.list_trusts(local_org_id="beta", status="active")
        assert all(t.trust_id != trust.trust_id for t in active_after)
        revoked = fed.list_trusts(local_org_id="beta", status="revoked")
        assert any(t.trust_id == trust.trust_id for t in revoked)

    def test_list_handshakes_filters(self, fed):
        offer1 = fed.initiate_handshake(
            local_org_id="acme", remote_org_id="beta",
            accepted_scope=["agent-acme-*"],
        )
        offer2 = fed.initiate_handshake(
            local_org_id="acme", remote_org_id="gamma",
            accepted_scope=["agent-acme-*"],
        )
        all_acme = fed.list_handshakes(local_org_id="acme")
        ids = {o.handshake_id for o in all_acme}
        assert offer1.handshake_id in ids
        assert offer2.handshake_id in ids


# ── Idempotent init ───────────────────────────────────────────────────────────


def test_init_db_idempotent(fed):
    fed.init_db()
    fed.init_db()  # must not raise
    # Sanity: schema is present
    with fed._cursor() as cur:
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND "
            "name IN ('federation_handshakes', 'federation_trusts')"
        )
        names = {r["name"] for r in cur.fetchall()}
    assert names == {"federation_handshakes", "federation_trusts"}
