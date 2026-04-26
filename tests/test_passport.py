"""
Tests for Sprint 3-1 — Cross-Vendor Agent Identity Passport

Covers:
  - PassportSubject / PassportScope / PassportIssuer / Passport dataclasses
  - request_passport (PENDING state, correct fields)
  - approve_passport (PENDING → APPROVED, state machine enforcement)
  - issue_passport (APPROVED → ISSUED, signature generated)
  - revoke_passport (ISSUED → REVOKED, with reason)
  - verify_passport (valid, invalid sig, revoked, expired, not found)
  - Passport.is_valid() / trust_score()
  - submit_evidence / list_evidence
  - list_passports with filters
  - get_passport
  - Integration playbooks (list + detail for all 4 vendors)
  - Error paths: double-approve, double-issue, issue-without-approve, etc.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone, timedelta
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    """
    Run every test against a clean store.

    SQLite mode: each test gets a fresh tmp file (default).
    Postgres mode: the tmp file is unused; instead we TRUNCATE the
    passport tables before each test so state cannot leak between
    tests sharing the same database.
    """
    db_path = str(tmp_path / "test_passport.db")
    with mock.patch.dict(os.environ, {"DATA_DB_PATH": db_path}):
        # Re-import after env patch so db path is picked up
        import importlib
        import modules.identity.passport as pm
        importlib.reload(pm)
        from modules.storage.db_backend import should_use_postgres

        if should_use_postgres():
            from modules.storage.pg_connection import get_db_conn

            pm.init_db()
            with get_db_conn() as conn:
                conn.execute("TRUNCATE TABLE passport_evidence, passports CASCADE")
                conn.commit()

        yield pm


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_passport(pm, *, tenant_id="t1", agent_id="agent-001",
                   owner_org="acme", display_name="Test Agent",
                   fingerprint="abc123", permissions=None,
                   resource_patterns=None, requested_by="ops"):
    return pm.request_passport(
        tenant_id=tenant_id,
        agent_id=agent_id,
        owner_org=owner_org,
        display_name=display_name,
        agent_dna_fingerprint=fingerprint,
        permissions=permissions or ["read:events"],
        resource_patterns=resource_patterns or ["arn:aws:*"],
        requested_by=requested_by,
    )


def _full_lifecycle(pm, **kwargs):
    """Create → approve → issue → return."""
    p = _make_passport(pm, **kwargs)
    pm.approve_passport(p.passport_id)
    return pm.issue_passport(p.passport_id)


# ---------------------------------------------------------------------------
# Creation tests
# ---------------------------------------------------------------------------


class TestRequestPassport:
    def test_returns_passport_in_pending_state(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm)
        assert p.passport_id.startswith("tdn-pass-")
        assert p.status == pm.PassportStatus.PENDING

    def test_correct_subject_fields(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm, agent_id="a1", owner_org="o1", display_name="D1",
                           fingerprint="fp1")
        assert p.subject.agent_id == "a1"
        assert p.subject.owner_org == "o1"
        assert p.subject.display_name == "D1"
        assert p.subject.agent_dna_fingerprint == "fp1"

    def test_correct_scope_fields(self, isolated_db):
        pm = isolated_db
        perms = ["read:data", "write:events"]
        patterns = ["arn:aws:bedrock:*"]
        p = _make_passport(pm, permissions=perms, resource_patterns=patterns)
        assert p.scope.permissions == perms
        assert p.scope.resource_patterns == patterns
        assert p.scope.delegation_depth == 0

    def test_issuer_fields_populated(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm)
        assert p.issuer.issuer_id == "tokendna-trust-authority"
        assert p.issuer.issued_by == "ops"
        assert p.issuer.key_id.startswith("tdn-key-")

    def test_revocation_url_format(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm)
        assert p.passport_id in p.revocation_url

    def test_signature_empty_when_pending(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm)
        assert p.signature == ""

    def test_not_before_and_not_after_set(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm)
        nb = datetime.fromisoformat(p.not_before)
        na = datetime.fromisoformat(p.not_after)
        assert (na - nb).days >= 89  # ~90 days validity

    def test_custom_validity_days(self, isolated_db):
        pm = isolated_db
        p = pm.request_passport(
            tenant_id="t1",
            agent_id="a1",
            owner_org="o",
            display_name="D",
            agent_dna_fingerprint="fp",
            permissions=["r"],
            resource_patterns=["*"],
            requested_by="ops",
            validity_days=30,
        )
        nb = datetime.fromisoformat(p.not_before)
        na = datetime.fromisoformat(p.not_after)
        assert 29 <= (na - nb).days <= 30

    def test_passport_persisted_and_retrievable(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm)
        fetched = pm.get_passport(p.passport_id)
        assert fetched is not None
        assert fetched.passport_id == p.passport_id
        assert fetched.status == pm.PassportStatus.PENDING

    def test_tenant_id_stored(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm, tenant_id="tenant-xyz")
        fetched = pm.get_passport(p.passport_id)
        assert fetched.tenant_id == "tenant-xyz"

    def test_model_fingerprint_optional(self, isolated_db):
        pm = isolated_db
        p = pm.request_passport(
            tenant_id="t1",
            agent_id="a1",
            owner_org="o",
            display_name="D",
            agent_dna_fingerprint="fp",
            permissions=["r"],
            resource_patterns=["*"],
            requested_by="ops",
            model_fingerprint="gpt-4-hash",
        )
        fetched = pm.get_passport(p.passport_id)
        assert fetched.subject.model_fingerprint == "gpt-4-hash"

    def test_custom_claims_stored(self, isolated_db):
        pm = isolated_db
        p = pm.request_passport(
            tenant_id="t1",
            agent_id="a1",
            owner_org="o",
            display_name="D",
            agent_dna_fingerprint="fp",
            permissions=["r"],
            resource_patterns=["*"],
            requested_by="ops",
            custom_claims={"env": "prod", "tier": "enterprise"},
        )
        fetched = pm.get_passport(p.passport_id)
        assert fetched.scope.custom_claims["env"] == "prod"


# ---------------------------------------------------------------------------
# State machine tests
# ---------------------------------------------------------------------------


class TestApprovePassport:
    def test_pending_to_approved(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm)
        approved = pm.approve_passport(p.passport_id)
        assert approved.status == pm.PassportStatus.APPROVED

    def test_approved_persisted(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm)
        pm.approve_passport(p.passport_id)
        fetched = pm.get_passport(p.passport_id)
        assert fetched.status == pm.PassportStatus.APPROVED

    def test_cannot_approve_already_approved(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm)
        pm.approve_passport(p.passport_id)
        with pytest.raises(ValueError, match="Cannot approve"):
            pm.approve_passport(p.passport_id)

    def test_cannot_approve_nonexistent(self, isolated_db):
        pm = isolated_db
        with pytest.raises(ValueError, match="not found"):
            pm.approve_passport("tdn-pass-does-not-exist")


class TestIssuePassport:
    def test_approved_to_issued(self, isolated_db):
        pm = isolated_db
        p = _full_lifecycle(pm)
        assert p.status == pm.PassportStatus.ISSUED

    def test_signature_set_on_issue(self, isolated_db):
        pm = isolated_db
        p = _full_lifecycle(pm)
        assert len(p.signature) == 64  # SHA-256 hex

    def test_issued_at_set(self, isolated_db):
        pm = isolated_db
        p = _full_lifecycle(pm)
        assert p.issued_at is not None

    def test_issued_passport_persisted(self, isolated_db):
        pm = isolated_db
        p = _full_lifecycle(pm)
        fetched = pm.get_passport(p.passport_id)
        assert fetched.status == pm.PassportStatus.ISSUED
        assert fetched.signature == p.signature

    def test_cannot_issue_pending(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm)
        with pytest.raises(ValueError, match="Cannot issue"):
            pm.issue_passport(p.passport_id)

    def test_cannot_issue_nonexistent(self, isolated_db):
        pm = isolated_db
        with pytest.raises(ValueError, match="not found"):
            pm.issue_passport("tdn-pass-nope")


class TestRevokePassport:
    def test_issued_to_revoked(self, isolated_db):
        pm = isolated_db
        p = _full_lifecycle(pm)
        revoked = pm.revoke_passport(p.passport_id, "test revocation")
        assert revoked.status == pm.PassportStatus.REVOKED

    def test_revocation_reason_stored(self, isolated_db):
        pm = isolated_db
        p = _full_lifecycle(pm)
        pm.revoke_passport(p.passport_id, "key compromise")
        fetched = pm.get_passport(p.passport_id)
        assert fetched.revocation_reason == "key compromise"
        assert fetched.revoked_at is not None

    def test_revoke_approved_passport(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm)
        pm.approve_passport(p.passport_id)
        revoked = pm.revoke_passport(p.passport_id, "change of mind")
        assert revoked.status == pm.PassportStatus.REVOKED

    def test_cannot_revoke_pending(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm)
        with pytest.raises(ValueError, match="Cannot revoke"):
            pm.revoke_passport(p.passport_id, "reason")

    def test_cannot_revoke_nonexistent(self, isolated_db):
        pm = isolated_db
        with pytest.raises(ValueError, match="not found"):
            pm.revoke_passport("tdn-pass-ghost", "reason")


# ---------------------------------------------------------------------------
# Verification tests
# ---------------------------------------------------------------------------


class TestVerifyPassport:
    def test_valid_passport_verifies(self, isolated_db):
        pm = isolated_db
        p = _full_lifecycle(pm)
        result = pm.verify_passport(p.to_dict())
        assert result["valid"] is True
        assert result["trust_score"] > 0.0
        assert result["passport_id"] == p.passport_id

    def test_invalid_signature_rejected(self, isolated_db):
        pm = isolated_db
        p = _full_lifecycle(pm)
        d = p.to_dict()
        d["signature"] = "deadbeef" * 8  # 64 hex chars, wrong value
        result = pm.verify_passport(d)
        assert result["valid"] is False
        assert "signature" in result["reason"]

    def test_missing_passport_id(self, isolated_db):
        pm = isolated_db
        result = pm.verify_passport({})
        assert result["valid"] is False
        assert "passport_id" in result["reason"]

    def test_nonexistent_passport(self, isolated_db):
        pm = isolated_db
        result = pm.verify_passport({"passport_id": "tdn-pass-ghost"})
        assert result["valid"] is False
        assert "not found" in result["reason"]

    def test_revoked_passport_rejected(self, isolated_db):
        pm = isolated_db
        p = _full_lifecycle(pm)
        pm.revoke_passport(p.passport_id, "security incident")
        result = pm.verify_passport(p.to_dict())
        assert result["valid"] is False
        assert "revoked" in result["reason"]

    def test_pending_passport_rejected(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm)
        result = pm.verify_passport(p.to_dict())
        assert result["valid"] is False

    def test_approved_not_issued_rejected(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm)
        pm.approve_passport(p.passport_id)
        fetched = pm.get_passport(p.passport_id)
        result = pm.verify_passport(fetched.to_dict())
        assert result["valid"] is False

    def test_expired_passport_rejected(self, isolated_db):
        pm = isolated_db
        # Issue a passport then backdating not_after
        p = _full_lifecycle(pm)
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        with pm._cursor() as cur:
            cur.execute(
                "UPDATE passports SET not_after=? WHERE passport_id=?",
                (past, p.passport_id),
            )
        result = pm.verify_passport(p.to_dict())
        assert result["valid"] is False
        assert "expired" in result["reason"]

    def test_result_contains_subject_and_scope(self, isolated_db):
        pm = isolated_db
        p = _full_lifecycle(pm)
        result = pm.verify_passport(p.to_dict())
        assert result["subject"]["agent_id"] is not None
        assert isinstance(result["scope"]["permissions"], list)


# ---------------------------------------------------------------------------
# Validity + trust score
# ---------------------------------------------------------------------------


class TestPassportValidity:
    def test_issued_passport_is_valid(self, isolated_db):
        pm = isolated_db
        p = _full_lifecycle(pm)
        assert p.is_valid() is True

    def test_pending_passport_not_valid(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm)
        assert p.is_valid() is False

    def test_revoked_passport_not_valid(self, isolated_db):
        pm = isolated_db
        p = _full_lifecycle(pm)
        pm.revoke_passport(p.passport_id, "test")
        fetched = pm.get_passport(p.passport_id)
        assert fetched.is_valid() is False

    def test_trust_score_range(self, isolated_db):
        pm = isolated_db
        p = _full_lifecycle(pm)
        score = p.trust_score()
        assert 0.0 <= score <= 1.0

    def test_trust_score_zero_for_invalid(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm)
        assert p.trust_score() == 0.0

    def test_narrow_scope_higher_trust(self, isolated_db):
        pm = isolated_db
        narrow = _full_lifecycle(pm, permissions=["read:data"],
                                 resource_patterns=["arn:specific:*"])
        wide = _full_lifecycle(pm, agent_id="agent-002",
                               permissions=["read:*", "write:*", "delete:*",
                                            "admin:*", "exec:*"],
                               resource_patterns=["*", "arn:*", "azure:*"])
        assert narrow.trust_score() >= wide.trust_score()


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


class TestEvidence:
    def test_submit_evidence_returns_bundle(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm)
        ev = pm.submit_evidence(
            passport_id=p.passport_id,
            tenant_id="t1",
            submitted_by="alice",
            evidence_type="attestation_record",
            evidence_ref="att-abc123",
            notes="Direct attestation from agent runtime",
        )
        assert ev.evidence_id.startswith("ev-")
        assert ev.passport_id == p.passport_id
        assert ev.status == "pending"

    def test_list_evidence_returns_submitted(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm)
        pm.submit_evidence(
            passport_id=p.passport_id,
            tenant_id="t1",
            submitted_by="alice",
            evidence_type="audit_log",
            evidence_ref="log-001",
        )
        pm.submit_evidence(
            passport_id=p.passport_id,
            tenant_id="t1",
            submitted_by="bob",
            evidence_type="manual",
            evidence_ref="manual review complete",
        )
        evidence = pm.list_evidence(p.passport_id)
        assert len(evidence) == 2

    def test_evidence_types_preserved(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm)
        pm.submit_evidence(
            passport_id=p.passport_id,
            tenant_id="t1",
            submitted_by="ops",
            evidence_type="api_key_proof",
            evidence_ref="key-xyz",
            notes="Validated API key ownership",
        )
        evidence = pm.list_evidence(p.passport_id)
        assert evidence[0].evidence_type == "api_key_proof"
        assert evidence[0].notes == "Validated API key ownership"

    def test_no_evidence_returns_empty(self, isolated_db):
        pm = isolated_db
        p = _make_passport(pm)
        assert pm.list_evidence(p.passport_id) == []


# ---------------------------------------------------------------------------
# List + query
# ---------------------------------------------------------------------------


class TestListPassports:
    def test_list_by_tenant(self, isolated_db):
        pm = isolated_db
        _make_passport(pm, tenant_id="t1", agent_id="a1")
        _make_passport(pm, tenant_id="t1", agent_id="a2")
        _make_passport(pm, tenant_id="t2", agent_id="a3")
        results = pm.list_passports(tenant_id="t1")
        assert len(results) == 2
        assert all(p.tenant_id == "t1" for p in results)

    def test_list_by_agent_id(self, isolated_db):
        pm = isolated_db
        _make_passport(pm, agent_id="alpha")
        _make_passport(pm, agent_id="beta")
        results = pm.list_passports(agent_id="alpha")
        assert len(results) == 1
        assert results[0].subject.agent_id == "alpha"

    def test_list_by_status(self, isolated_db):
        pm = isolated_db
        _make_passport(pm, agent_id="a1")
        _full_lifecycle(pm, agent_id="a2")
        pending = pm.list_passports(status="pending")
        issued = pm.list_passports(status="issued")
        assert len(pending) == 1
        assert len(issued) == 1

    def test_list_respects_limit(self, isolated_db):
        pm = isolated_db
        for i in range(5):
            _make_passport(pm, agent_id=f"agent-{i}")
        results = pm.list_passports(limit=3)
        assert len(results) == 3

    def test_get_nonexistent_returns_none(self, isolated_db):
        pm = isolated_db
        assert pm.get_passport("tdn-pass-does-not-exist") is None


# ---------------------------------------------------------------------------
# Integration playbooks
# ---------------------------------------------------------------------------


class TestIntegrationPlaybooks:
    def test_list_playbooks_returns_all_vendors(self, isolated_db):
        pm = isolated_db
        playbooks = pm.list_integration_playbooks()
        vendors = {p["vendor"] for p in playbooks}
        assert vendors == {"aws_bedrock", "azure_openai", "anthropic", "openai"}

    def test_list_playbooks_have_display_names(self, isolated_db):
        pm = isolated_db
        playbooks = pm.list_integration_playbooks()
        for p in playbooks:
            assert len(p["display_name"]) > 0

    def test_aws_bedrock_playbook_structure(self, isolated_db):
        pm = isolated_db
        pb = pm.get_integration_playbook("aws_bedrock")
        assert pb["vendor"] == "aws_bedrock"
        assert "steps" in pb
        assert len(pb["steps"]) >= 2
        assert "permissions_reference" in pb
        assert "resource_pattern_examples" in pb
        assert "docs_url" in pb

    def test_azure_openai_playbook(self, isolated_db):
        pm = isolated_db
        pb = pm.get_integration_playbook("azure_openai")
        assert pb["vendor"] == "azure_openai"
        assert len(pb["steps"]) >= 1

    def test_anthropic_playbook(self, isolated_db):
        pm = isolated_db
        pb = pm.get_integration_playbook("anthropic")
        assert pb["vendor"] == "anthropic"
        assert any("anthropic:messages" in p for p in pb["permissions_reference"])

    def test_openai_playbook(self, isolated_db):
        pm = isolated_db
        pb = pm.get_integration_playbook("openai")
        assert pb["vendor"] == "openai"
        assert any("chat.completions" in p for p in pb["permissions_reference"])

    def test_unknown_vendor_raises(self, isolated_db):
        pm = isolated_db
        with pytest.raises(ValueError, match="Unknown vendor"):
            pm.get_integration_playbook("grok_ai")

    def test_playbook_steps_have_required_keys(self, isolated_db):
        pm = isolated_db
        for vendor in ["aws_bedrock", "azure_openai", "anthropic", "openai"]:
            pb = pm.get_integration_playbook(vendor)
            for step in pb["steps"]:
                assert "step" in step
                assert "title" in step
                assert "description" in step

    def test_all_playbooks_have_code_samples(self, isolated_db):
        pm = isolated_db
        for vendor in ["aws_bedrock", "azure_openai", "anthropic", "openai"]:
            pb = pm.get_integration_playbook(vendor)
            # At least one step should have a code sample
            assert any("code_sample" in s for s in pb["steps"])


# ---------------------------------------------------------------------------
# Serialization (to_dict roundtrip)
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_to_dict_is_json_serializable(self, isolated_db):
        pm = isolated_db
        p = _full_lifecycle(pm)
        d = p.to_dict()
        json_str = json.dumps(d)
        assert len(json_str) > 0

    def test_to_dict_contains_all_top_level_keys(self, isolated_db):
        pm = isolated_db
        p = _full_lifecycle(pm)
        d = p.to_dict()
        required_keys = {
            "passport_id", "subject", "scope", "issuer",
            "not_before", "not_after", "revocation_url",
            "status", "signature", "created_at",
        }
        assert required_keys.issubset(set(d.keys()))

    def test_subject_keys(self, isolated_db):
        pm = isolated_db
        p = _full_lifecycle(pm)
        sub = p.to_dict()["subject"]
        assert "agent_id" in sub
        assert "owner_org" in sub
        assert "agent_dna_fingerprint" in sub

    def test_scope_keys(self, isolated_db):
        pm = isolated_db
        p = _full_lifecycle(pm)
        scope = p.to_dict()["scope"]
        assert "permissions" in scope
        assert "resource_patterns" in scope
        assert "delegation_depth" in scope
