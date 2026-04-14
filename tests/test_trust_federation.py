from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity import trust_federation


def _setup_tmp_db():
    tmpdir = tempfile.TemporaryDirectory()
    db_path = Path(tmpdir.name) / "tokendna-trust-federation-test.db"
    os.environ["DATA_DB_PATH"] = str(db_path)
    os.environ["ATTESTATION_CA_SECRET"] = "federation-secret"
    os.environ.pop("ATTESTATION_ACTIVE_KEY_ID", None)
    os.environ.pop("ATTESTATION_KEYRING_JSON", None)
    return tmpdir


def test_trust_federation_verifier_and_quorum_flow():
    tmp = _setup_tmp_db()
    try:
        trust_federation.init_db()

        v1 = trust_federation.upsert_verifier(
            tenant_id="tenant-1",
            verifier_id=None,
            name="Verifier One",
            trust_score=0.9,
            issuer="https://verifier1.example",
            jwks_uri="https://verifier1.example/.well-known/jwks.json",
            metadata={"region": "us"},
            status="active",
        )
        v2 = trust_federation.upsert_verifier(
            tenant_id="tenant-1",
            verifier_id=None,
            name="Verifier Two",
            trust_score=0.85,
            issuer="https://verifier2.example",
            jwks_uri="https://verifier2.example/.well-known/jwks.json",
            metadata={"region": "eu"},
            status="active",
        )

        listed = trust_federation.list_verifiers(tenant_id="tenant-1", status="active", limit=10)
        assert len(listed) == 2

        a1 = trust_federation.issue_federation_attestation(
            tenant_id="tenant-1",
            verifier_id=v1["verifier_id"],
            target_type="agent",
            target_id="agent-1",
            verdict="allow",
            confidence=0.9,
            metadata={"source": "runtime"},
        )
        a2 = trust_federation.issue_federation_attestation(
            tenant_id="tenant-1",
            verifier_id=v2["verifier_id"],
            target_type="agent",
            target_id="agent-1",
            verdict="block",
            confidence=0.8,
            metadata={"source": "runtime"},
        )
        assert trust_federation.verify_attestation_signature(a1)["valid"] is True
        assert trust_federation.verify_attestation_signature(a2)["valid"] is True

        quorum = trust_federation.evaluate_federation_quorum(
            tenant_id="tenant-1",
            target_type="agent",
            target_id="agent-1",
            min_verifiers=2,
            min_trust_score=0.6,
            min_confidence=0.6,
        )
        assert quorum["quorum"]["met"] is True
        assert quorum["effective_action"] in {"allow", "step_up", "block"}
        assert len(quorum["accepted"]) == 2
    finally:
        os.environ.pop("ATTESTATION_CA_SECRET", None)
        tmp.cleanup()


def test_trust_federation_lifecycle_rotation_and_revocation():
    tmp = _setup_tmp_db()
    try:
        trust_federation.init_db()
        verifier = trust_federation.upsert_verifier(
            tenant_id="tenant-1",
            verifier_id=None,
            name="Lifecycle Verifier",
            trust_score=0.88,
            issuer="https://lifecycle.example",
            jwks_uri="https://lifecycle.example/.well-known/jwks.json",
            metadata={"key_version": "v1"},
            status="active",
        )
        verifier_id = verifier["verifier_id"]

        rotated = trust_federation.rotate_verifier_key(
            tenant_id="tenant-1",
            verifier_id=verifier_id,
            actor="owner-1",
            key_version="v2",
            key_expires_at="2099-01-01T00:00:00+00:00",
        )
        assert rotated is not None
        assert rotated["key_version"] == "v2"

        lifecycle = trust_federation.verifier_lifecycle_status(
            tenant_id="tenant-1",
            verifier_id=verifier_id,
        )
        assert lifecycle is not None
        assert lifecycle["status"] == "active"
        assert lifecycle["is_expired"] is False

        revoked = trust_federation.revoke_verifier(
            tenant_id="tenant-1",
            verifier_id=verifier_id,
            actor="owner-1",
            reason="compromised_key",
        )
        assert revoked is not None
        assert revoked["status"] == "revoked"
        assert revoked["revocation_reason"] == "compromised_key"
    finally:
        os.environ.pop("ATTESTATION_CA_SECRET", None)
        tmp.cleanup()
