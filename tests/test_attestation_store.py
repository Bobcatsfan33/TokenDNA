from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _setup_tmp_db():
    tmpdir = tempfile.TemporaryDirectory()
    db_path = Path(tmpdir.name) / "tokendna-test.db"
    os.environ["DATA_DB_PATH"] = str(db_path)
    return tmpdir


def test_attestation_store_insert_get_list_and_certificate_roundtrip():
    tmp = _setup_tmp_db()
    try:
        from modules.identity import attestation_store

        attestation_store.init_db()
        record = {
            "attestation_id": "att-1",
            "created_at": "2026-01-01T00:00:00+00:00",
            "who": {"agent_id": "agent-1"},
            "what": {"soul_hash": "abc"},
            "how": {"dpop_bound": True},
            "why": {"declared_purpose": "test"},
            "integrity_digest": "digest",
            "agent_dna_fingerprint": "dna",
        }
        attestation_store.insert_attestation("tenant-1", record)
        fetched = attestation_store.get_attestation("tenant-1", "att-1")
        assert fetched is not None
        assert fetched["attestation_id"] == "att-1"

        rows = attestation_store.list_attestations("tenant-1", limit=10, agent_id="agent-1")
        assert len(rows) == 1
        assert rows[0]["who"]["agent_id"] == "agent-1"

        cert = {
            "certificate_id": "cert-1",
            "tenant_id": "tenant-1",
            "attestation_id": "att-1",
            "issued_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2026-01-02T00:00:00+00:00",
            "issuer": "TokenDNA Trust Authority",
            "subject": "agent-1",
            "signature": "sig",
        }
        attestation_store.insert_certificate("tenant-1", cert)
        fetched_cert = attestation_store.get_certificate("tenant-1", "cert-1")
        assert fetched_cert is not None
        assert fetched_cert["certificate_id"] == "cert-1"
    finally:
        tmp.cleanup()


def test_attestation_store_certificate_lifecycle_and_drift_events():
    tmp = _setup_tmp_db()
    try:
        from modules.identity import attestation_store

        attestation_store.init_db()

        cert_active = {
            "certificate_id": "cert-active",
            "tenant_id": "tenant-1",
            "attestation_id": "att-1",
            "issued_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2026-01-02T00:00:00+00:00",
            "issuer": "TokenDNA Trust Authority",
            "subject": "agent-1",
            "signature_alg": "HS256",
            "ca_key_id": "key-1",
            "status": "active",
            "revoked_at": None,
            "revocation_reason": None,
            "signature": "sig1",
        }
        cert_revoked = {
            "certificate_id": "cert-revoked",
            "tenant_id": "tenant-1",
            "attestation_id": "att-2",
            "issued_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2026-01-02T00:00:00+00:00",
            "issuer": "TokenDNA Trust Authority",
            "subject": "agent-1",
            "signature_alg": "HS256",
            "ca_key_id": "key-1",
            "status": "revoked",
            "revoked_at": "2026-01-01T12:00:00+00:00",
            "revocation_reason": "compromised",
            "signature": "sig2",
        }
        attestation_store.insert_certificate("tenant-1", cert_active)
        attestation_store.insert_certificate("tenant-1", cert_revoked)

        by_status = attestation_store.list_certificates("tenant-1", status="active", limit=10)
        assert len(by_status) == 1
        assert by_status[0]["certificate_id"] == "cert-active"

        by_subject = attestation_store.list_certificates("tenant-1", subject="agent-1", limit=10)
        assert len(by_subject) == 2

        revoked = attestation_store.revoke_certificate(
            tenant_id="tenant-1",
            certificate_id="cert-active",
            revoked_at="2026-01-01T13:00:00+00:00",
            reason="manual_revoke",
        )
        assert revoked is not None
        assert revoked["status"] == "revoked"
        assert revoked["revocation_reason"] == "manual_revoke"

        drift_event = {
            "drift_event_id": "tenant-1:agent-1:req-1",
            "tenant_id": "tenant-1",
            "agent_id": "agent-1",
            "attestation_id": "att-1",
            "certificate_id": "cert-revoked",
            "detected_at": "2026-01-01T14:00:00+00:00",
            "severity": "high",
            "drift_score": 0.7,
            "reasons": ["soul_hash_mismatch"],
            "request_id": "req-1",
        }
        attestation_store.insert_drift_event("tenant-1", drift_event)
        drift_rows = attestation_store.list_drift_events("tenant-1", agent_id="agent-1", limit=10)
        assert len(drift_rows) == 1
        assert drift_rows[0]["severity"] == "high"
    finally:
        tmp.cleanup()


def test_attestation_store_ca_key_registry_roundtrip():
    tmp = _setup_tmp_db()
    try:
        from modules.identity import attestation_store

        attestation_store.init_db()
        attestation_store.upsert_ca_key(
            key_id="ca-2026-01",
            algorithm="RS256",
            backend="aws_kms",
            kms_key_id="arn:aws:kms:us-east-1:123456789012:key/abcd",
            status="active",
            activated_at="2026-01-01T00:00:00+00:00",
            metadata={"rotation_epoch": 1},
        )
        fetched = attestation_store.get_ca_key("ca-2026-01")
        assert fetched is not None
        assert fetched["backend"] == "aws_kms"
        assert fetched["algorithm"] == "RS256"
        assert fetched["metadata"]["rotation_epoch"] == 1

        keys = attestation_store.list_ca_keys(status="active", limit=10)
        assert len(keys) == 1
        assert keys[0]["key_id"] == "ca-2026-01"
    finally:
        tmp.cleanup()

