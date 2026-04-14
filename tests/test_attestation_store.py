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

