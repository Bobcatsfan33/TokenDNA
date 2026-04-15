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


def test_certificate_transparency_append_and_verify_integrity():
    tmp = _setup_tmp_db()
    try:
        from modules.identity import certificate_transparency as ct

        ct.init_db()
        e1 = ct.append_log_entry(
            tenant_id="tenant-1",
            certificate_id="cert-1",
            attestation_id="att-1",
            action="issued",
            payload={"status": "active"},
        )
        e2 = ct.append_log_entry(
            tenant_id="tenant-1",
            certificate_id="cert-1",
            attestation_id="att-1",
            action="revoked",
            payload={"status": "revoked"},
        )
        assert e1["log_index"] < e2["log_index"]
        rows = ct.list_log_entries("tenant-1", limit=10)
        assert len(rows) == 2
        integrity = ct.verify_log_integrity("tenant-1")
        assert integrity["ok"] is True
        assert integrity["entries"] == 2
    finally:
        tmp.cleanup()

