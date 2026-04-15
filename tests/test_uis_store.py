from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _setup_tmp_db():
    tmpdir = tempfile.TemporaryDirectory()
    db_path = Path(tmpdir.name) / "tokendna-test.db"
    os.environ["DATA_DB_PATH"] = str(db_path)
    return tmpdir


def test_uis_store_insert_get_list_roundtrip():
    tmp = _setup_tmp_db()
    try:
        from modules.identity import uis_store

        uis_store.init_db()
        event = {
            "event_id": "evt-1",
            "event_timestamp": "2026-01-01T00:00:00+00:00",
            "identity": {"subject": "user-1"},
            "auth": {"protocol": "oidc"},
            "threat": {"risk_tier": "allow"},
        }
        uis_store.insert_event("tenant-1", event)

        fetched = uis_store.get_event("tenant-1", "evt-1")
        assert fetched is not None
        assert fetched["event_id"] == "evt-1"

        rows = uis_store.list_events("tenant-1", limit=10, subject="user-1")
        assert len(rows) == 1
        assert rows[0]["identity"]["subject"] == "user-1"
    finally:
        tmp.cleanup()


def test_uis_store_dual_write_fallback_records_audit_without_failing():
    tmp = _setup_tmp_db()
    try:
        from modules.identity import uis_store

        os.environ["TOKENDNA_DB_BACKEND"] = "sqlite"
        os.environ["TOKENDNA_DB_DUAL_WRITE"] = "true"
        os.environ["TOKENDNA_PG_DSN"] = "postgresql://invalid-host:5432/tokendna"

        uis_store.init_db()
        event = {
            "event_id": "evt-dual-1",
            "event_timestamp": "2026-01-01T00:00:01+00:00",
            "identity": {"subject": "user-2"},
            "auth": {"protocol": "oidc"},
            "threat": {"risk_tier": "allow"},
        }
        with mock.patch(
            "modules.identity.uis_store._pg_insert_event",
            side_effect=RuntimeError("pg unavailable"),
        ):
            uis_store.insert_event("tenant-1", event)

        fetched = uis_store.get_event("tenant-1", "evt-dual-1")
        assert fetched is not None
        assert fetched["event_id"] == "evt-dual-1"
    finally:
        for key in ("TOKENDNA_DB_BACKEND", "TOKENDNA_DB_DUAL_WRITE", "TOKENDNA_PG_DSN"):
            os.environ.pop(key, None)
        tmp.cleanup()

