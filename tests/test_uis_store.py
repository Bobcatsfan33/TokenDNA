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

