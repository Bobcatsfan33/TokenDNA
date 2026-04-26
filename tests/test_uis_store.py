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



def test_bulk_insert_events_roundtrip():
    """Bulk insert lands rows that look identical to per-event insert."""
    tmp = _setup_tmp_db()
    try:
        from modules.identity import uis_store

        uis_store.init_db()
        events = [
            {
                "event_id": f"bulk-{i}",
                "event_timestamp": f"2026-01-01T00:00:{i:02d}+00:00",
                "identity": {"subject": f"agent-{i}"},
                "auth": {"protocol": "oidc"},
                "threat": {"risk_tier": "allow"},
            }
            for i in range(20)
        ]
        n = uis_store.bulk_insert_events(
            "tenant-bulk", events, skip_downstream=True,
        )
        assert n == 20

        # Each event must round-trip via the normal get_event API.
        for e in events:
            stored = uis_store.get_event("tenant-bulk", e["event_id"])
            assert stored is not None
            assert stored["event_id"] == e["event_id"]


    finally:
        tmp.cleanup()


def test_bulk_insert_events_empty_input_is_noop():
    tmp = _setup_tmp_db()
    try:
        from modules.identity import uis_store
        uis_store.init_db()
        assert uis_store.bulk_insert_events("t", [], skip_downstream=True) == 0
    finally:
        tmp.cleanup()


def test_bulk_insert_events_perf_one_transaction():
    """
    Smoke test that bulk_insert holds a single transaction — proxied by
    confirming a moderately-sized batch completes well under the time it
    would take per-event (2k events).  Per-event insert at ~5ms each would
    be ~10s; bulk should be well under 1s.
    """
    import time
    tmp = _setup_tmp_db()
    try:
        from modules.identity import uis_store
        uis_store.init_db()
        events = [
            {
                "event_id": f"perf-{i}",
                "event_timestamp": "2026-01-01T00:00:00+00:00",
                "identity": {"subject": "x"},
                "auth": {"protocol": "oidc"},
                "threat": {"risk_tier": "allow"},
            }
            for i in range(2000)
        ]
        start = time.perf_counter()
        uis_store.bulk_insert_events(
            "tenant-perf", events, skip_downstream=True,
        )
        elapsed = time.perf_counter() - start
        assert elapsed < 1.5, (
            f"bulk_insert_events took {elapsed:.3f}s for 2000 events — "
            "single-transaction guarantee likely broken"
        )
    finally:
        tmp.cleanup()
