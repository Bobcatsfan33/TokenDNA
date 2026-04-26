"""
Migration tests for modules/product/threat_sharing.py — same shape as
tests/test_pg_module_migration.py (Sprint D-2 passport + verifier_reputation).

What this verifies:
  1. The module no longer imports sqlite3 directly — every DB call routes
     through pg_connection.get_db_conn / AdaptedCursor.
  2. The module no longer uses any `if _use_pg(): return` early-stub
     branches — those would silently no-op on Postgres deploys.
  3. `_cursor()` yields an AdaptedCursor.
  4. Full round-trip (opt-in → publish → propagate → sync) works through
     the unified backend abstraction on the SQLite path. The PG path
     produces the same SQL via adapt_sql; verifying it end-to-end against
     a live Postgres is left to integration tests with TOKENDNA_PG_DSN set.

This is the same testing pattern Sprint D-2 used for passport — see
tests/test_pg_module_migration.py.
"""

from __future__ import annotations

import importlib
import inspect
import os
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture()
def isolated(tmp_path, monkeypatch):
    """Fresh DB + reloaded modules per test."""
    db = str(tmp_path / "ts.db")
    monkeypatch.setenv("DATA_DB_PATH", db)
    monkeypatch.delenv("TOKENDNA_DB_BACKEND", raising=False)
    monkeypatch.delenv("TOKENDNA_PG_DSN", raising=False)

    import modules.storage.pg_connection as pgc
    pgc._pg_pool = None  # type: ignore[attr-defined]

    import modules.identity.intent_correlation as ic
    import modules.product.threat_sharing as ts
    importlib.reload(pgc)
    importlib.reload(ic)
    importlib.reload(ts)
    ts.init_db()
    return ts


# ─────────────────────────────────────────────────────────────────────────────
# Migration shape — the contract every PG-migrated module must meet.
# ─────────────────────────────────────────────────────────────────────────────

class TestNoDirectSqlite3Import:
    def test_module_does_not_import_sqlite3(self):
        import modules.product.threat_sharing as ts
        src = inspect.getsource(ts)
        # We allow the type-annotation reference but no `import sqlite3`.
        assert "import sqlite3" not in src, (
            "threat_sharing.py must route DB calls through pg_connection, "
            "not import sqlite3 directly."
        )

    def test_module_imports_from_pg_connection(self):
        import modules.product.threat_sharing as ts
        src = inspect.getsource(ts)
        assert "from modules.storage.pg_connection import" in src
        assert "AdaptedCursor" in src
        assert "get_db_conn" in src

    def test_no_use_pg_early_returns(self):
        """The pre-migration code had ``if _use_pg(): return ...`` stubs in
        every public function. The migration must remove those — otherwise
        Postgres deploys silently no-op."""
        import modules.product.threat_sharing as ts
        src = inspect.getsource(ts)
        assert "_use_pg()" not in src, (
            "_use_pg() early-return stubs detected — migration incomplete."
        )


class TestCursorYieldsAdapted:
    def test_cursor_returns_adapted_cursor(self, isolated):
        from modules.storage.pg_connection import AdaptedCursor
        with isolated._cursor() as cur:
            assert isinstance(cur, AdaptedCursor)


# ─────────────────────────────────────────────────────────────────────────────
# Round-trip — exercises every public path through the unified abstraction.
# ─────────────────────────────────────────────────────────────────────────────

class TestRoundTrip:
    def _seed_playbook(self, ic, tenant: str) -> str:
        return ic.add_playbook(
            tenant_id=tenant, name="Acme",
            description="Test pattern from agent-1",
            severity="high",
            steps=[{"category": "auth_anomaly", "min_confidence": 0.5,
                    "agent_id": "agent-x"}],
            window_seconds=600,
        )

    def test_full_publish_propagate_sync(self, isolated):
        import modules.identity.intent_correlation as ic
        ts = isolated

        ts.opt_in("tenant-a")
        ts.opt_in("tenant-b")
        pid = self._seed_playbook(ic, "tenant-a")

        receipt = ts.publish_playbook("tenant-a", pid)
        assert receipt["network_playbook_id"].startswith("net:")
        assert receipt["deduplicated"] is False

        # Catalog browse.
        catalog = ts.list_network_playbooks()
        assert len(catalog) == 1
        assert "agent-x" not in repr(catalog), "anonymization leaked agent_id"

        # Propagate.
        out = ts.propagate_to_tenant("tenant-b", receipt["network_playbook_id"])
        assert out is not None
        assert out["deduplicated"] is False
        # Sync — already propagated, returns 0.
        n = ts.sync_network_playbooks("tenant-b")
        assert n == 0

        status = ts.get_status("tenant-a")
        assert status["published_count"] == 1
        status = ts.get_status("tenant-b")
        assert status["received_count"] == 1

    def test_publish_idempotency(self, isolated):
        import modules.identity.intent_correlation as ic
        ts = isolated

        ts.opt_in("tenant-a")
        pid = self._seed_playbook(ic, "tenant-a")
        first = ts.publish_playbook("tenant-a", pid)
        again = ts.publish_playbook("tenant-a", pid)
        assert again["network_playbook_id"] == first["network_playbook_id"]
        assert again["deduplicated"] is True
        # Counter must NOT double-increment on dedup'd publish.
        assert ts.get_status("tenant-a")["published_count"] == 1

    def test_anonymize_pure_function(self, isolated):
        ts = isolated
        pb = {"name": "test from 10.0.0.5",
              "description": "agent-bob hits user@example.com",
              "severity": "high",
              "steps": [{"category": "auth_anomaly", "agent_id": "secret-1"}]}
        out = ts.anonymize_playbook(pb)
        flat = repr(out)
        for leak in ("10.0.0.5", "user@example.com", "secret-1"):
            assert leak not in flat
        # Original input unmodified.
        assert pb["steps"][0]["agent_id"] == "secret-1"


class TestSchemaParity:
    """Spot-check: the DDL list is split into individual statements (no
    sqlite3.executescript), so each is portable to PG via adapt_sql."""

    def test_ddl_is_split(self, isolated):
        ts = isolated
        # The DDL list should have >1 statement (it has 5).
        assert len(ts._DDL_STATEMENTS) >= 5
        # No statement should contain `executescript` syntax (semicolon-separated).
        for stmt in ts._DDL_STATEMENTS:
            assert stmt.count(";") <= 1, (
                f"statement contains multiple ';' — should be split: {stmt[:80]}"
            )

    def test_ddl_uses_no_sqlite_only_idioms(self, isolated):
        ts = isolated
        for stmt in ts._DDL_STATEMENTS:
            lowered = stmt.lower()
            # PG doesn't support SQLite's WITHOUT ROWID, AUTOINCREMENT, etc.
            assert "without rowid" not in lowered
            assert "autoincrement" not in lowered
