"""
Migration tests for modules/identity/delegation_receipt.py — same shape
as Sprint D-2's tests/test_pg_module_migration.py.

What this verifies:
  1. The module no longer imports sqlite3 directly — every DB call routes
     through pg_connection.get_db_conn / AdaptedCursor.
  2. The module no longer uses any `if _use_pg(): return` early-stub
     branches — those would silently no-op on Postgres deploys.
  3. `_cursor()` yields an AdaptedCursor.
  4. Full round-trip works on the SQLite path through the unified
     abstraction. The PG path produces the same SQL via adapt_sql;
     verifying it end-to-end against a live Postgres is left to
     integration tests with TOKENDNA_PG_DSN set.
  5. The recursive CTE for cascade revocation is portable (same syntax
     on SQLite 3.8+ and Postgres 8.4+).
"""

from __future__ import annotations

import importlib
import inspect
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture()
def isolated(tmp_path, monkeypatch):
    db = str(tmp_path / "dr.db")
    monkeypatch.setenv("DATA_DB_PATH", db)
    monkeypatch.setenv("TOKENDNA_DELEGATION_SECRET", "test-pg-migration")
    monkeypatch.delenv("TOKENDNA_DB_BACKEND", raising=False)
    monkeypatch.delenv("TOKENDNA_PG_DSN", raising=False)

    import modules.storage.pg_connection as pgc
    pgc._pg_pool = None  # type: ignore[attr-defined]

    import modules.identity.delegation_receipt as dr
    importlib.reload(pgc)
    importlib.reload(dr)
    dr.init_db()
    return dr


# ─────────────────────────────────────────────────────────────────────────────
# Migration shape
# ─────────────────────────────────────────────────────────────────────────────

class TestNoDirectSqlite3Import:
    def test_module_does_not_import_sqlite3(self):
        import modules.identity.delegation_receipt as dr
        src = inspect.getsource(dr)
        assert "import sqlite3" not in src, (
            "delegation_receipt.py must route DB calls through pg_connection."
        )

    def test_module_imports_from_pg_connection(self):
        import modules.identity.delegation_receipt as dr
        src = inspect.getsource(dr)
        assert "from modules.storage.pg_connection import" in src
        assert "AdaptedCursor" in src
        assert "get_db_conn" in src

    def test_no_use_pg_early_returns(self):
        import modules.identity.delegation_receipt as dr
        src = inspect.getsource(dr)
        assert "_use_pg()" not in src, (
            "_use_pg() early-return stubs detected — migration incomplete."
        )

    def test_no_threading_lock(self):
        """The pg_connection layer manages its own pool concurrency; the
        module-level threading.Lock that wrapped sqlite3 calls is no longer
        needed."""
        import modules.identity.delegation_receipt as dr
        src = inspect.getsource(dr)
        assert "threading.Lock()" not in src


class TestCursorYieldsAdapted:
    def test_cursor_returns_adapted_cursor(self, isolated):
        from modules.storage.pg_connection import AdaptedCursor
        with isolated._cursor() as cur:
            assert isinstance(cur, AdaptedCursor)


# ─────────────────────────────────────────────────────────────────────────────
# Round-trip — exercise every public path through the unified abstraction.
# ─────────────────────────────────────────────────────────────────────────────

TENANT = "t-pg-test"
HUMAN = "human:alice"


class TestRoundTrip:
    def test_three_hop_chain_with_replay_and_cascade(self, isolated):
        dr = isolated

        # 1. Issue a 3-hop chain.
        r1 = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:*"], 3600)
        r2 = dr.issue_receipt(TENANT, "agt-A", "agt-B", ["db:read"], 3600,
                              parent_receipt_id=r1.receipt_id)
        r3 = dr.issue_receipt(TENANT, "agt-B", "agt-C", ["db:read"], 3600,
                              parent_receipt_id=r2.receipt_id)

        # 2. Each hop verifies on its own.
        for rcpt in (r1, r2, r3):
            v = dr.verify_receipt(rcpt.receipt_id)
            assert v.valid is True, f"{rcpt.receipt_id} → {v.reason}"

        # 3. Chain walks root → leaf.
        chain = dr.get_chain(r3.receipt_id)
        assert [c.receipt_id for c in chain] == [r1.receipt_id, r2.receipt_id, r3.receipt_id]
        assert [c.depth for c in chain] == [0, 1, 2]

        # 4. Cascade revoke kills every descendant. This exercises the
        # recursive CTE — same SQL on SQLite and Postgres.
        out = dr.revoke_receipt(r1.receipt_id, "admin", cascade=True)
        assert set(out["revoked_ids"]) == {r1.receipt_id, r2.receipt_id, r3.receipt_id}

        for rcpt in (r1, r2, r3):
            v = dr.verify_receipt(rcpt.receipt_id)
            assert v.valid is False
            assert v.reason == "revoked"

    def test_scope_subset_enforcement(self, isolated):
        dr = isolated
        r1 = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:read"], 3600)
        # Child trying to widen scope must fail.
        with pytest.raises(dr.DelegationError, match="scope_exceeds_parent"):
            dr.issue_receipt(TENANT, "agt-A", "agt-B", ["db:write"], 3600,
                             parent_receipt_id=r1.receipt_id)

    def test_get_receipts_for_agent_active_only(self, isolated):
        dr = isolated
        r1 = dr.issue_receipt(TENANT, HUMAN, "agt-X", ["db:read"], 3600)
        r2 = dr.issue_receipt(TENANT, HUMAN, "agt-X", ["queue:write"], 3600)
        dr.revoke_receipt(r2.receipt_id, "admin", cascade=False)
        active = dr.get_receipts_for_agent(TENANT, "agt-X")
        assert {r.receipt_id for r in active} == {r1.receipt_id}

    def test_chain_report_signature_pinning(self, isolated):
        dr = isolated
        r1 = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["db:*"], 3600)
        report = dr.export_chain_report(r1.receipt_id)
        assert report["found"] is True
        assert report["overall_valid"] is True
        assert len(report["hops"]) == 1


class TestSchemaParity:
    """Spot-check: the DDL list is split into individual statements (no
    sqlite3.executescript), so each is portable to PG via adapt_sql."""

    def test_ddl_is_split(self, isolated):
        dr = isolated
        assert len(dr._DDL_STATEMENTS) >= 2

    def test_ddl_uses_no_sqlite_only_idioms(self, isolated):
        dr = isolated
        for stmt in dr._DDL_STATEMENTS:
            lowered = stmt.lower()
            assert "without rowid" not in lowered
            assert "autoincrement" not in lowered

    def test_recursive_cte_syntax_portable(self, isolated):
        """The cascade revoke uses WITH RECURSIVE — confirm it works on
        the SQLite path. Same SQL works on PG via adapt_sql."""
        dr = isolated
        r1 = dr.issue_receipt(TENANT, HUMAN, "agt-A", ["*"], 3600)
        # Build a small tree to exercise the CTE.
        for i in range(3):
            dr.issue_receipt(TENANT, "agt-A", f"agt-B{i}", ["*"], 3600,
                             parent_receipt_id=r1.receipt_id)
        out = dr.revoke_receipt(r1.receipt_id, "admin", cascade=True)
        # Root + 3 children = 4 ids revoked.
        assert len(out["revoked_ids"]) == 4
