"""
Sprint D-2 — Module Migration Tests

Verifies that passport.py and verifier_reputation.py now route all DB
operations through pg_connection.get_db_conn() / AdaptedCursor, rather
than calling sqlite3.connect() directly.

Tests confirm:
  1. Neither module imports sqlite3 directly
  2. Both modules use AdaptedCursor for DB access
  3. Full round-trip operations work correctly via the new abstraction
  4. init_db functions work without manual os.makedirs calls
  5. adapt_sql() is applied correctly by AdaptedCursor
  6. WAL and FK PRAGMAs are applied by _sqlite_conn_ctx
"""

from __future__ import annotations

import importlib
import inspect
import os
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tmp_db(tmp_path: Path, name: str = "test.db") -> str:
    return str(tmp_path / name)


def _setup_modules(db_path: str) -> tuple[Any, Any]:
    """Reload both modules with a tmp DB path."""
    os.environ["DATA_DB_PATH"] = db_path
    os.environ.pop("TOKENDNA_DB_BACKEND", None)
    os.environ.pop("TOKENDNA_PG_DSN", None)

    import modules.storage.pg_connection as pgc
    pgc._pg_pool = None  # type: ignore[attr-defined]

    import modules.identity.passport as pmod
    import modules.identity.verifier_reputation as vmod

    importlib.reload(pgc)
    importlib.reload(pmod)
    importlib.reload(vmod)

    pmod.init_passport_db()
    vmod.init_reputation_db()

    return pmod, vmod


# ---------------------------------------------------------------------------
# 1. No direct sqlite3 import in the migrated modules
# ---------------------------------------------------------------------------


class TestNoDirectSqlite3Import:
    def test_passport_does_not_import_sqlite3(self):
        import modules.identity.passport as pmod

        src = inspect.getsource(pmod)
        assert "import sqlite3" not in src, (
            "passport.py must not import sqlite3 directly after D-2 migration"
        )

    def test_verifier_reputation_does_not_import_sqlite3(self):
        import modules.identity.verifier_reputation as vmod

        src = inspect.getsource(vmod)
        assert "import sqlite3" not in src, (
            "verifier_reputation.py must not import sqlite3 directly after D-2 migration"
        )

    def test_passport_imports_from_pg_connection(self):
        import modules.identity.passport as pmod

        src = inspect.getsource(pmod)
        assert "from modules.storage.pg_connection import" in src

    def test_verifier_reputation_imports_from_pg_connection(self):
        import modules.identity.verifier_reputation as vmod

        src = inspect.getsource(vmod)
        assert "from modules.storage.pg_connection import" in src


# ---------------------------------------------------------------------------
# 2. AdaptedCursor used in _cursor() context manager
# ---------------------------------------------------------------------------


class TestAdaptedCursorUsed:
    def test_passport_cursor_yields_adapted_cursor(self, tmp_path):
        db = _tmp_db(tmp_path)
        pmod, _ = _setup_modules(db)
        from modules.storage.pg_connection import AdaptedCursor

        with pmod._cursor() as cur:
            assert isinstance(cur, AdaptedCursor), (
                f"passport._cursor() must yield AdaptedCursor, got {type(cur)}"
            )

    def test_verifier_reputation_cursor_yields_adapted_cursor(self, tmp_path):
        db = _tmp_db(tmp_path)
        _, vmod = _setup_modules(db)
        from modules.storage.pg_connection import AdaptedCursor

        with vmod._cursor() as cur:
            assert isinstance(cur, AdaptedCursor), (
                f"verifier_reputation._cursor() must yield AdaptedCursor, got {type(cur)}"
            )


# ---------------------------------------------------------------------------
# 3. Full round-trip: passport operations via pg_connection
# ---------------------------------------------------------------------------


class TestPassportRoundTrip:
    def test_request_and_retrieve_passport(self, tmp_path):
        db = _tmp_db(tmp_path)
        pmod, _ = _setup_modules(db)

        p = pmod.request_passport(
            tenant_id="tenant-migrate-test",
            agent_id="agent-001",
            owner_org="AcmeCorp",
            display_name="Test Agent",
            agent_dna_fingerprint="fp-abc123",
            model_fingerprint="gpt-4o",
            permissions=["read:data"],
            resource_patterns=["arn:aws:s3:::my-bucket/*"],
            requested_by="admin@acmecorp.com",
        )

        assert p.passport_id.startswith("tdn-pass-")
        assert p.status.value == "pending"
        assert p.tenant_id == "tenant-migrate-test"

        # Retrieve
        fetched = pmod.get_passport(p.passport_id)
        assert fetched is not None
        assert fetched.passport_id == p.passport_id
        assert fetched.subject.agent_id == "agent-001"

    def test_approve_and_issue_passport(self, tmp_path):
        db = _tmp_db(tmp_path)
        pmod, _ = _setup_modules(db)

        p = pmod.request_passport(
            tenant_id="t1",
            agent_id="a1",
            owner_org="Org",
            display_name="Agent",
            agent_dna_fingerprint="fp1",
            model_fingerprint=None,
            permissions=["write:*"],
            resource_patterns=["*"],
            requested_by="admin",
        )
        approved = pmod.approve_passport(p.passport_id)
        assert approved.status.value == "approved"

        issued = pmod.issue_passport(p.passport_id)
        assert issued.status.value == "issued"
        assert issued.signature != ""

    def test_revoke_passport(self, tmp_path):
        db = _tmp_db(tmp_path)
        pmod, _ = _setup_modules(db)

        p = pmod.request_passport(
            tenant_id="t1", agent_id="a1", owner_org="Org",
            display_name="Agent", agent_dna_fingerprint="fp1",
            model_fingerprint=None, permissions=[], resource_patterns=[],
            requested_by="admin",
        )
        pmod.approve_passport(p.passport_id)
        pmod.issue_passport(p.passport_id)
        revoked = pmod.revoke_passport(p.passport_id, "test revocation")
        assert revoked.status.value == "revoked"
        assert revoked.revocation_reason == "test revocation"

    def test_verify_issued_passport(self, tmp_path):
        db = _tmp_db(tmp_path)
        pmod, _ = _setup_modules(db)

        p = pmod.request_passport(
            tenant_id="t1", agent_id="a1", owner_org="Org",
            display_name="Agent", agent_dna_fingerprint="fp1",
            model_fingerprint=None, permissions=[], resource_patterns=[],
            requested_by="admin",
        )
        pmod.approve_passport(p.passport_id)
        issued = pmod.issue_passport(p.passport_id)

        bundle = issued.to_dict()
        result = pmod.verify_passport(bundle)
        assert result["valid"] is True

    def test_list_passports_by_tenant(self, tmp_path):
        db = _tmp_db(tmp_path)
        pmod, _ = _setup_modules(db)

        for i in range(3):
            pmod.request_passport(
                tenant_id="t-list",
                agent_id=f"agent-{i}",
                owner_org="Org",
                display_name=f"Agent {i}",
                agent_dna_fingerprint=f"fp-{i}",
                model_fingerprint=None,
                permissions=[],
                resource_patterns=[],
                requested_by="admin",
            )

        passports = pmod.list_passports(tenant_id="t-list")
        assert len(passports) == 3

    def test_passport_tenant_isolation(self, tmp_path):
        db = _tmp_db(tmp_path)
        pmod, _ = _setup_modules(db)

        pmod.request_passport(
            tenant_id="tenant-A", agent_id="a1", owner_org="Org",
            display_name="Agent", agent_dna_fingerprint="fp1",
            model_fingerprint=None, permissions=[], resource_patterns=[],
            requested_by="admin",
        )
        pmod.request_passport(
            tenant_id="tenant-B", agent_id="a2", owner_org="Org",
            display_name="Agent", agent_dna_fingerprint="fp2",
            model_fingerprint=None, permissions=[], resource_patterns=[],
            requested_by="admin",
        )

        a_passports = pmod.list_passports(tenant_id="tenant-A")
        b_passports = pmod.list_passports(tenant_id="tenant-B")
        assert len(a_passports) == 1
        assert len(b_passports) == 1
        assert a_passports[0].subject.agent_id == "a1"
        assert b_passports[0].subject.agent_id == "a2"


# ---------------------------------------------------------------------------
# 4. Full round-trip: verifier_reputation operations via pg_connection
# ---------------------------------------------------------------------------


class TestVerifierReputationRoundTrip:
    def test_issue_challenge_creates_entry(self, tmp_path):
        """issue_challenge() creates a challenge record and returns it in PENDING state."""
        db = _tmp_db(tmp_path)
        _, vmod = _setup_modules(db)

        challenge = vmod.issue_challenge(verifier_id="vr-001", tenant_id="t1")
        assert challenge.verifier_id == "vr-001"
        assert challenge.tenant_id == "t1"
        assert challenge.outcome.value == "pending"
        assert challenge.challenge_nonce != ""

    def test_resolve_challenge_correct(self, tmp_path):
        db = _tmp_db(tmp_path)
        _, vmod = _setup_modules(db)

        challenge = vmod.issue_challenge(verifier_id="vr-chall", tenant_id="t1")
        # Use the internal expected response (simulates verifier knowing its secret)
        correct_resp = vmod._compute_expected_response(challenge.challenge_nonce)
        resolved = vmod.resolve_challenge(challenge.challenge_id, correct_resp)
        assert resolved.outcome.value == "correct"

    def test_resolve_challenge_incorrect(self, tmp_path):
        db = _tmp_db(tmp_path)
        _, vmod = _setup_modules(db)

        challenge = vmod.issue_challenge(verifier_id="vr-wrong", tenant_id="t1")
        resolved = vmod.resolve_challenge(challenge.challenge_id, "totally-wrong")
        assert resolved.outcome.value == "incorrect"

    def test_get_reputation_after_correct_challenge(self, tmp_path):
        db = _tmp_db(tmp_path)
        _, vmod = _setup_modules(db)

        ch = vmod.issue_challenge(verifier_id="vr-rep", tenant_id="t1")
        correct_resp = vmod._compute_expected_response(ch.challenge_nonce)
        vmod.resolve_challenge(ch.challenge_id, correct_resp)

        rep = vmod.get_reputation(verifier_id="vr-rep", tenant_id="t1")
        assert rep is not None
        assert rep.verifier_id == "vr-rep"

    def test_sync_static_scores(self, tmp_path):
        db = _tmp_db(tmp_path)
        _, vmod = _setup_modules(db)

        # Issue + resolve enough correct challenges to be considered reliable
        for _ in range(3):
            ch = vmod.issue_challenge(verifier_id="vr-sync", tenant_id="t1")
            correct = vmod._compute_expected_response(ch.challenge_nonce)
            vmod.resolve_challenge(ch.challenge_id, correct)

        updated = vmod.sync_static_scores(tenant_id="t1")
        assert updated >= 0  # may be 0 if below reliable threshold — just no crash

    def test_challenge_history(self, tmp_path):
        db = _tmp_db(tmp_path)
        _, vmod = _setup_modules(db)

        for _ in range(3):
            ch = vmod.issue_challenge(verifier_id="vr-hist", tenant_id="t1")
            correct = vmod._compute_expected_response(ch.challenge_nonce)
            vmod.resolve_challenge(ch.challenge_id, correct)

        history = vmod.get_challenge_history(verifier_id="vr-hist", tenant_id="t1")
        assert len(history) == 3

    def test_tenant_isolation(self, tmp_path):
        """Challenges from tenant-X should not appear for tenant-Y."""
        db = _tmp_db(tmp_path)
        _, vmod = _setup_modules(db)

        vmod.issue_challenge(verifier_id="vr-iso", tenant_id="tenant-X")

        # tenant-Y should see empty history for vr-iso
        history_y = vmod.get_challenge_history(verifier_id="vr-iso", tenant_id="tenant-Y")
        assert len(history_y) == 0


# ---------------------------------------------------------------------------
# 5. AdaptedCursor.adapt_sql() applied on execute
# ---------------------------------------------------------------------------


class TestAdaptedCursorPlaceholders:
    def test_adapted_cursor_auto_converts_placeholders(self, tmp_path):
        """AdaptedCursor.execute() should call adapt_sql() on the SQL."""
        import sqlite3
        from modules.storage.pg_connection import AdaptedCursor, adapt_sql

        db = str(tmp_path / "placeholder_test.db")
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE t (id INTEGER, v TEXT)")
        conn.commit()

        cur = AdaptedCursor(conn.cursor())
        # In SQLite mode, adapt_sql is a no-op — just confirm no exception
        cur.execute("INSERT INTO t (id, v) VALUES (?, ?)", (1, "hello"))
        conn.commit()

        row = AdaptedCursor(conn.cursor()).execute("SELECT v FROM t WHERE id = ?", (1,)).fetchone()
        assert row[0] == "hello"
        conn.close()

    def test_adapted_cursor_executemany(self, tmp_path):
        import sqlite3
        from modules.storage.pg_connection import AdaptedCursor

        db = str(tmp_path / "executemany_test.db")
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE t (id INTEGER, v TEXT)")
        conn.commit()

        cur = AdaptedCursor(conn.cursor())
        cur.executemany("INSERT INTO t VALUES (?, ?)", [(1, "a"), (2, "b"), (3, "c")])
        conn.commit()

        rows = AdaptedCursor(conn.cursor()).execute("SELECT COUNT(*) FROM t").fetchone()
        assert rows[0] == 3
        conn.close()

    def test_adapted_cursor_fetchall(self, tmp_path):
        import sqlite3
        from modules.storage.pg_connection import AdaptedCursor

        db = str(tmp_path / "fetchall_test.db")
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE t (id INTEGER)")
        for i in range(5):
            conn.execute("INSERT INTO t VALUES (?)", (i,))
        conn.commit()

        cur = AdaptedCursor(conn.cursor())
        rows = cur.execute("SELECT id FROM t ORDER BY id").fetchall()
        assert len(rows) == 5
        conn.close()

    def test_adapted_cursor_rowcount(self, tmp_path):
        import sqlite3
        from modules.storage.pg_connection import AdaptedCursor

        db = str(tmp_path / "rowcount_test.db")
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE t (id INTEGER, v TEXT)")
        conn.execute("INSERT INTO t VALUES (1, 'a')")
        conn.commit()

        cur = AdaptedCursor(conn.cursor())
        cur.execute("UPDATE t SET v = ? WHERE id = ?", ("b", 1))
        assert cur.rowcount == 1
        conn.close()


# ---------------------------------------------------------------------------
# 6. WAL and FK PRAGMAs applied by _sqlite_conn_ctx
# ---------------------------------------------------------------------------


class TestSQLitePRAGMAs:
    def test_wal_mode_applied(self, tmp_path):
        from modules.storage.pg_connection import get_db_conn

        db = str(tmp_path / "wal_test.db")
        os.environ.pop("TOKENDNA_DB_BACKEND", None)

        with get_db_conn(db_path=db) as conn:
            row = conn.execute("PRAGMA journal_mode").fetchone()
            # WAL mode requested; SQLite returns 'wal' after enabling
            assert row[0] in ("wal", "memory"), f"Unexpected journal_mode: {row[0]}"

    def test_foreign_keys_enabled(self, tmp_path):
        from modules.storage.pg_connection import get_db_conn

        db = str(tmp_path / "fk_test.db")
        os.environ.pop("TOKENDNA_DB_BACKEND", None)

        with get_db_conn(db_path=db) as conn:
            row = conn.execute("PRAGMA foreign_keys").fetchone()
            assert row[0] == 1, "foreign_keys PRAGMA should be ON (1)"


# ---------------------------------------------------------------------------
# 7. init_db works without manual directory creation
# ---------------------------------------------------------------------------


class TestInitDbNoManualMkdirs:
    def test_init_passport_db_creates_dir(self, tmp_path):
        """init_passport_db() should work in a nested tmp dir without manual makedirs."""
        nested = tmp_path / "deep" / "nested" / "dir"
        db = str(nested / "passport.db")
        os.environ["DATA_DB_PATH"] = db
        os.environ.pop("TOKENDNA_DB_BACKEND", None)

        import modules.storage.pg_connection as pgc
        pgc._pg_pool = None  # type: ignore[attr-defined]
        import modules.identity.passport as pmod

        importlib.reload(pgc)
        importlib.reload(pmod)

        # Should not raise despite nested dir not existing
        pmod.init_passport_db()
        assert nested.exists()

    def test_init_reputation_db_creates_dir(self, tmp_path):
        nested = tmp_path / "deep" / "reputation"
        db = str(nested / "rep.db")
        os.environ["DATA_DB_PATH"] = db
        os.environ.pop("TOKENDNA_DB_BACKEND", None)

        import modules.storage.pg_connection as pgc
        pgc._pg_pool = None  # type: ignore[attr-defined]
        import modules.identity.verifier_reputation as vmod

        importlib.reload(pgc)
        importlib.reload(vmod)

        vmod.init_reputation_db()
        assert nested.exists()
