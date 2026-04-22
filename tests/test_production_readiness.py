"""
Sprint D-1 — Production Readiness Tests

Covers:
  1. pg_connection.py — BackendConfig, adapt_sql, get_db_conn SQLite path,
     ConfigurationError when Postgres DSN is missing, dual-write helpers
  2. config.py — RATE_LIMIT_OPEN_PER_MINUTE default + override
  3. api.py  — check_rate_limit_open enforces 429 after threshold,
               open endpoints have rate limiting wired
  4. Existing db_backend contract preserved (no regression)
"""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# -- path setup ---------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# =============================================================================
# Helpers
# =============================================================================

def _clean_backend_env() -> None:
    for k in (
        "TOKENDNA_DB_BACKEND",
        "TOKENDNA_DB_DUAL_WRITE",
        "TOKENDNA_PG_DSN",
        "DATA_DB_PATH",
    ):
        os.environ.pop(k, None)


def _reload_backend() -> ModuleType:
    """Force-reload db_backend so env changes take effect."""
    import modules.storage.db_backend as m

    return importlib.reload(m)


def _reload_pg_connection() -> ModuleType:
    """Force-reload pg_connection (also clears pool singleton)."""
    import modules.storage.pg_connection as m

    # reset pool singleton
    m._pg_pool = None  # type: ignore[attr-defined]
    return importlib.reload(m)


# =============================================================================
# 1. pg_connection — SQLite path
# =============================================================================


class TestPgConnectionSQLitePath:
    def setup_method(self):
        _clean_backend_env()
        _reload_backend()
        _reload_pg_connection()

    def test_default_backend_is_sqlite(self):
        from modules.storage import pg_connection as pgc

        assert not pgc.should_use_postgres()

    def test_get_db_conn_opens_sqlite(self, tmp_path):
        from modules.storage.pg_connection import get_db_conn

        db = str(tmp_path / "test.db")
        with get_db_conn(db_path=db) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, v TEXT)")
            conn.execute("INSERT INTO t (v) VALUES (?)", ("hello",))

        # Data persists after context exit (committed)
        with get_db_conn(db_path=db) as conn:
            row = conn.execute("SELECT v FROM t").fetchone()
            assert row[0] == "hello"

    def test_rollback_on_exception(self, tmp_path):
        from modules.storage.pg_connection import get_db_conn

        db = str(tmp_path / "rollback.db")
        with get_db_conn(db_path=db) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, v TEXT)")

        with pytest.raises(RuntimeError):
            with get_db_conn(db_path=db) as conn:
                conn.execute("INSERT INTO t (v) VALUES (?)", ("should_rollback",))
                raise RuntimeError("simulated error")

        # Row should NOT be persisted
        with get_db_conn(db_path=db) as conn:
            rows = conn.execute("SELECT * FROM t").fetchall()
            assert len(rows) == 0

    def test_adapt_sql_is_noop_in_sqlite_mode(self):
        from modules.storage.pg_connection import adapt_sql

        sql = "SELECT * FROM t WHERE id = ? AND v = ?"
        assert adapt_sql(sql) == sql

    def test_adapt_sql_converts_placeholders_in_postgres_mode(self):
        os.environ["TOKENDNA_DB_BACKEND"] = "postgres"
        os.environ["TOKENDNA_PG_DSN"] = "postgresql://localhost/test"
        _reload_backend()
        pg_mod = _reload_pg_connection()

        sql = "INSERT INTO t (a, b) VALUES (?, ?)"
        result = pg_mod.adapt_sql(sql)
        assert result == "INSERT INTO t (a, b) VALUES (%s, %s)"

        # cleanup
        _clean_backend_env()
        _reload_backend()
        pg_mod._pg_pool = None  # type: ignore[attr-defined]
        importlib.reload(pg_mod)

    def test_adapt_sql_caches_result(self):
        from modules.storage import pg_connection as pgc

        # In SQLite mode — cache still populated with original SQL
        sql = "SELECT 1 WHERE x = ?"
        r1 = pgc.adapt_sql(sql)
        r2 = pgc.adapt_sql(sql)
        assert r1 == r2 == sql


# =============================================================================
# 2. pg_connection — Postgres path (no actual PG required)
# =============================================================================


class TestPgConnectionPostgresConfig:
    def setup_method(self):
        _clean_backend_env()
        _reload_backend()
        _reload_pg_connection()

    def teardown_method(self):
        _clean_backend_env()
        _reload_backend()
        _reload_pg_connection()

    def test_raises_configuration_error_when_dsn_missing(self):
        os.environ["TOKENDNA_DB_BACKEND"] = "postgres"
        # No TOKENDNA_PG_DSN set
        _reload_backend()
        pg_mod = _reload_pg_connection()

        with pytest.raises(pg_mod.ConfigurationError, match="TOKENDNA_PG_DSN"):
            pg_mod._get_pg_pool()

    def test_raises_backend_unavailable_when_pool_fails(self):
        os.environ["TOKENDNA_DB_BACKEND"] = "postgres"
        os.environ["TOKENDNA_PG_DSN"] = "postgresql://localhost:9999/nonexistent"
        _reload_backend()
        pg_mod = _reload_pg_connection()

        # Mock both psycopg and psycopg_pool so the import succeeds but pool init fails
        fake_pool_cls = MagicMock(side_effect=Exception("connection refused"))
        fake_psycopg = MagicMock()
        fake_psycopg.rows = MagicMock(dict_row=MagicMock())
        with patch.dict(
            "sys.modules",
            {
                "psycopg": fake_psycopg,
                "psycopg_pool": MagicMock(ConnectionPool=fake_pool_cls),
            },
        ):
            with pytest.raises(pg_mod.BackendUnavailableError, match="connection refused"):
                pg_mod._get_pg_pool()

    def test_get_db_conn_raises_in_postgres_mode_without_dsn(self):
        os.environ["TOKENDNA_DB_BACKEND"] = "postgres"
        _reload_backend()
        pg_mod = _reload_pg_connection()

        with pytest.raises(pg_mod.ConfigurationError):
            with pg_mod.get_db_conn() as _:
                pass


# =============================================================================
# 3. pg_connection — dual-write helpers
# =============================================================================


class TestDualWrite:
    def setup_method(self):
        _clean_backend_env()
        _reload_backend()
        _reload_pg_connection()

    def teardown_method(self):
        _clean_backend_env()
        _reload_backend()
        _reload_pg_connection()

    def test_dual_write_off_yields_sqlite_and_none(self, tmp_path):
        from modules.storage.pg_connection import get_dual_write_conns

        db = str(tmp_path / "dual.db")
        with get_dual_write_conns(db_path=db) as (primary, secondary):
            assert secondary is None
            primary.execute(
                "CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, v TEXT)"
            )
            primary.execute("INSERT INTO t (v) VALUES (?)", ("primary",))

        with get_dual_write_conns(db_path=db) as (conn, _):
            row = conn.execute("SELECT v FROM t").fetchone()
            assert row[0] == "primary"

    def test_dual_write_on_falls_back_gracefully_when_pg_unavailable(self, tmp_path):
        """Even with dual-write enabled, if PG pool fails we continue on SQLite."""
        os.environ["TOKENDNA_DB_DUAL_WRITE"] = "true"
        os.environ["TOKENDNA_PG_DSN"] = "postgresql://localhost:9999/nonexistent"
        _reload_backend()
        pg_mod = _reload_pg_connection()

        db = str(tmp_path / "fallback.db")

        # Pool init will fail → should fall back to SQLite-only
        fake_pool_cls = MagicMock(side_effect=Exception("conn refused"))
        with patch.dict(
            "sys.modules",
            {"psycopg_pool": MagicMock(ConnectionPool=fake_pool_cls)},
        ):
            with pg_mod.get_dual_write_conns(db_path=db) as (primary, secondary):
                assert secondary is None
                primary.execute(
                    "CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, v TEXT)"
                )
                primary.execute("INSERT INTO t (v) VALUES (?)", ("fallback",))

        with pg_mod.get_dual_write_conns(db_path=db) as (conn, _):
            row = conn.execute("SELECT v FROM t").fetchone()
            assert row[0] == "fallback"


# =============================================================================
# 4. config.py — RATE_LIMIT_OPEN_PER_MINUTE
# =============================================================================


class TestRateLimitOpenConfig:
    def test_default_open_rate_limit(self):
        os.environ.pop("RATE_LIMIT_OPEN_PER_MINUTE", None)
        import config as cfg

        importlib.reload(cfg)
        assert cfg.RATE_LIMIT_OPEN_PER_MINUTE == 30

    def test_custom_open_rate_limit(self):
        os.environ["RATE_LIMIT_OPEN_PER_MINUTE"] = "10"
        import config as cfg

        importlib.reload(cfg)
        assert cfg.RATE_LIMIT_OPEN_PER_MINUTE == 10
        os.environ.pop("RATE_LIMIT_OPEN_PER_MINUTE", None)
        importlib.reload(cfg)


# =============================================================================
# 5. check_rate_limit_open — unit tests (mock Redis)
# =============================================================================


class TestCheckRateLimitOpen:
    """Unit tests for the check_rate_limit_open FastAPI dependency."""

    def _make_request(self, ip: str = "1.2.3.4") -> MagicMock:
        req = MagicMock()
        req.client = MagicMock()
        req.client.host = ip
        return req

    def test_under_limit_does_not_raise(self):
        import asyncio
        import api as api_mod

        # increment_rate returns 1 (well under limit)
        with patch.object(api_mod, "increment_rate", return_value=1):
            req = self._make_request()
            # Should not raise
            asyncio.run(api_mod.check_rate_limit_open(req))

    def test_over_limit_raises_429(self):
        from fastapi import HTTPException
        import asyncio
        import api as api_mod

        # increment_rate returns 9999 (way over limit)
        with patch.object(api_mod, "increment_rate", return_value=9999):
            req = self._make_request()
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(api_mod.check_rate_limit_open(req))
            assert exc_info.value.status_code == 429
            assert "Retry-After" in exc_info.value.headers

    def test_exactly_at_limit_is_allowed(self):
        """count == limit should be allowed; count > limit is the trigger."""
        import asyncio
        import api as api_mod

        with patch.object(api_mod, "increment_rate", return_value=30):
            req = self._make_request()
            # Should not raise — 30 == limit, not 30 > limit
            asyncio.run(api_mod.check_rate_limit_open(req))

    def test_one_over_limit_raises(self):
        from fastapi import HTTPException
        import asyncio
        import api as api_mod

        with patch.object(api_mod, "increment_rate", return_value=31):
            req = self._make_request()
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(api_mod.check_rate_limit_open(req))
            assert exc_info.value.status_code == 429

    def test_uses_open_namespace(self):
        """Open rate limiter uses '_open_' tenant namespace, not a real tenant."""
        import asyncio
        import api as api_mod

        captured: dict = {}

        def mock_increment(key, window_seconds, tenant_id):
            captured["tenant_id"] = tenant_id
            return 1

        with patch.object(api_mod, "increment_rate", side_effect=mock_increment):
            req = self._make_request()
            asyncio.run(api_mod.check_rate_limit_open(req))

        assert captured["tenant_id"] == "_open_"

    def test_unknown_ip_when_no_client(self):
        """If request.client is None, uses 'unknown' as key."""
        import asyncio
        import api as api_mod

        captured: dict = {}

        def mock_increment(key, window_seconds, tenant_id):
            captured["key"] = key
            return 1

        with patch.object(api_mod, "increment_rate", side_effect=mock_increment):
            req = MagicMock()
            req.client = None
            asyncio.run(api_mod.check_rate_limit_open(req))

        assert "open_rate:unknown" in captured.get("key", "")


# =============================================================================
# 6. Open endpoint rate-limiting wired in api.py
# =============================================================================


class TestOpenEndpointsHaveRateLimiting:
    """
    Verify that the open endpoints have check_rate_limit_open in their
    dependency tree without starting the full app.
    """

    def _get_route_dep_names(self, path: str, method: str = "POST") -> list[str]:
        """
        Return a list of dependency callable names wired to a route via
        ``dependencies=[Depends(...)]`` at the decorator level.
        """
        import api as api_mod

        for route in api_mod.app.routes:
            if hasattr(route, "path") and route.path == path:
                if method.upper() in getattr(route, "methods", set()):
                    names = []
                    for dep in getattr(route, "dependencies", []):
                        # dep is a fastapi.params.Depends instance
                        callable_ = getattr(dep, "dependency", None)
                        if callable_ is not None:
                            names.append(getattr(callable_, "__name__", repr(callable_)))
                    return names
        return []

    def test_passport_verify_has_rate_limit(self):
        deps = self._get_route_dep_names("/api/passport/verify", "POST")
        assert "check_rate_limit_open" in deps, (
            f"POST /api/passport/verify is missing check_rate_limit_open. deps={deps}"
        )

    def test_verifier_challenge_respond_has_rate_limit(self):
        deps = self._get_route_dep_names(
            "/api/verifier/challenge/{challenge_id}/respond", "POST"
        )
        assert "check_rate_limit_open" in deps, (
            "POST /api/verifier/challenge/{challenge_id}/respond is missing "
            f"check_rate_limit_open. deps={deps}"
        )

    def test_passport_status_has_rate_limit(self):
        deps = self._get_route_dep_names("/api/passport/{passport_id}/status", "GET")
        assert "check_rate_limit_open" in deps, (
            f"GET /api/passport/{{passport_id}}/status is missing check_rate_limit_open. deps={deps}"
        )


# =============================================================================
# 7. db_backend contract preserved (regression guard)
# =============================================================================


class TestDbBackendRegression:
    """Ensure the existing db_backend API is unchanged."""

    def setup_method(self):
        _clean_backend_env()

    def test_defaults_to_sqlite(self):
        from modules.storage.db_backend import get_backend_config

        cfg = get_backend_config()
        assert cfg.backend == "sqlite"
        assert cfg.dual_write is False
        assert cfg.postgres_dsn is None

    def test_postgres_flag_detection(self):
        os.environ["TOKENDNA_DB_BACKEND"] = "postgres"
        os.environ["TOKENDNA_PG_DSN"] = "postgresql://localhost/test"
        from modules.storage import db_backend

        importlib.reload(db_backend)
        assert db_backend.should_use_postgres() is True
        _clean_backend_env()
        importlib.reload(db_backend)

    def test_dual_write_flag_detection(self):
        os.environ["TOKENDNA_DB_BACKEND"] = "postgres"
        os.environ["TOKENDNA_DB_DUAL_WRITE"] = "true"
        os.environ["TOKENDNA_PG_DSN"] = "postgresql://localhost/test"
        from modules.storage import db_backend

        importlib.reload(db_backend)
        assert db_backend.should_dual_write() is True
        _clean_backend_env()
        importlib.reload(db_backend)

    def test_invalid_backend_defaults_to_sqlite(self):
        os.environ["TOKENDNA_DB_BACKEND"] = "mysql"  # not supported
        from modules.storage import db_backend

        importlib.reload(db_backend)
        cfg = db_backend.get_backend_config()
        assert cfg.backend == "sqlite"
        _clean_backend_env()
        importlib.reload(db_backend)


# =============================================================================
# 8. RATE_LIMIT_OPEN_PER_MINUTE exported from api.py
# =============================================================================


class TestApiImportsOpenRateLimit:
    def test_api_imports_open_rate_limit_constant(self):
        import api as api_mod

        assert hasattr(api_mod, "RATE_LIMIT_OPEN_PER_MINUTE") or hasattr(
            api_mod, "check_rate_limit_open"
        ), "api.py must import or define RATE_LIMIT_OPEN_PER_MINUTE or check_rate_limit_open"

    def test_check_rate_limit_open_is_async(self):
        import asyncio
        import api as api_mod

        assert asyncio.iscoroutinefunction(api_mod.check_rate_limit_open)
