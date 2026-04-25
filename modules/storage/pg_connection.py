"""
TokenDNA — Unified Database Connection Factory (Sprint D-1)

Provides a single ``get_db_conn()`` context manager that returns either:

  * A ``sqlite3.Connection``   — when TOKENDNA_DB_BACKEND=sqlite  (default/dev)
  * A ``psycopg.Connection``   — when TOKENDNA_DB_BACKEND=postgres + TOKENDNA_PG_DSN is set

Both connections expose the same cursor interface that TokenDNA modules use:
    conn.execute(sql, params)   → cursor
    conn.executemany(sql, rows) → cursor
    conn.commit()
    conn.close()

Callers never import sqlite3 or psycopg directly — they call:

    from modules.storage.pg_connection import get_db_conn, adapt_sql

    with get_db_conn(db_path="/data/tokendna.db") as conn:
        conn.execute(adapt_sql("INSERT INTO t VALUES (?, ?)"), (a, b))

``adapt_sql()`` converts SQLite-style ``?`` placeholders to psycopg ``%s``
when running against Postgres.  In SQLite mode it is a no-op.

``db_path`` is only used in SQLite mode; it is ignored in Postgres mode.

Connection lifecycle
────────────────────
- SQLite:  a new ``sqlite3.Connection`` is opened and closed per call (same
  behaviour as existing modules).
- Postgres: connections are drawn from a global ``psycopg.pool.ConnectionPool``
  initialised once on first use.  The pool is sized from env vars:
    TOKENDNA_PG_POOL_MIN  (default 2)
    TOKENDNA_PG_POOL_MAX  (default 10)

Fallback
────────
If ``TOKENDNA_DB_BACKEND=postgres`` but ``TOKENDNA_PG_DSN`` is not set, or if
the Postgres pool fails to initialise, a ``ConfigurationError`` is raised so
the operator sees the misconfiguration clearly instead of silently using SQLite.

Migration helper
────────────────
``should_dual_write()`` is re-exported from ``db_backend`` for convenience.
"""

from __future__ import annotations

import contextlib
import logging
import os
import sqlite3
import threading
from typing import Any, Generator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Re-exports from db_backend for convenience
# ---------------------------------------------------------------------------
from modules.storage.db_backend import (  # noqa: E402
    get_backend_config,
    should_use_postgres,
    should_dual_write,  # noqa: F401
    record_backend_fallback,
)

# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class ConfigurationError(RuntimeError):
    """Raised when the database backend is mis-configured."""


class BackendUnavailableError(RuntimeError):
    """Raised when the configured backend cannot be reached."""


# ---------------------------------------------------------------------------
# Postgres connection pool (lazy init, singleton)
# ---------------------------------------------------------------------------

_pg_pool: Any = None  # psycopg.pool.ConnectionPool | None
_pg_pool_lock = threading.Lock()


def _normalize_dsn_for_psycopg(dsn: str) -> str:
    """
    Strip a SQLAlchemy-style ``+driver`` suffix from a Postgres URL so it
    parses as a libpq URI.  ``postgresql+psycopg://...`` → ``postgresql://...``.

    SQLAlchemy / Alembic uses the ``dialect+driver`` scheme to pin the v3
    psycopg driver (otherwise SQLAlchemy tries to import psycopg2).  libpq
    does not understand the suffix and falls back to parsing the whole
    string as ``key=value`` conninfo, which fails with
    ``missing "=" after "..."``.  We accept the same env var everywhere
    and normalise it here for psycopg's benefit.
    """
    scheme, sep, rest = dsn.partition("://")
    if not sep:
        return dsn
    base, plus, _driver = scheme.partition("+")
    if not plus or base not in {"postgresql", "postgres"}:
        return dsn
    return f"{base}://{rest}"


def _get_pg_pool() -> Any:
    """Return (or initialise) the global psycopg connection pool."""
    global _pg_pool
    if _pg_pool is not None:
        return _pg_pool

    with _pg_pool_lock:
        if _pg_pool is not None:
            return _pg_pool

        cfg = get_backend_config()
        if not cfg.postgres_dsn:
            raise ConfigurationError(
                "TOKENDNA_DB_BACKEND=postgres but TOKENDNA_PG_DSN is not set. "
                "Set TOKENDNA_PG_DSN to a valid libpq connection string."
            )

        min_size = int(os.getenv("TOKENDNA_PG_POOL_MIN", "2"))
        max_size = int(os.getenv("TOKENDNA_PG_POOL_MAX", "10"))

        try:
            import psycopg
            from psycopg_pool import ConnectionPool  # type: ignore[import]

            pool = ConnectionPool(
                _normalize_dsn_for_psycopg(cfg.postgres_dsn),
                min_size=min_size,
                max_size=max_size,
                kwargs={"autocommit": False, "row_factory": psycopg.rows.dict_row},
                open=True,
            )
            _pg_pool = pool
            logger.info(
                "Postgres pool initialised (min=%d max=%d dsn=***)",
                min_size,
                max_size,
            )
            return _pg_pool
        except ImportError as exc:
            raise BackendUnavailableError(
                "psycopg / psycopg_pool not installed. "
                "Add psycopg[binary] and psycopg-pool to requirements.txt."
            ) from exc
        except Exception as exc:
            raise BackendUnavailableError(
                f"Failed to initialise Postgres connection pool: {exc}"
            ) from exc


def close_pg_pool() -> None:
    """Gracefully close the global Postgres pool (call at application shutdown)."""
    global _pg_pool
    with _pg_pool_lock:
        if _pg_pool is not None:
            try:
                _pg_pool.close()
            except Exception:
                pass
            _pg_pool = None


# ---------------------------------------------------------------------------
# SQL dialect helpers
# ---------------------------------------------------------------------------

_PLACEHOLDER_CACHE: dict[str, str] = {}


def adapt_sql(sql: str) -> str:
    """
    Convert SQLite ``?`` positional placeholders to psycopg ``%s`` when
    Postgres is active.  In SQLite mode this is a no-op.

    The result is cached per unique SQL string to avoid repeated scanning.
    """
    if not should_use_postgres():
        return sql
    cached = _PLACEHOLDER_CACHE.get(sql)
    if cached is not None:
        return cached
    result = sql.replace("?", "%s")
    _PLACEHOLDER_CACHE[sql] = result
    return result


def adapt_params(params: Any) -> Any:
    """
    Normalise query parameters.

    psycopg expects a sequence or mapping; sqlite3 accepts tuples, lists, or
    dicts.  This function returns params unchanged in almost all cases — it
    exists as a hook for future dialect normalisation (e.g. booleans, UUIDs).
    """
    return params


# ---------------------------------------------------------------------------
# Adapted cursor — auto-applies adapt_sql() on every execute() call
# ---------------------------------------------------------------------------


class AdaptedCursor:
    """
    Thin wrapper around a DB-API 2.0 cursor that automatically runs
    ``adapt_sql()`` on every SQL string passed to ``execute()`` or
    ``executemany()``.  This lets callers write SQLite-style ``?``
    placeholders without caring which backend is active.

    Usage::

        with _cursor() as cur:           # cur is an AdaptedCursor
            cur.execute("SELECT * FROM t WHERE id = ?", (tid,))
            rows = cur.fetchall()
    """

    def __init__(self, cursor: Any) -> None:
        self._cur = cursor

    def execute(self, sql: str, params: Any = ()) -> "AdaptedCursor":
        self._cur.execute(adapt_sql(sql), params)
        return self

    def executemany(self, sql: str, seq: Any) -> "AdaptedCursor":
        self._cur.executemany(adapt_sql(sql), seq)
        return self

    def fetchone(self) -> Any:
        return self._cur.fetchone()

    def fetchall(self) -> list[Any]:
        return self._cur.fetchall()

    @property
    def lastrowid(self) -> Any:
        return self._cur.lastrowid

    @property
    def rowcount(self) -> int:
        return self._cur.rowcount

    def __iter__(self) -> Any:
        return iter(self._cur)


# ---------------------------------------------------------------------------
# SQLite row factory shim  (matches sqlite3.Row dict-style access)
# ---------------------------------------------------------------------------


class _SQLiteRowDict(sqlite3.Row):
    """sqlite3.Row sub-class that also supports ``row["col"]`` access (already built-in)."""


# ---------------------------------------------------------------------------
# Main connection context manager
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def get_db_conn(
    db_path: str | None = None,
    *,
    autocommit: bool = False,
) -> Generator[Any, None, None]:
    """
    Context manager that yields a database connection.

    Parameters
    ----------
    db_path:
        Path to the SQLite file.  Required in SQLite mode; ignored in Postgres
        mode.  Defaults to the ``DATA_DB_PATH`` environment variable or
        ``/data/tokendna.db``.
    autocommit:
        In SQLite mode, sets ``isolation_level=None`` (autocommit).
        In Postgres mode, sets ``autocommit=True`` on the connection.

    Yields
    ------
    sqlite3.Connection | psycopg.Connection
        Both support ``.execute()``, ``.executemany()``, ``.commit()``,
        ``.close()`` and cursor-based iteration.

    Raises
    ------
    ConfigurationError
        When ``TOKENDNA_DB_BACKEND=postgres`` but no DSN is configured.
    BackendUnavailableError
        When the Postgres pool cannot be reached.
    """
    cfg = get_backend_config()
    if cfg.backend == "postgres":
        if not cfg.postgres_dsn:
            raise ConfigurationError(
                "TOKENDNA_DB_BACKEND=postgres but TOKENDNA_PG_DSN is not set. "
                "Set TOKENDNA_PG_DSN to a valid libpq connection string."
            )
        with _pg_conn_ctx(autocommit=autocommit) as conn:
            yield conn
    else:
        resolved_path = db_path or os.getenv("DATA_DB_PATH", "/data/tokendna.db")
        with _sqlite_conn_ctx(resolved_path, autocommit=autocommit) as conn:
            yield conn


@contextlib.contextmanager
def _sqlite_conn_ctx(
    db_path: str,
    *,
    autocommit: bool,
) -> Generator[sqlite3.Connection, None, None]:
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    isolation = None if autocommit else ""
    conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=isolation)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for concurrent readers + FK enforcement (idempotent)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        if not autocommit:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextlib.contextmanager
def _pg_conn_ctx(*, autocommit: bool) -> Generator[Any, None, None]:
    pool = _get_pg_pool()
    with pool.connection() as conn:
        if autocommit:
            conn.autocommit = True
        try:
            yield conn
            if not autocommit:
                conn.commit()
        except Exception:
            if not autocommit:
                conn.rollback()
            raise


# ---------------------------------------------------------------------------
# Dual-write helper
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def get_dual_write_conns(
    db_path: str | None = None,
) -> Generator[tuple[Any, Any | None], None, None]:
    """
    Context manager for dual-write migration.

    Yields ``(primary_conn, secondary_conn_or_None)``.

    When ``TOKENDNA_DB_DUAL_WRITE=true``:
      * primary_conn  → SQLite (source of truth during migration)
      * secondary_conn → Postgres (written in parallel)

    When dual-write is off, secondary_conn is ``None``.

    Both connections are managed independently; an error on the secondary
    is logged and swallowed so the primary write always succeeds.
    """
    resolved_path = db_path or os.getenv("DATA_DB_PATH", "/data/tokendna.db")

    if not should_dual_write():
        with _sqlite_conn_ctx(resolved_path, autocommit=False) as conn:
            yield conn, None
        return

    # Open both
    sqlite_ctx = _sqlite_conn_ctx(resolved_path, autocommit=False)
    pg_ctx = _pg_conn_ctx(autocommit=False)

    with sqlite_ctx as primary:
        try:
            with pg_ctx as secondary:
                try:
                    yield primary, secondary
                except Exception as exc:
                    # Roll back secondary on any caller error
                    try:
                        secondary.rollback()
                    except Exception:
                        pass
                    raise exc
        except (ConfigurationError, BackendUnavailableError) as pool_err:
            record_backend_fallback(
                reason=str(pool_err),
                context={"db_path": resolved_path},
            )
            logger.warning(
                "Dual-write: Postgres secondary unavailable, continuing SQLite-only. %s",
                pool_err,
            )
            yield primary, None
