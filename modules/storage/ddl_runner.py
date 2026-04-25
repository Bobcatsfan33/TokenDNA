"""
TokenDNA — DDL helper for backend-portable schema initialization.

Provides :func:`run_ddl` for modules that historically used
``conn.executescript(...)`` to apply a multi-statement DDL block.
``executescript`` is SQLite-only; psycopg's cursor only takes one statement
at a time. This helper splits a DDL bundle into individual statements and
runs each through an :class:`AdaptedCursor`, so the same DDL string works
on both backends.

The splitter is naive (boundary on top-level ``;``) which is sufficient for
the simple ``CREATE TABLE`` / ``CREATE INDEX`` shapes TokenDNA modules use.
It does not currently support stored procedures or trigger bodies that
contain inner ``;``.
"""

from __future__ import annotations

import threading
from typing import Iterable

from modules.storage.pg_connection import AdaptedCursor, get_db_conn


_GLOBAL_DDL_LOCK = threading.Lock()


def split_ddl(schema_sql: str) -> list[str]:
    """Split a DDL bundle into individual SQL statements."""
    out: list[str] = []
    buf: list[str] = []
    in_string: str | None = None
    for ch in schema_sql:
        if in_string:
            buf.append(ch)
            if ch == in_string:
                in_string = None
            continue
        if ch in ("'", '"'):
            in_string = ch
            buf.append(ch)
            continue
        if ch == ";":
            stmt = "".join(buf).strip()
            if stmt:
                out.append(stmt)
            buf = []
            continue
        buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return out


def run_ddl(schema_sql: str | Iterable[str], db_path: str | None = None) -> None:
    """
    Apply a DDL bundle on the configured DB backend.

    ``schema_sql`` may be either a single multi-statement string (split on
    top-level ``;``) or an iterable of individual statements.
    """
    if isinstance(schema_sql, str):
        statements = split_ddl(schema_sql)
    else:
        statements = [s.strip() for s in schema_sql if s and s.strip()]
    if not statements:
        return
    with _GLOBAL_DDL_LOCK:
        with get_db_conn(db_path=db_path) as conn:
            cur = AdaptedCursor(conn.cursor())
            for stmt in statements:
                cur.execute(stmt)
