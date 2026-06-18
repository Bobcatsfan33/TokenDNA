"""Governed retrieval — agents may query only approved sources (Epic 3.3 / B3).

The NSA MCP advisory calls for *governed retrieval*: an agent must not be able
to pull from arbitrary data sources. This module holds a per-agent allow-list of
source patterns and brokers every retrieval: a request to a source that doesn't
match the allow-list is denied and audited (fail-closed). Patterns are glob
(fnmatch) over source URIs, e.g. ``snowflake://prod/*``, ``s3://reports/**``,
``https://api.weather.com/*``.
"""
from __future__ import annotations

import fnmatch
import os
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from modules.storage.ddl_runner import run_ddl
from modules.storage.pg_connection import AdaptedCursor, get_db_conn

_DB_PATH = os.getenv("DATA_DB_PATH", os.path.expanduser("~/.tokendna/tokendna.db"))
_lock = threading.Lock()
_initialized_paths: set[str] = set()

# Wildcard agent — a policy that applies to every agent in the tenant.
ANY_AGENT = "*"

_DDL = (
    """
    CREATE TABLE IF NOT EXISTS gr_allowed_sources (
        source_id   TEXT PRIMARY KEY,
        tenant_id   TEXT NOT NULL,
        agent_id    TEXT NOT NULL,
        pattern     TEXT NOT NULL,
        kind        TEXT NOT NULL DEFAULT 'any',
        added_by    TEXT,
        added_at    TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_gr_sources ON gr_allowed_sources(tenant_id, agent_id)",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db(db_path: str = _DB_PATH) -> None:
    if db_path in _initialized_paths:
        return
    with _lock:
        if db_path in _initialized_paths:
            return
        run_ddl(_DDL, db_path)
        _initialized_paths.add(db_path)


@contextmanager
def _cursor(db_path: str = _DB_PATH):
    with get_db_conn(db_path=db_path) as conn:
        yield AdaptedCursor(conn.cursor())


def add_allowed_source(
    *, tenant_id: str, agent_id: str, pattern: str, kind: str = "any",
    added_by: str = "system", db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Allow ``agent_id`` (or ANY_AGENT) to retrieve from sources matching pattern."""
    if not pattern:
        raise ValueError("pattern is required")
    init_db(db_path)
    sid = str(uuid.uuid4())
    with _cursor(db_path) as cur:
        cur.execute(
            "INSERT INTO gr_allowed_sources (source_id, tenant_id, agent_id, pattern, kind, added_by, added_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (sid, tenant_id, agent_id, pattern, kind, added_by, _now()),
        )
    return {"source_id": sid, "pattern": pattern}


def list_allowed_sources(*, tenant_id: str, agent_id: Optional[str] = None,
                         db_path: str = _DB_PATH) -> list[dict[str, Any]]:
    init_db(db_path)
    with _cursor(db_path) as cur:
        if agent_id is None:
            rows = cur.execute(
                "SELECT source_id, agent_id, pattern, kind FROM gr_allowed_sources WHERE tenant_id=?",
                (tenant_id,)).fetchall()
        else:
            rows = cur.execute(
                "SELECT source_id, agent_id, pattern, kind FROM gr_allowed_sources "
                "WHERE tenant_id=? AND agent_id IN (?, ?)",
                (tenant_id, agent_id, ANY_AGENT)).fetchall()
    return [dict(r) for r in rows]


def remove_allowed_source(*, tenant_id: str, source_id: str, db_path: str = _DB_PATH) -> bool:
    init_db(db_path)
    with _cursor(db_path) as cur:
        cur.execute("DELETE FROM gr_allowed_sources WHERE tenant_id=? AND source_id=?",
                    (tenant_id, source_id))
    return True


def _emit(allowed: bool, *, tenant_id: str, agent_id: str, source: str, matched: Optional[str]) -> None:
    try:
        from modules.security.audit_log import AuditEventType, AuditOutcome, log_event
        log_event(
            AuditEventType.RETRIEVAL_ALLOWED if allowed else AuditEventType.RETRIEVAL_DENIED,
            AuditOutcome.SUCCESS if allowed else AuditOutcome.FAILURE,
            tenant_id=tenant_id, subject=agent_id, resource=source,
            detail={"source": source, "matched_pattern": matched, "decision": "allow" if allowed else "deny"},
        )
    except Exception:  # noqa: BLE001 - audit best-effort
        pass


def check_retrieval(*, tenant_id: str, agent_id: str, source: str,
                    db_path: str = _DB_PATH) -> dict[str, Any]:
    """Fail-closed decision: allowed only if source matches an allow-list pattern.

    Always audits the decision. Returns {allowed, matched_pattern, source}.
    """
    init_db(db_path)
    patterns = list_allowed_sources(tenant_id=tenant_id, agent_id=agent_id, db_path=db_path)
    matched = None
    for p in patterns:
        if fnmatch.fnmatch(source, p["pattern"]):
            matched = p["pattern"]
            break
    allowed = matched is not None
    _emit(allowed, tenant_id=tenant_id, agent_id=agent_id, source=source, matched=matched)
    return {"allowed": allowed, "matched_pattern": matched, "source": source}


class RetrievalDenied(Exception):
    """Raised by broker() when a retrieval is not permitted."""


def broker(*, tenant_id: str, agent_id: str, source: str, fetch: Callable[[], Any],
           db_path: str = _DB_PATH) -> Any:
    """Run ``fetch()`` only if the source is allowed; else raise RetrievalDenied.

    The single choke point an agent's data access flows through.
    """
    decision = check_retrieval(tenant_id=tenant_id, agent_id=agent_id, source=source, db_path=db_path)
    if not decision["allowed"]:
        raise RetrievalDenied(f"retrieval denied: {source} not in allow-list for {agent_id}")
    return fetch()
