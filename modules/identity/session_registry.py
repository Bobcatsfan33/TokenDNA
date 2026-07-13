"""Agent live-session registry + server-side invalidation (Gap roadmap Epic 2.3).

A rogue agent's *live* sessions (streaming chats, websocket tool loops, long
poll connections) keep running even after its tokens are revoked, until they're
explicitly torn down. This registry tracks every active agent session keyed by
agent, and lets the kill switch terminate them server-side: a terminated
session id is rejected by ``is_session_active``, which the runtime checks before
serving the next frame, so the connection dies on its next turn.

Storage follows the shared pg_connection pattern; init is tracked per db_path so
switching paths (tests, the kill connector touching the default DB) always
applies the schema.
"""
from __future__ import annotations

import os
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Optional

from modules.storage.ddl_runner import run_ddl
from modules.storage.pg_connection import AdaptedCursor, get_db_conn

_DB_PATH = os.getenv("DATA_DB_PATH", os.path.expanduser("~/.tokendna/tokendna.db"))
_lock = threading.Lock()
_initialized_paths: set[str] = set()

_DDL = (
    """
    CREATE TABLE IF NOT EXISTS agent_sessions (
        session_id     TEXT PRIMARY KEY,
        tenant_id      TEXT NOT NULL,
        agent_id       TEXT NOT NULL,
        channel        TEXT NOT NULL DEFAULT 'unknown',
        status         TEXT NOT NULL DEFAULT 'active',
        opened_at      TEXT NOT NULL,
        terminated_at  TEXT,
        terminated_by  TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_agent_sessions_agent ON agent_sessions(tenant_id, agent_id, status)",
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


def register_session(
    *,
    tenant_id: str,
    agent_id: str,
    channel: str = "unknown",
    session_id: Optional[str] = None,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Record a live agent session. Returns its session_id + status."""
    init_db(db_path)
    sid = session_id or str(uuid.uuid4())
    with _cursor(db_path) as cur:
        cur.execute(
            """
            INSERT INTO agent_sessions (session_id, tenant_id, agent_id, channel, status, opened_at)
            VALUES (?, ?, ?, ?, 'active', ?)
            """,
            (sid, tenant_id, agent_id, channel, _now()),
        )
    return {"session_id": sid, "status": "active"}


def is_session_active(tenant_id: str, session_id: str, *, db_path: str = _DB_PATH) -> bool:
    """Server-side check the runtime calls before serving the next frame."""
    init_db(db_path)
    with _cursor(db_path) as cur:
        row = cur.execute(
            "SELECT status FROM agent_sessions WHERE tenant_id=? AND session_id=?",
            (tenant_id, session_id),
        ).fetchone()
    return bool(row) and row["status"] == "active"


def list_active_sessions(tenant_id: str, agent_id: str, *, db_path: str = _DB_PATH) -> list[dict[str, Any]]:
    init_db(db_path)
    with _cursor(db_path) as cur:
        rows = cur.execute(
            "SELECT session_id, channel, opened_at FROM agent_sessions "
            "WHERE tenant_id=? AND agent_id=? AND status='active' ORDER BY opened_at DESC",
            (tenant_id, agent_id),
        ).fetchall()
    return [dict(r) for r in rows]


def terminate_agent_sessions(
    tenant_id: str, agent_id: str, *, terminated_by: str, db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Kill-switch action: terminate every active session for an agent.

    Idempotent; actor required. A terminated session is rejected by
    is_session_active on its next turn (server-side invalidation).
    """
    if not terminated_by:
        raise ValueError("terminated_by is required")
    init_db(db_path)
    now = _now()
    with _cursor(db_path) as cur:
        n = cur.execute(
            "SELECT COUNT(*) AS n FROM agent_sessions WHERE tenant_id=? AND agent_id=? AND status='active'",
            (tenant_id, agent_id),
        ).fetchone()["n"]
        cur.execute(
            "UPDATE agent_sessions SET status='terminated', terminated_at=?, terminated_by=? "
            "WHERE tenant_id=? AND agent_id=? AND status='active'",
            (now, terminated_by, tenant_id, agent_id),
        )
    return {"sessions_terminated": int(n)}
