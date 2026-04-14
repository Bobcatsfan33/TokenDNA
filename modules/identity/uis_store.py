"""
TokenDNA -- Persistent store for UIS-normalized identity events.

Stores UIS events in SQLite for lightweight local persistence and queryability.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any


_lock = threading.Lock()


def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def _cursor():
    with _lock:
        conn = _get_conn()
        try:
            cur = conn.cursor()
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def init_db() -> None:
    db_path = _db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    with _cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS uis_events (
                event_id        TEXT PRIMARY KEY,
                tenant_id       TEXT NOT NULL,
                subject         TEXT NOT NULL,
                event_timestamp TEXT NOT NULL,
                protocol        TEXT NOT NULL,
                risk_tier       TEXT NOT NULL,
                event_json      TEXT NOT NULL
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_uis_events_tenant_ts ON uis_events(tenant_id, event_timestamp DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_uis_events_tenant_subject_ts ON uis_events(tenant_id, subject, event_timestamp DESC)"
        )


def insert_event(tenant_id: str, event: dict[str, Any]) -> None:
    identity = event.get("identity", {})
    auth = event.get("auth", {})
    threat = event.get("threat", {})
    with _cursor() as cur:
        cur.execute(
            """
            INSERT OR REPLACE INTO uis_events (
                event_id, tenant_id, subject, event_timestamp, protocol, risk_tier, event_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.get("event_id", ""),
                tenant_id,
                identity.get("subject", "unknown"),
                event.get("event_timestamp", ""),
                auth.get("protocol", "custom"),
                threat.get("risk_tier", "unknown"),
                json.dumps(event),
            ),
        )


def get_event(tenant_id: str, event_id: str) -> dict[str, Any] | None:
    with _cursor() as cur:
        row = cur.execute(
            """
            SELECT event_json
            FROM uis_events
            WHERE tenant_id = ? AND event_id = ?
            """,
            (tenant_id, event_id),
        ).fetchone()
    if not row:
        return None
    return json.loads(row["event_json"])


def list_events(tenant_id: str, limit: int = 50, subject: str | None = None) -> list[dict[str, Any]]:
    with _cursor() as cur:
        if subject:
            rows = cur.execute(
                """
                SELECT event_json
                FROM uis_events
                WHERE tenant_id = ? AND subject = ?
                ORDER BY event_timestamp DESC
                LIMIT ?
                """,
                (tenant_id, subject, limit),
            ).fetchall()
        else:
            rows = cur.execute(
                """
                SELECT event_json
                FROM uis_events
                WHERE tenant_id = ?
                ORDER BY event_timestamp DESC
                LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
    return [json.loads(row["event_json"]) for row in rows]
