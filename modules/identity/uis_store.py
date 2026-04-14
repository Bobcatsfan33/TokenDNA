"""
TokenDNA -- Persistent store for UIS-normalized identity events.

Stores UIS events in SQLite for lightweight local persistence and queryability.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any


_lock = threading.Lock()


def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _encode_cursor(event_timestamp: str, event_id: str) -> str:
    raw = f"{event_timestamp}|{event_id}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8")


def _decode_cursor(cursor: str | None) -> tuple[str, str] | None:
    if not cursor:
        return None
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("utf-8")).decode("utf-8")
    except Exception:
        return None
    if "|" not in raw:
        return None
    event_timestamp, event_id = raw.split("|", 1)
    if not event_timestamp or not event_id:
        return None
    return event_timestamp, event_id


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


def list_events_with_cursor(
    tenant_id: str,
    *,
    limit: int = 50,
    subject: str | None = None,
    before_event_timestamp: str | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    normalized_limit = min(max(int(limit), 1), 200)
    with _cursor() as cur:
        params: list[Any] = [tenant_id]
        where = ["tenant_id = ?"]
        if subject:
            where.append("subject = ?")
            params.append(subject)
        if before_event_timestamp:
            where.append("event_timestamp < ?")
            params.append(before_event_timestamp)
        params.append(normalized_limit + 1)
        rows = cur.execute(
            f"""
            SELECT event_json
            FROM uis_events
            WHERE {' AND '.join(where)}
            ORDER BY event_timestamp DESC
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
    payloads = [json.loads(row["event_json"]) for row in rows[:normalized_limit]]
    next_cursor = None
    if len(rows) > normalized_limit and payloads:
        next_cursor = str(payloads[-1].get("event_timestamp") or "")
    return payloads, (next_cursor or None)


def list_events_paginated(
    tenant_id: str,
    *,
    page_size: int = 50,
    cursor: str | None = None,
    subject: str | None = None,
) -> dict[str, Any]:
    normalized_limit = min(max(int(page_size), 1), 200)
    decoded = _decode_cursor(cursor)
    with _cursor() as cur:
        params: list[Any] = [tenant_id]
        where = ["tenant_id = ?"]
        if subject:
            where.append("subject = ?")
            params.append(subject)
        if decoded:
            event_timestamp, event_id = decoded
            where.append("(event_timestamp < ? OR (event_timestamp = ? AND event_id < ?))")
            params.extend([event_timestamp, event_timestamp, event_id])
        params.append(normalized_limit + 1)
        rows = cur.execute(
            f"""
            SELECT event_id, event_timestamp, event_json
            FROM uis_events
            WHERE {' AND '.join(where)}
            ORDER BY event_timestamp DESC, event_id DESC
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
    payloads = [json.loads(row["event_json"]) for row in rows[:normalized_limit]]
    has_more = len(rows) > normalized_limit
    next_cursor = None
    if has_more and rows[:normalized_limit]:
        last = rows[normalized_limit - 1]
        next_cursor = _encode_cursor(str(last["event_timestamp"]), str(last["event_id"]))
    return {
        "items": payloads,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "page_size": normalized_limit,
    }
