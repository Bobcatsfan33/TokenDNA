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

from modules.storage import db_backend


_lock = threading.Lock()


def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _pg_dsn() -> str:
    from modules.storage.pg_connection import normalize_dsn_for_psycopg

    return normalize_dsn_for_psycopg(os.getenv("TOKENDNA_PG_DSN", ""))


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


def _pg_connect():
    import psycopg

    dsn = _pg_dsn()
    if not dsn:
        raise RuntimeError("TOKENDNA_PG_DSN is required for postgres backend")
    conn = psycopg.connect(dsn)
    conn.autocommit = False
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
    if db_backend.should_use_postgres():
        _pg_init_db()
        return
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
        # Zero-downtime narrative migration: add column to pre-v1.1 databases
        _sqlite_add_column_if_missing(cur, "uis_events", "narrative_json", "TEXT")


def _sqlite_add_column_if_missing(cur: sqlite3.Cursor, table: str, column: str, col_type: str) -> None:
    """Idempotent ALTER TABLE — adds column only if it doesn't already exist."""
    existing = {row[1] for row in cur.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in existing:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")


def _pg_init_db() -> None:
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS uis_events (
                    event_id        TEXT PRIMARY KEY,
                    tenant_id       TEXT NOT NULL,
                    subject         TEXT NOT NULL,
                    event_timestamp TEXT NOT NULL,
                    protocol        TEXT NOT NULL,
                    risk_tier       TEXT NOT NULL,
                    event_json      JSONB NOT NULL
                )
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_uis_events_tenant_ts ON uis_events(tenant_id, event_timestamp DESC)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_uis_events_tenant_subject_ts ON uis_events(tenant_id, subject, event_timestamp DESC)"
            )
        conn.commit()


def bulk_insert_events(
    tenant_id: str,
    events: list[dict[str, Any]],
    *,
    skip_downstream: bool = False,
) -> int:
    """
    High-throughput bulk insert.  Opens ONE connection, uses ``executemany``,
    commits ONCE.  Cuts the demo seeder's 30-day run from ~12 min to under
    30 sec on commodity hardware.

    Parameters
    ----------
    tenant_id
        Tenant the events belong to.
    events
        List of UIS event dicts.  Same shape as ``insert_event`` accepts.
    skip_downstream
        When True, do NOT run the per-event trust_graph / intent_correlation /
        agent_dna refresh side effects.  The seeder uses this because it
        seeds the trust graph from its own templates.  Production ingest
        paths should leave this False (default).

    Returns
    -------
    int
        Number of events inserted.

    Notes
    -----
    * Postgres mode (``TOKENDNA_DB_BACKEND=postgres``) is not yet bulk-aware —
      falls through to per-event insert_event so behavior is preserved.  The
      production ingest path tops out well below SQLite seed throughput so
      bulk PG isn't the bottleneck today.  TODO: psycopg copy-from when needed.
    * Dual-write mode also falls through — same reasoning.
    """
    if not events:
        return 0

    if db_backend.should_use_postgres() or db_backend.should_dual_write():
        for event in events:
            insert_event(tenant_id, event)
        return len(events)

    rows: list[tuple] = []
    for event in events:
        identity = event.get("identity") or {}
        auth = event.get("auth") or {}
        threat = event.get("threat") or {}
        rows.append((
            event.get("event_id", ""),
            tenant_id,
            identity.get("subject", "unknown"),
            event.get("event_timestamp", ""),
            auth.get("protocol", "custom"),
            threat.get("risk_tier", "unknown"),
            json.dumps(event),
        ))

    with _cursor() as cur:
        cur.executemany(
            """
            INSERT OR REPLACE INTO uis_events (
                event_id, tenant_id, subject, event_timestamp, protocol, risk_tier, event_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )

    if not skip_downstream:
        # Run the per-event side effects.  Slower than skipping but preserves
        # production semantics — callers that want max throughput should pass
        # skip_downstream=True and seed the graph / correlation tables
        # themselves.
        try:
            from modules.identity import trust_graph  # noqa: PLC0415
            for event in events:
                anomalies = trust_graph.ingest_uis_event(tenant_id, event)
                for anomaly in anomalies:
                    trust_graph.store_anomaly(anomaly)
        except Exception:  # noqa: BLE001
            pass
        try:
            from modules.identity import intent_correlation  # noqa: PLC0415
            for event in events:
                intent_correlation.correlate_event(tenant_id, event)
        except Exception:  # noqa: BLE001
            pass

    return len(events)


def insert_event(tenant_id: str, event: dict[str, Any]) -> None:
    if db_backend.should_use_postgres():
        _pg_insert_event(tenant_id=tenant_id, event=event)
        return
    if db_backend.should_dual_write():
        try:
            _pg_insert_event(tenant_id=tenant_id, event=event)
        except Exception as exc:
            db_backend.record_backend_fallback(
                "uis_store.insert_event dual-write postgres failed",
                context={"error": str(exc), "tenant_id": tenant_id},
            )
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
    # Incrementally build the trust graph from this event (non-fatal)
    try:
        from modules.identity import trust_graph  # noqa: PLC0415
        anomalies = trust_graph.ingest_uis_event(tenant_id, event)
        for anomaly in anomalies:
            trust_graph.store_anomaly(anomaly)
    except Exception:  # noqa: BLE001
        pass  # graph ingestion never blocks event persistence
    # Run intent correlation against active playbooks (non-fatal)
    try:
        from modules.identity import intent_correlation  # noqa: PLC0415
        intent_correlation.correlate_event(tenant_id, event)
    except Exception:  # noqa: BLE001
        pass  # correlation never blocks event persistence
    # Background agent DNA refresh every 10 observations (non-fatal)
    try:
        _maybe_refresh_agent_dna(tenant_id, event)
    except Exception:  # noqa: BLE001
        pass  # DNA refresh never blocks event persistence


def _maybe_refresh_agent_dna(tenant_id: str, event: dict[str, Any]) -> None:
    """Trigger a background agent DNA refresh if observation count is a multiple of 10."""
    identity = event.get("identity", {})
    agent_id = identity.get("agent_id")
    if not agent_id:
        return
    # Check observation count from trust graph nodes table
    try:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT observation_count FROM tg_nodes WHERE tenant_id=? AND label=?",
                (tenant_id, agent_id),
            ).fetchone()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        return
    if row is None:
        return
    obs = row["observation_count"] if isinstance(row, sqlite3.Row) else row[0]
    if obs % 10 != 0:
        return

    def _bg_refresh() -> None:
        try:
            from modules.identity import agent_dna  # noqa: PLC0415
            agent_dna.refresh_agent_dna(tenant_id=tenant_id, agent_id=agent_id)
        except Exception:  # noqa: BLE001
            pass

    threading.Thread(target=_bg_refresh, daemon=True).start()


def _pg_insert_event(tenant_id: str, event: dict[str, Any]) -> None:
    identity = event.get("identity", {})
    auth = event.get("auth", {})
    threat = event.get("threat", {})
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO uis_events (
                    event_id, tenant_id, subject, event_timestamp, protocol, risk_tier, event_json
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (event_id) DO UPDATE SET
                    tenant_id = EXCLUDED.tenant_id,
                    subject = EXCLUDED.subject,
                    event_timestamp = EXCLUDED.event_timestamp,
                    protocol = EXCLUDED.protocol,
                    risk_tier = EXCLUDED.risk_tier,
                    event_json = EXCLUDED.event_json
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
        conn.commit()


def get_event(tenant_id: str, event_id: str) -> dict[str, Any] | None:
    if db_backend.should_use_postgres():
        return _pg_get_event(tenant_id=tenant_id, event_id=event_id)
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


def _pg_get_event(tenant_id: str, event_id: str) -> dict[str, Any] | None:
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT event_json
                FROM uis_events
                WHERE tenant_id = %s AND event_id = %s
                """,
                (tenant_id, event_id),
            )
            row = cur.fetchone()
    if not row:
        return None
    raw = row[0]
    return raw if isinstance(raw, dict) else json.loads(raw)


def list_events(tenant_id: str, limit: int = 50, subject: str | None = None) -> list[dict[str, Any]]:
    if db_backend.should_use_postgres():
        return _pg_list_events(tenant_id=tenant_id, limit=limit, subject=subject)
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


def _pg_list_events(tenant_id: str, limit: int = 50, subject: str | None = None) -> list[dict[str, Any]]:
    size = min(max(int(limit), 1), 200)
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            if subject:
                cur.execute(
                    """
                    SELECT event_json
                    FROM uis_events
                    WHERE tenant_id = %s AND subject = %s
                    ORDER BY event_timestamp DESC
                    LIMIT %s
                    """,
                    (tenant_id, subject, size),
                )
            else:
                cur.execute(
                    """
                    SELECT event_json
                    FROM uis_events
                    WHERE tenant_id = %s
                    ORDER BY event_timestamp DESC
                    LIMIT %s
                    """,
                    (tenant_id, size),
                )
            rows = cur.fetchall()
    events: list[dict[str, Any]] = []
    for row in rows:
        raw = row[0]
        events.append(raw if isinstance(raw, dict) else json.loads(raw))
    return events


def list_events_with_cursor(
    tenant_id: str,
    *,
    limit: int = 50,
    subject: str | None = None,
    before_event_timestamp: str | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    if db_backend.should_use_postgres():
        return _pg_list_events_with_cursor(
            tenant_id=tenant_id,
            limit=limit,
            subject=subject,
            before_event_timestamp=before_event_timestamp,
        )
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


def _pg_list_events_with_cursor(
    tenant_id: str,
    *,
    limit: int = 50,
    subject: str | None = None,
    before_event_timestamp: str | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    normalized_limit = min(max(int(limit), 1), 200)
    params: list[Any] = [tenant_id]
    where = ["tenant_id = %s"]
    if subject:
        where.append("subject = %s")
        params.append(subject)
    if before_event_timestamp:
        where.append("event_timestamp < %s")
        params.append(before_event_timestamp)
    params.append(normalized_limit + 1)

    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT event_json
                FROM uis_events
                WHERE {' AND '.join(where)}
                ORDER BY event_timestamp DESC
                LIMIT %s
                """,
                tuple(params),
            )
            rows = cur.fetchall()
    payloads: list[dict[str, Any]] = []
    for row in rows[:normalized_limit]:
        raw = row[0]
        payloads.append(raw if isinstance(raw, dict) else json.loads(raw))
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
    if db_backend.should_use_postgres():
        return _pg_list_events_paginated(
            tenant_id=tenant_id,
            page_size=page_size,
            cursor=cursor,
            subject=subject,
        )
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


def _pg_list_events_paginated(
    tenant_id: str,
    *,
    page_size: int = 50,
    cursor: str | None = None,
    subject: str | None = None,
) -> dict[str, Any]:
    normalized_limit = min(max(int(page_size), 1), 200)
    decoded = _decode_cursor(cursor)
    params: list[Any] = [tenant_id]
    where = ["tenant_id = %s"]
    if subject:
        where.append("subject = %s")
        params.append(subject)
    if decoded:
        event_timestamp, event_id = decoded
        where.append("(event_timestamp < %s OR (event_timestamp = %s AND event_id < %s))")
        params.extend([event_timestamp, event_timestamp, event_id])
    params.append(normalized_limit + 1)

    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT event_id, event_timestamp, event_json
                FROM uis_events
                WHERE {' AND '.join(where)}
                ORDER BY event_timestamp DESC, event_id DESC
                LIMIT %s
                """,
                tuple(params),
            )
            rows = cur.fetchall()

    payloads: list[dict[str, Any]] = []
    for row in rows[:normalized_limit]:
        raw = row[2]
        payloads.append(raw if isinstance(raw, dict) else json.loads(raw))
    has_more = len(rows) > normalized_limit
    next_cursor = None
    if has_more and rows[:normalized_limit]:
        last = rows[normalized_limit - 1]
        next_cursor = _encode_cursor(str(last[1]), str(last[0]))
    return {
        "items": payloads,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "page_size": normalized_limit,
    }


def list_events_by_agent_id(
    tenant_id: str,
    agent_id: str,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Return up to *limit* events for the given *agent_id* (matches identity.agent_id).

    Falls back gracefully if the database is not yet initialised.
    """
    normalized_limit = min(max(int(limit), 1), 200)
    try:
        with _cursor() as cur:
            rows = cur.execute(
                """
                SELECT event_json
                FROM uis_events
                WHERE tenant_id = ?
                  AND json_extract(event_json, '$.identity.agent_id') = ?
                ORDER BY event_timestamp DESC
                LIMIT ?
                """,
                (tenant_id, agent_id, normalized_limit),
            ).fetchall()
    except Exception:  # noqa: BLE001
        return []
    return [json.loads(row["event_json"]) for row in rows]
