"""
TokenDNA -- Persistent store for agent attestation records and certificates.

Uses SQLite for portability. In production this can be swapped for Postgres
behind the same function interface.
"""

from __future__ import annotations

import base64
import json
import math
import os
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any

from modules.storage import db_backend
from modules.storage.pg_connection import AdaptedCursor, get_db_conn


_lock = threading.Lock()


def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _pg_dsn() -> str:
    from modules.storage.pg_connection import normalize_dsn_for_psycopg

    return normalize_dsn_for_psycopg(str(os.getenv("TOKENDNA_PG_DSN", "")).strip())


def _encode_cursor(order_value: str, item_id: str) -> str:
    raw = f"{order_value}|{item_id}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8")


def _decode_cursor(cursor: str | None) -> tuple[str, str] | None:
    if not cursor:
        return None
    try:
        decoded = base64.urlsafe_b64decode(cursor.encode("utf-8")).decode("utf-8")
    except Exception:
        return None
    if "|" not in decoded:
        return None
    order_value, item_id = decoded.split("|", 1)
    if not order_value or not item_id:
        return None
    return order_value, item_id


@contextmanager
def _cursor():
    """Yield a backend-portable AdaptedCursor (SQLite or Postgres)."""
    with _lock:
        with get_db_conn(db_path=_db_path()) as conn:
            yield AdaptedCursor(conn.cursor())


def init_db() -> None:
    db_path = _db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    with _cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_attestations (
                attestation_id         TEXT PRIMARY KEY,
                tenant_id              TEXT NOT NULL,
                agent_id               TEXT NOT NULL,
                created_at             TEXT NOT NULL,
                integrity_digest       TEXT NOT NULL,
                agent_dna_fingerprint  TEXT NOT NULL,
                who_json               TEXT NOT NULL,
                what_json              TEXT NOT NULL,
                how_json               TEXT NOT NULL,
                why_json               TEXT NOT NULL,
                record_json            TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS attestation_certificates (
                certificate_id         TEXT PRIMARY KEY,
                tenant_id              TEXT NOT NULL,
                attestation_id         TEXT NOT NULL,
                issued_at              TEXT NOT NULL,
                expires_at             TEXT NOT NULL,
                issuer                 TEXT NOT NULL,
                subject                TEXT NOT NULL,
                signature_alg          TEXT NOT NULL DEFAULT 'HS256',
                ca_key_id              TEXT NOT NULL DEFAULT 'tokendna-ca-default',
                status                 TEXT NOT NULL DEFAULT 'active',
                revoked_at             TEXT,
                revocation_reason      TEXT,
                signature              TEXT NOT NULL,
                certificate_json       TEXT NOT NULL
            )
            """
        )
        # Non-destructive migration for DBs created before certificate lifecycle fields.
        for ddl in (
            "ALTER TABLE attestation_certificates ADD COLUMN signature_alg TEXT NOT NULL DEFAULT 'HS256'",
            "ALTER TABLE attestation_certificates ADD COLUMN ca_key_id TEXT NOT NULL DEFAULT 'tokendna-ca-default'",
            "ALTER TABLE attestation_certificates ADD COLUMN status TEXT NOT NULL DEFAULT 'active'",
            "ALTER TABLE attestation_certificates ADD COLUMN revoked_at TEXT",
            "ALTER TABLE attestation_certificates ADD COLUMN revocation_reason TEXT",
        ):
            try:
                cur.execute(ddl)
            except Exception:
                pass
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS attestation_drift_events (
                drift_event_id          TEXT PRIMARY KEY,
                tenant_id               TEXT NOT NULL,
                agent_id                TEXT NOT NULL,
                attestation_id          TEXT,
                certificate_id          TEXT,
                detected_at             TEXT NOT NULL,
                severity                TEXT NOT NULL,
                drift_score             REAL NOT NULL,
                reasons_json            TEXT NOT NULL,
                event_json              TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS attestation_ca_keys (
                key_id                  TEXT PRIMARY KEY,
                algorithm               TEXT NOT NULL,
                backend                 TEXT NOT NULL,
                kms_key_id              TEXT,
                public_key_pem          TEXT,
                status                  TEXT NOT NULL DEFAULT 'active',
                activated_at            TEXT,
                deactivated_at          TEXT,
                metadata_json           TEXT NOT NULL
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_agent_attestations_tenant_created ON agent_attestations(tenant_id, created_at DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_agent_attestations_tenant_agent_created ON agent_attestations(tenant_id, agent_id, created_at DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_attestation_certs_tenant_attestation ON attestation_certificates(tenant_id, attestation_id)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_attestation_certs_tenant_status ON attestation_certificates(tenant_id, status, issued_at DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_attestation_certs_tenant_keyid ON attestation_certificates(tenant_id, ca_key_id, issued_at DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_attestation_drift_tenant_agent_detected ON attestation_drift_events(tenant_id, agent_id, detected_at DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_attestation_ca_keys_status ON attestation_ca_keys(status, activated_at DESC)"
        )


def insert_attestation(tenant_id: str, record: dict[str, Any]) -> None:
    if db_backend.should_dual_write():
        # Postgres dual-write for migration safety; never blocks sqlite success.
        try:
            import psycopg
            dsn = _pg_dsn()
            if dsn:
                with psycopg.connect(dsn) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            CREATE TABLE IF NOT EXISTS agent_attestations (
                                attestation_id         TEXT PRIMARY KEY,
                                tenant_id              TEXT NOT NULL,
                                agent_id               TEXT NOT NULL,
                                created_at             TEXT NOT NULL,
                                integrity_digest       TEXT NOT NULL,
                                agent_dna_fingerprint  TEXT NOT NULL,
                                who_json               TEXT NOT NULL,
                                what_json              TEXT NOT NULL,
                                how_json               TEXT NOT NULL,
                                why_json               TEXT NOT NULL,
                                record_json            JSONB NOT NULL
                            )
                            """
                        )
                        cur.execute(
                            """
                            INSERT INTO agent_attestations (
                                attestation_id, tenant_id, agent_id, created_at, integrity_digest,
                                agent_dna_fingerprint, who_json, what_json, how_json, why_json, record_json
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (attestation_id) DO UPDATE SET
                                tenant_id = EXCLUDED.tenant_id,
                                agent_id = EXCLUDED.agent_id,
                                created_at = EXCLUDED.created_at,
                                integrity_digest = EXCLUDED.integrity_digest,
                                agent_dna_fingerprint = EXCLUDED.agent_dna_fingerprint,
                                who_json = EXCLUDED.who_json,
                                what_json = EXCLUDED.what_json,
                                how_json = EXCLUDED.how_json,
                                why_json = EXCLUDED.why_json,
                                record_json = EXCLUDED.record_json
                            """,
                            (
                                record["attestation_id"],
                                tenant_id,
                                record.get("who", {}).get("agent_id", "unknown"),
                                record["created_at"],
                                record["integrity_digest"],
                                record["agent_dna_fingerprint"],
                                json.dumps(record.get("who", {})),
                                json.dumps(record.get("what", {})),
                                json.dumps(record.get("how", {})),
                                json.dumps(record.get("why", {})),
                                json.dumps(record),
                            ),
                        )
                    conn.commit()
        except Exception as exc:
            db_backend.record_backend_fallback(
                "attestation_store.insert_attestation dual-write postgres failed",
                context={"error": str(exc), "tenant_id": tenant_id},
            )
    with _cursor() as cur:
        cur.execute(
            """
            INSERT OR REPLACE INTO agent_attestations (
                attestation_id, tenant_id, agent_id, created_at, integrity_digest,
                agent_dna_fingerprint, who_json, what_json, how_json, why_json, record_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["attestation_id"],
                tenant_id,
                record.get("who", {}).get("agent_id", "unknown"),
                record["created_at"],
                record["integrity_digest"],
                record["agent_dna_fingerprint"],
                json.dumps(record.get("who", {})),
                json.dumps(record.get("what", {})),
                json.dumps(record.get("how", {})),
                json.dumps(record.get("why", {})),
                json.dumps(record),
            ),
        )


def get_attestation(tenant_id: str, attestation_id: str) -> dict[str, Any] | None:
    with _cursor() as cur:
        row = cur.execute(
            """
            SELECT record_json
            FROM agent_attestations
            WHERE tenant_id = ? AND attestation_id = ?
            """,
            (tenant_id, attestation_id),
        ).fetchone()
    if not row:
        return None
    return json.loads(row["record_json"])


def list_attestations(tenant_id: str, limit: int = 50, agent_id: str | None = None) -> list[dict[str, Any]]:
    with _cursor() as cur:
        if agent_id:
            rows = cur.execute(
                """
                SELECT record_json
                FROM agent_attestations
                WHERE tenant_id = ? AND agent_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (tenant_id, agent_id, limit),
            ).fetchall()
        else:
            rows = cur.execute(
                """
                SELECT record_json
                FROM agent_attestations
                WHERE tenant_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
    return [json.loads(row["record_json"]) for row in rows]


def list_attestations_paginated(
    tenant_id: str,
    *,
    page_size: int = 50,
    cursor: str | None = None,
    agent_id: str | None = None,
) -> dict[str, Any]:
    size = max(1, min(int(page_size), 200))
    decoded = _decode_cursor(cursor)
    params: list[Any] = [tenant_id]
    where = ["tenant_id = ?"]
    if agent_id:
        where.append("agent_id = ?")
        params.append(agent_id)
    if decoded:
        ts, attestation_id = decoded
        where.append("(created_at < ? OR (created_at = ? AND attestation_id < ?))")
        params.extend([ts, ts, attestation_id])
    params.append(size + 1)
    with _cursor() as cur:
        rows = cur.execute(
            f"""
            SELECT attestation_id, created_at, record_json
            FROM agent_attestations
            WHERE {' AND '.join(where)}
            ORDER BY created_at DESC, attestation_id DESC
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
    has_more = len(rows) > size
    selected = rows[:size]
    items = [json.loads(row["record_json"]) for row in selected]
    next_cursor = None
    if has_more and selected:
        last = selected[-1]
        next_cursor = _encode_cursor(str(last["created_at"]), str(last["attestation_id"]))
    return {
        "items": items,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "page_size": size,
    }


def insert_certificate(tenant_id: str, certificate: dict[str, Any]) -> None:
    if db_backend.should_dual_write():
        try:
            import psycopg
            dsn = _pg_dsn()
            if dsn:
                with psycopg.connect(dsn) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            CREATE TABLE IF NOT EXISTS attestation_certificates (
                                certificate_id         TEXT PRIMARY KEY,
                                tenant_id              TEXT NOT NULL,
                                attestation_id         TEXT NOT NULL,
                                issued_at              TEXT NOT NULL,
                                expires_at             TEXT NOT NULL,
                                issuer                 TEXT NOT NULL,
                                subject                TEXT NOT NULL,
                                signature_alg          TEXT NOT NULL,
                                ca_key_id              TEXT NOT NULL,
                                status                 TEXT NOT NULL,
                                revoked_at             TEXT,
                                revocation_reason      TEXT,
                                signature              TEXT NOT NULL,
                                certificate_json       JSONB NOT NULL
                            )
                            """
                        )
                        cur.execute(
                            """
                            INSERT INTO attestation_certificates (
                                certificate_id, tenant_id, attestation_id, issued_at, expires_at,
                                issuer, subject, signature_alg, ca_key_id, status, revoked_at, revocation_reason,
                                signature, certificate_json
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (certificate_id) DO UPDATE SET
                                tenant_id = EXCLUDED.tenant_id,
                                attestation_id = EXCLUDED.attestation_id,
                                issued_at = EXCLUDED.issued_at,
                                expires_at = EXCLUDED.expires_at,
                                issuer = EXCLUDED.issuer,
                                subject = EXCLUDED.subject,
                                signature_alg = EXCLUDED.signature_alg,
                                ca_key_id = EXCLUDED.ca_key_id,
                                status = EXCLUDED.status,
                                revoked_at = EXCLUDED.revoked_at,
                                revocation_reason = EXCLUDED.revocation_reason,
                                signature = EXCLUDED.signature,
                                certificate_json = EXCLUDED.certificate_json
                            """,
                            (
                                certificate["certificate_id"],
                                tenant_id,
                                certificate["attestation_id"],
                                certificate["issued_at"],
                                certificate["expires_at"],
                                certificate["issuer"],
                                certificate["subject"],
                                certificate.get("signature_alg", "HS256"),
                                certificate.get("ca_key_id", "tokendna-ca-default"),
                                certificate.get("status", "active"),
                                certificate.get("revoked_at"),
                                certificate.get("revocation_reason"),
                                certificate["signature"],
                                json.dumps(certificate),
                            ),
                        )
                    conn.commit()
        except Exception as exc:
            db_backend.record_backend_fallback(
                "attestation_store.insert_certificate dual-write postgres failed",
                context={"error": str(exc), "tenant_id": tenant_id},
            )
    with _cursor() as cur:
        cur.execute(
            """
            INSERT OR REPLACE INTO attestation_certificates (
                certificate_id, tenant_id, attestation_id, issued_at, expires_at,
                issuer, subject, signature_alg, ca_key_id, status, revoked_at, revocation_reason,
                signature, certificate_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                certificate["certificate_id"],
                tenant_id,
                certificate["attestation_id"],
                certificate["issued_at"],
                certificate["expires_at"],
                certificate["issuer"],
                certificate["subject"],
                certificate.get("signature_alg", "HS256"),
                certificate.get("ca_key_id", "tokendna-ca-default"),
                certificate.get("status", "active"),
                certificate.get("revoked_at"),
                certificate.get("revocation_reason"),
                certificate["signature"],
                json.dumps(certificate),
            ),
        )


def get_certificate(tenant_id: str, certificate_id: str) -> dict[str, Any] | None:
    with _cursor() as cur:
        row = cur.execute(
            """
            SELECT certificate_json
            FROM attestation_certificates
            WHERE tenant_id = ? AND certificate_id = ?
            """,
            (tenant_id, certificate_id),
        ).fetchone()
    if not row:
        return None
    return json.loads(row["certificate_json"])


def get_certificate_by_attestation_id(tenant_id: str, attestation_id: str) -> dict[str, Any] | None:
    with _cursor() as cur:
        row = cur.execute(
            """
            SELECT certificate_json
            FROM attestation_certificates
            WHERE tenant_id = ? AND attestation_id = ?
            ORDER BY issued_at DESC
            LIMIT 1
            """,
            (tenant_id, attestation_id),
        ).fetchone()
    if not row:
        return None
    return json.loads(row["certificate_json"])


def list_certificates(
    tenant_id: str,
    limit: int = 50,
    subject: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    with _cursor() as cur:
        if subject and status:
            rows = cur.execute(
                """
                SELECT certificate_json
                FROM attestation_certificates
                WHERE tenant_id = ? AND subject = ? AND status = ?
                ORDER BY issued_at DESC
                LIMIT ?
                """,
                (tenant_id, subject, status, limit),
            ).fetchall()
        elif subject:
            rows = cur.execute(
                """
                SELECT certificate_json
                FROM attestation_certificates
                WHERE tenant_id = ? AND subject = ?
                ORDER BY issued_at DESC
                LIMIT ?
                """,
                (tenant_id, subject, limit),
            ).fetchall()
        elif status:
            rows = cur.execute(
                """
                SELECT certificate_json
                FROM attestation_certificates
                WHERE tenant_id = ? AND status = ?
                ORDER BY issued_at DESC
                LIMIT ?
                """,
                (tenant_id, status, limit),
            ).fetchall()
        else:
            rows = cur.execute(
                """
                SELECT certificate_json
                FROM attestation_certificates
                WHERE tenant_id = ?
                ORDER BY issued_at DESC
                LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
    return [json.loads(row["certificate_json"]) for row in rows]


def list_certificates_paginated(
    tenant_id: str,
    *,
    page_size: int = 50,
    cursor: str | None = None,
    subject: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    size = max(1, min(int(page_size), 200))
    decoded = _decode_cursor(cursor)
    params: list[Any] = [tenant_id]
    where = ["tenant_id = ?"]
    if subject:
        where.append("subject = ?")
        params.append(subject)
    if status:
        where.append("status = ?")
        params.append(status)
    if decoded:
        issued_at, certificate_id = decoded
        where.append("(issued_at < ? OR (issued_at = ? AND certificate_id < ?))")
        params.extend([issued_at, issued_at, certificate_id])
    params.append(size + 1)
    with _cursor() as cur:
        rows = cur.execute(
            f"""
            SELECT certificate_id, issued_at, certificate_json
            FROM attestation_certificates
            WHERE {' AND '.join(where)}
            ORDER BY issued_at DESC, certificate_id DESC
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
    has_more = len(rows) > size
    selected = rows[:size]
    items = [json.loads(row["certificate_json"]) for row in selected]
    next_cursor = None
    if has_more and selected:
        last = selected[-1]
        next_cursor = _encode_cursor(str(last["issued_at"]), str(last["certificate_id"]))
    return {
        "items": items,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "page_size": size,
    }


def revoke_certificate(
    tenant_id: str,
    certificate_id: str,
    revoked_at: str,
    reason: str,
) -> dict[str, Any] | None:
    existing = get_certificate(tenant_id=tenant_id, certificate_id=certificate_id)
    if existing is None:
        return None

    updated = dict(existing)
    updated["status"] = "revoked"
    updated["revoked_at"] = revoked_at
    updated["revocation_reason"] = reason
    insert_certificate(tenant_id=tenant_id, certificate=updated)
    return updated


def get_latest_attestation_for_agent(tenant_id: str, agent_id: str) -> dict[str, Any] | None:
    with _cursor() as cur:
        row = cur.execute(
            """
            SELECT record_json
            FROM agent_attestations
            WHERE tenant_id = ? AND agent_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (tenant_id, agent_id),
        ).fetchone()
    if not row:
        return None
    return json.loads(row["record_json"])


def insert_drift_event(tenant_id: str, event: dict[str, Any]) -> None:
    with _cursor() as cur:
        cur.execute(
            """
            INSERT OR REPLACE INTO attestation_drift_events (
                drift_event_id, tenant_id, agent_id, attestation_id, certificate_id,
                detected_at, severity, drift_score, reasons_json, event_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["drift_event_id"],
                tenant_id,
                event.get("agent_id", "unknown"),
                event.get("attestation_id"),
                event.get("certificate_id"),
                event["detected_at"],
                event.get("severity", "info"),
                float(event.get("drift_score", 0.0)),
                json.dumps(event.get("reasons", [])),
                json.dumps(event),
            ),
        )


def list_drift_events(
    tenant_id: str,
    limit: int = 100,
    agent_id: str | None = None,
) -> list[dict[str, Any]]:
    with _cursor() as cur:
        if agent_id:
            rows = cur.execute(
                """
                SELECT event_json
                FROM attestation_drift_events
                WHERE tenant_id = ? AND agent_id = ?
                ORDER BY detected_at DESC
                LIMIT ?
                """,
                (tenant_id, agent_id, limit),
            ).fetchall()
        else:
            rows = cur.execute(
                """
                SELECT event_json
                FROM attestation_drift_events
                WHERE tenant_id = ?
                ORDER BY detected_at DESC
                LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
    return [json.loads(row["event_json"]) for row in rows]


def list_drift_events_paginated(
    tenant_id: str,
    *,
    page_size: int = 100,
    cursor: str | None = None,
    agent_id: str | None = None,
) -> dict[str, Any]:
    size = max(1, min(int(page_size), 500))
    decoded = _decode_cursor(cursor)
    params: list[Any] = [tenant_id]
    where = ["tenant_id = ?"]
    if agent_id:
        where.append("agent_id = ?")
        params.append(agent_id)
    if decoded:
        detected_at, drift_event_id = decoded
        where.append("(detected_at < ? OR (detected_at = ? AND drift_event_id < ?))")
        params.extend([detected_at, detected_at, drift_event_id])
    params.append(size + 1)
    with _cursor() as cur:
        rows = cur.execute(
            f"""
            SELECT drift_event_id, detected_at, event_json
            FROM attestation_drift_events
            WHERE {' AND '.join(where)}
            ORDER BY detected_at DESC, drift_event_id DESC
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
    has_more = len(rows) > size
    selected = rows[:size]
    items = [json.loads(row["event_json"]) for row in selected]
    next_cursor = None
    if has_more and selected:
        last = selected[-1]
        next_cursor = _encode_cursor(str(last["detected_at"]), str(last["drift_event_id"]))
    return {
        "items": items,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "page_size": size,
    }


def upsert_ca_key(
    *,
    key_id: str,
    algorithm: str,
    backend: str,
    kms_key_id: str | None = None,
    public_key_pem: str | None = None,
    status: str = "active",
    activated_at: str | None = None,
    deactivated_at: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    with _cursor() as cur:
        cur.execute(
            """
            INSERT OR REPLACE INTO attestation_ca_keys (
                key_id, algorithm, backend, kms_key_id, public_key_pem,
                status, activated_at, deactivated_at, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                key_id,
                algorithm.upper(),
                backend.lower(),
                kms_key_id,
                public_key_pem,
                status,
                activated_at,
                deactivated_at,
                json.dumps(metadata or {}, sort_keys=True),
            ),
        )


def get_ca_key(key_id: str) -> dict[str, Any] | None:
    with _cursor() as cur:
        row = cur.execute(
            """
            SELECT key_id, algorithm, backend, kms_key_id, public_key_pem,
                   status, activated_at, deactivated_at, metadata_json
            FROM attestation_ca_keys
            WHERE key_id = ?
            """,
            (key_id,),
        ).fetchone()
    if not row:
        return None
    return {
        "key_id": row["key_id"],
        "algorithm": row["algorithm"],
        "backend": row["backend"],
        "kms_key_id": row["kms_key_id"],
        "public_key_pem": row["public_key_pem"],
        "status": row["status"],
        "activated_at": row["activated_at"],
        "deactivated_at": row["deactivated_at"],
        "metadata": json.loads(row["metadata_json"]),
    }


def list_ca_keys(status: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    with _cursor() as cur:
        if status:
            rows = cur.execute(
                """
                SELECT key_id, algorithm, backend, kms_key_id, public_key_pem,
                       status, activated_at, deactivated_at, metadata_json
                FROM attestation_ca_keys
                WHERE status = ?
                ORDER BY activated_at DESC
                LIMIT ?
                """,
                (status, limit),
            ).fetchall()
        else:
            rows = cur.execute(
                """
                SELECT key_id, algorithm, backend, kms_key_id, public_key_pem,
                       status, activated_at, deactivated_at, metadata_json
                FROM attestation_ca_keys
                ORDER BY activated_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
    return [
        {
            "key_id": row["key_id"],
            "algorithm": row["algorithm"],
            "backend": row["backend"],
            "kms_key_id": row["kms_key_id"],
            "public_key_pem": row["public_key_pem"],
            "status": row["status"],
            "activated_at": row["activated_at"],
            "deactivated_at": row["deactivated_at"],
            "metadata": json.loads(row["metadata_json"]),
        }
        for row in rows
    ]
