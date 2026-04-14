"""
TokenDNA -- Persistent store for agent attestation records and certificates.

Uses SQLite for portability. In production this can be swapped for Postgres
behind the same function interface.
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
                signature              TEXT NOT NULL,
                certificate_json       TEXT NOT NULL
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


def insert_attestation(tenant_id: str, record: dict[str, Any]) -> None:
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


def insert_certificate(tenant_id: str, certificate: dict[str, Any]) -> None:
    with _cursor() as cur:
        cur.execute(
            """
            INSERT OR REPLACE INTO attestation_certificates (
                certificate_id, tenant_id, attestation_id, issued_at, expires_at,
                issuer, subject, signature, certificate_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                certificate["certificate_id"],
                tenant_id,
                certificate["attestation_id"],
                certificate["issued_at"],
                certificate["expires_at"],
                certificate["issuer"],
                certificate["subject"],
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
