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
