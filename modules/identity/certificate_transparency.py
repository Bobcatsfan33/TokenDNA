"""
TokenDNA -- Certificate transparency-style append-only log for attestations.

Each entry includes a hash pointer to the previous log entry and a Merkle root
over all entry hashes to provide tamper-evident verification semantics.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any


_lock = threading.Lock()


def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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
            CREATE TABLE IF NOT EXISTS certificate_transparency_log (
                log_index              INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id              TEXT NOT NULL,
                certificate_id         TEXT NOT NULL,
                attestation_id         TEXT NOT NULL,
                action                 TEXT NOT NULL,
                timestamp              TEXT NOT NULL,
                payload_json           TEXT NOT NULL,
                previous_entry_hash    TEXT NOT NULL,
                entry_hash             TEXT NOT NULL,
                merkle_root            TEXT NOT NULL
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_ctlog_tenant_index ON certificate_transparency_log(tenant_id, log_index DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_ctlog_tenant_cert ON certificate_transparency_log(tenant_id, certificate_id)"
        )


def _entry_payload(
    *,
    tenant_id: str,
    certificate_id: str,
    attestation_id: str,
    action: str,
    timestamp: str,
    payload_json: str,
    previous_entry_hash: str,
) -> bytes:
    obj = {
        "tenant_id": tenant_id,
        "certificate_id": certificate_id,
        "attestation_id": attestation_id,
        "action": action,
        "timestamp": timestamp,
        "payload_json": payload_json,
        "previous_entry_hash": previous_entry_hash,
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _merkle_root(entry_hashes: list[str]) -> str:
    if not entry_hashes:
        return "0" * 64
    level = [bytes.fromhex(h) for h in entry_hashes]
    while len(level) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            next_level.append(hashlib.sha256(left + right).digest())
        level = next_level
    return level[0].hex()


def append_log_entry(
    *,
    tenant_id: str,
    certificate_id: str,
    attestation_id: str,
    action: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    timestamp = _iso_now()
    payload_json = json.dumps(payload, sort_keys=True)

    with _cursor() as cur:
        prev_row = cur.execute(
            """
            SELECT entry_hash
            FROM certificate_transparency_log
            WHERE tenant_id = ?
            ORDER BY log_index DESC
            LIMIT 1
            """,
            (tenant_id,),
        ).fetchone()
        previous_entry_hash = prev_row["entry_hash"] if prev_row else "0" * 64
        entry_hash = _sha256_hex(
            _entry_payload(
                tenant_id=tenant_id,
                certificate_id=certificate_id,
                attestation_id=attestation_id,
                action=action,
                timestamp=timestamp,
                payload_json=payload_json,
                previous_entry_hash=previous_entry_hash,
            )
        )

        cur.execute(
            """
            INSERT INTO certificate_transparency_log (
                tenant_id, certificate_id, attestation_id, action, timestamp,
                payload_json, previous_entry_hash, entry_hash, merkle_root
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                certificate_id,
                attestation_id,
                action,
                timestamp,
                payload_json,
                previous_entry_hash,
                entry_hash,
                "0" * 64,  # updated below after insertion
            ),
        )
        log_index = int(cur.lastrowid)

        rows = cur.execute(
            """
            SELECT entry_hash
            FROM certificate_transparency_log
            WHERE tenant_id = ?
            ORDER BY log_index ASC
            """,
            (tenant_id,),
        ).fetchall()
        root = _merkle_root([row["entry_hash"] for row in rows])
        cur.execute(
            """
            UPDATE certificate_transparency_log
            SET merkle_root = ?
            WHERE log_index = ?
            """,
            (root, log_index),
        )

    return {
        "log_index": log_index,
        "tenant_id": tenant_id,
        "certificate_id": certificate_id,
        "attestation_id": attestation_id,
        "action": action,
        "timestamp": timestamp,
        "entry_hash": entry_hash,
        "previous_entry_hash": previous_entry_hash,
        "merkle_root": root,
    }


def list_log_entries(tenant_id: str, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    with _cursor() as cur:
        rows = cur.execute(
            """
            SELECT log_index, tenant_id, certificate_id, attestation_id, action,
                   timestamp, payload_json, previous_entry_hash, entry_hash, merkle_root
            FROM certificate_transparency_log
            WHERE tenant_id = ?
            ORDER BY log_index DESC
            LIMIT ? OFFSET ?
            """,
            (tenant_id, limit, max(int(offset), 0)),
        ).fetchall()
    return [
        {
            "log_index": row["log_index"],
            "tenant_id": row["tenant_id"],
            "certificate_id": row["certificate_id"],
            "attestation_id": row["attestation_id"],
            "action": row["action"],
            "timestamp": row["timestamp"],
            "payload": json.loads(row["payload_json"]),
            "previous_entry_hash": row["previous_entry_hash"],
            "entry_hash": row["entry_hash"],
            "merkle_root": row["merkle_root"],
        }
        for row in rows
    ]


def verify_log_integrity(tenant_id: str) -> dict[str, Any]:
    with _cursor() as cur:
        rows = cur.execute(
            """
            SELECT log_index, tenant_id, certificate_id, attestation_id, action,
                   timestamp, payload_json, previous_entry_hash, entry_hash
            FROM certificate_transparency_log
            WHERE tenant_id = ?
            ORDER BY log_index ASC
            """,
            (tenant_id,),
        ).fetchall()

    previous = "0" * 64
    hashes: list[str] = []
    for row in rows:
        payload_json = row["payload_json"]
        expected = _sha256_hex(
            _entry_payload(
                tenant_id=row["tenant_id"],
                certificate_id=row["certificate_id"],
                attestation_id=row["attestation_id"],
                action=row["action"],
                timestamp=row["timestamp"],
                payload_json=payload_json,
                previous_entry_hash=row["previous_entry_hash"],
            )
        )
        if row["previous_entry_hash"] != previous:
            return {
                "ok": False,
                "reason": "previous_hash_mismatch",
                "log_index": row["log_index"],
            }
        if expected != row["entry_hash"]:
            return {
                "ok": False,
                "reason": "entry_hash_mismatch",
                "log_index": row["log_index"],
            }
        hashes.append(row["entry_hash"])
        previous = row["entry_hash"]

    return {
        "ok": True,
        "entries": len(rows),
        "merkle_root": _merkle_root(hashes),
    }

