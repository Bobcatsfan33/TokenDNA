"""
TokenDNA — Tenant store
SQLite in dev/single-node; swap DATA_DB_URL to postgres://... for production.
Uses raw sqlite3 (no ORM dependency) for portability.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Optional

from .models import ApiKey, Plan, Tenant

logger = logging.getLogger(__name__)

_DB_PATH = os.getenv("DATA_DB_PATH", "/data/tokendna.db")

# SQLite isn't safe for concurrent writes across processes; in production
# point DATA_DB_URL at PostgreSQL and swap the driver below.
_lock = threading.Lock()


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
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


# ── Schema ────────────────────────────────────────────────────────────────────

def init_db() -> None:
    """Create tables if they don't exist. Idempotent."""
    with _cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS tenants (
                id           TEXT PRIMARY KEY,
                name         TEXT NOT NULL,
                plan         TEXT NOT NULL DEFAULT 'free',
                is_active    INTEGER NOT NULL DEFAULT 1,
                owner_email  TEXT NOT NULL DEFAULT '',
                created_at   TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id           TEXT PRIMARY KEY,
                tenant_id    TEXT NOT NULL REFERENCES tenants(id),
                name         TEXT NOT NULL,
                key_prefix   TEXT NOT NULL,
                key_hash     TEXT NOT NULL UNIQUE,
                is_active    INTEGER NOT NULL DEFAULT 1,
                created_at   TEXT NOT NULL,
                last_used    TEXT
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id)")
    logger.info("Tenant DB initialised at %s", _DB_PATH)


# ── Tenants ───────────────────────────────────────────────────────────────────

def create_tenant(name: str, owner_email: str = "", plan: Plan = Plan.FREE) -> tuple[Tenant, str]:
    """Create a tenant and its first API key. Returns (tenant, raw_api_key)."""
    tenant = Tenant.new(name=name, owner_email=owner_email, plan=plan)
    api_key_record, raw_key = ApiKey.generate(tenant.id, "default")

    with _cursor() as cur:
        cur.execute(
            "INSERT INTO tenants VALUES (?,?,?,?,?,?)",
            (tenant.id, tenant.name, tenant.plan.value,
             int(tenant.is_active), tenant.owner_email,
             tenant.created_at.isoformat()),
        )
        cur.execute(
            "INSERT INTO api_keys VALUES (?,?,?,?,?,?,?,?)",
            (api_key_record.id, api_key_record.tenant_id, api_key_record.name,
             api_key_record.key_prefix, api_key_record.key_hash,
             int(api_key_record.is_active), api_key_record.created_at.isoformat(), None),
        )

    logger.info("Created tenant %s (%s)", tenant.name, tenant.id)
    return tenant, raw_key


def get_tenant(tenant_id: str) -> Optional[Tenant]:
    with _cursor() as cur:
        row = cur.execute("SELECT * FROM tenants WHERE id=?", (tenant_id,)).fetchone()
    return _row_to_tenant(row) if row else None


def list_tenants() -> list[Tenant]:
    with _cursor() as cur:
        rows = cur.execute("SELECT * FROM tenants ORDER BY created_at DESC").fetchall()
    return [_row_to_tenant(r) for r in rows]


def deactivate_tenant(tenant_id: str) -> None:
    with _cursor() as cur:
        cur.execute("UPDATE tenants SET is_active=0 WHERE id=?", (tenant_id,))


# ── API Keys ──────────────────────────────────────────────────────────────────

def create_api_key(tenant_id: str, name: str) -> tuple[ApiKey, str]:
    """Rotate / add a new key for a tenant. Returns (record, raw_key)."""
    record, raw_key = ApiKey.generate(tenant_id=tenant_id, name=name)
    with _cursor() as cur:
        cur.execute(
            "INSERT INTO api_keys VALUES (?,?,?,?,?,?,?,?)",
            (record.id, record.tenant_id, record.name,
             record.key_prefix, record.key_hash,
             int(record.is_active), record.created_at.isoformat(), None),
        )
    return record, raw_key


def lookup_by_key(raw_key: str) -> Optional[tuple[ApiKey, Tenant]]:
    """Primary auth path: hash the raw key, look up tenant. O(1) index lookup."""
    key_hash = ApiKey.hash(raw_key)
    with _cursor() as cur:
        row = cur.execute(
            """SELECT k.*, t.name AS tname, t.plan, t.is_active AS tactive
               FROM api_keys k
               JOIN tenants t ON k.tenant_id = t.id
               WHERE k.key_hash=? AND k.is_active=1 AND t.is_active=1""",
            (key_hash,),
        ).fetchone()
        if row:
            # Update last_used timestamp without blocking the response
            cur.execute(
                "UPDATE api_keys SET last_used=? WHERE id=?",
                (datetime.utcnow().isoformat(), row["id"]),
            )
    if not row:
        return None

    key_record = ApiKey(
        id=row["id"], tenant_id=row["tenant_id"], name=row["name"],
        key_prefix=row["key_prefix"], key_hash=row["key_hash"],
        is_active=bool(row["is_active"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        last_used=datetime.fromisoformat(row["last_used"]) if row["last_used"] else None,
    )
    tenant = Tenant(
        id=row["tenant_id"], name=row["tname"], plan=Plan(row["plan"]),
        is_active=bool(row["tactive"]),
        created_at=datetime.fromisoformat(row["created_at"]),
    )
    return key_record, tenant


def list_api_keys(tenant_id: str) -> list[ApiKey]:
    with _cursor() as cur:
        rows = cur.execute(
            "SELECT * FROM api_keys WHERE tenant_id=? ORDER BY created_at DESC",
            (tenant_id,),
        ).fetchall()
    return [
        ApiKey(
            id=r["id"], tenant_id=r["tenant_id"], name=r["name"],
            key_prefix=r["key_prefix"], key_hash=r["key_hash"],
            is_active=bool(r["is_active"]),
            created_at=datetime.fromisoformat(r["created_at"]),
            last_used=datetime.fromisoformat(r["last_used"]) if r["last_used"] else None,
        )
        for r in rows
    ]


def revoke_api_key(key_id: str, tenant_id: str) -> None:
    with _cursor() as cur:
        cur.execute(
            "UPDATE api_keys SET is_active=0 WHERE id=? AND tenant_id=?",
            (key_id, tenant_id),
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _row_to_tenant(row: sqlite3.Row) -> Tenant:
    return Tenant(
        id=row["id"], name=row["name"], plan=Plan(row["plan"]),
        is_active=bool(row["is_active"]), owner_email=row["owner_email"],
        created_at=datetime.fromisoformat(row["created_at"]),
    )
