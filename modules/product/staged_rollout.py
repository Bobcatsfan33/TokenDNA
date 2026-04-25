"""
TokenDNA — Staged Rollout / Per-Tenant Feature Allowlists

Sits between ``commercial_tiers`` and the routes. The default flow remains
"tenant tier ≥ feature min_tier → entitled". This module adds a per-tenant
override:

    A tenant on Plan.FREE (community tier) can be allowlisted onto
    ``ent.intent_correlation`` for design-partner / beta / staged-rollout
    purposes — without changing their commercial plan.

The override is **additive only** — there is no "denylist". Tenants
already entitled by their tier remain entitled regardless of allowlist
state. This keeps the failure mode clean: allowlist outages can only
*restrict* access in their absence (fail-closed for the override), they
cannot revoke baseline tier entitlement.

Tables
------
``tenant_feature_allowlists``  (tenant_id, feature_key, granted_at, granted_by,
                                reason, revoked_at, revoked_by)

Audit
-----
Every grant / revoke writes to the same table — reads filter on revoked_at
IS NULL. The full history is retained so an auditor can prove a tenant had
access to a feature at a specific point in time.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from modules.product import commercial_tiers
from modules.storage import db_backend

logger = logging.getLogger(__name__)
_lock = threading.Lock()


def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _use_pg() -> bool:
    return db_backend.should_use_postgres()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tenant_feature_allowlists (
    grant_id        TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    feature_key     TEXT NOT NULL,
    granted_at      TEXT NOT NULL,
    granted_by      TEXT NOT NULL,
    reason          TEXT NOT NULL DEFAULT '',
    revoked_at      TEXT,
    revoked_by      TEXT,
    revoke_reason   TEXT
);

CREATE INDEX IF NOT EXISTS idx_allowlist_tenant
    ON tenant_feature_allowlists(tenant_id, feature_key, revoked_at);
CREATE UNIQUE INDEX IF NOT EXISTS uq_allowlist_active
    ON tenant_feature_allowlists(tenant_id, feature_key)
    WHERE revoked_at IS NULL;
"""


def init_db() -> None:
    if _use_pg():
        return
    db_path = _db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    with _lock:
        conn = _get_conn()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AllowlistGrant:
    grant_id: str
    tenant_id: str
    feature_key: str
    granted_at: str
    granted_by: str
    reason: str
    revoked_at: str | None = None
    revoked_by: str | None = None
    revoke_reason: str | None = None

    def is_active(self) -> bool:
        return self.revoked_at is None

    def as_dict(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "tenant_id": self.tenant_id,
            "feature_key": self.feature_key,
            "granted_at": self.granted_at,
            "granted_by": self.granted_by,
            "reason": self.reason,
            "revoked_at": self.revoked_at,
            "revoked_by": self.revoked_by,
            "revoke_reason": self.revoke_reason,
            "active": self.is_active(),
        }


# ── Public surface ────────────────────────────────────────────────────────────

class AllowlistError(ValueError):
    """Raised when a grant/revoke cannot be applied."""


def is_allowlisted(tenant_id: str, feature_key: str) -> bool:
    """Hot-path check: does this tenant have an active grant for this
    feature? Defensive: missing table or PG mode → return False (fail
    closed for the override, never overrides true entitlement)."""
    if _use_pg():
        return False
    try:
        with _lock:
            conn = _get_conn()
            try:
                row = conn.execute(
                    """
                    SELECT 1 FROM tenant_feature_allowlists
                    WHERE tenant_id=? AND feature_key=? AND revoked_at IS NULL
                    LIMIT 1
                    """,
                    (tenant_id, feature_key),
                ).fetchone()
                return row is not None
            finally:
                conn.close()
    except sqlite3.OperationalError:
        # Table not yet initialized — treat as no override.
        return False


def grant_access(
    tenant_id: str,
    feature_key: str,
    granted_by: str,
    reason: str = "",
) -> AllowlistGrant:
    """
    Grant a tenant access to a feature outside its commercial tier.

    Errors:
      AllowlistError("unknown_feature_key") — typo guard, fail-closed.
      AllowlistError("already_active")      — pre-existing active grant
                                                (call revoke first).
    """
    if feature_key not in commercial_tiers.COMMERCIAL_FEATURES:
        raise AllowlistError("unknown_feature_key")
    if _use_pg():
        raise NotImplementedError("staged_rollout PG path not implemented")
    if is_allowlisted(tenant_id, feature_key):
        raise AllowlistError("already_active")
    grant_id = f"grant:{uuid.uuid4().hex[:24]}"
    granted_at = _iso(_now())
    with _lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                INSERT INTO tenant_feature_allowlists
                    (grant_id, tenant_id, feature_key, granted_at, granted_by, reason)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (grant_id, tenant_id, feature_key, granted_at,
                 granted_by, reason or ""),
            )
            conn.commit()
        finally:
            conn.close()
    logger.info(
        "staged_rollout grant tenant=%s feature=%s by=%s reason=%s",
        tenant_id, feature_key, granted_by, reason or "-",
    )
    return AllowlistGrant(
        grant_id=grant_id, tenant_id=tenant_id, feature_key=feature_key,
        granted_at=granted_at, granted_by=granted_by, reason=reason or "",
    )


def revoke_access(
    tenant_id: str,
    feature_key: str,
    revoked_by: str,
    reason: str = "",
) -> dict[str, Any]:
    """Revoke the *active* grant for (tenant, feature). Idempotent: returns
    ``{"revoked": False, "reason": "no_active_grant"}`` if there's nothing
    to revoke."""
    if _use_pg():
        return {"revoked": False, "reason": "pg_not_implemented"}
    revoked_at = _iso(_now())
    with _lock:
        conn = _get_conn()
        try:
            cur = conn.execute(
                """
                UPDATE tenant_feature_allowlists
                SET revoked_at = ?, revoked_by = ?, revoke_reason = ?
                WHERE tenant_id=? AND feature_key=? AND revoked_at IS NULL
                """,
                (revoked_at, revoked_by, reason or "",
                 tenant_id, feature_key),
            )
            conn.commit()
        finally:
            conn.close()
    if cur.rowcount == 0:
        return {"revoked": False, "reason": "no_active_grant"}
    logger.info(
        "staged_rollout revoke tenant=%s feature=%s by=%s reason=%s",
        tenant_id, feature_key, revoked_by, reason or "-",
    )
    return {
        "revoked": True,
        "tenant_id": tenant_id,
        "feature_key": feature_key,
        "revoked_at": revoked_at,
        "revoked_by": revoked_by,
    }


def list_grants(
    tenant_id: str,
    *,
    include_revoked: bool = False,
) -> list[AllowlistGrant]:
    if _use_pg():
        return []
    with _lock:
        conn = _get_conn()
        try:
            sql = "SELECT * FROM tenant_feature_allowlists WHERE tenant_id=?"
            if not include_revoked:
                sql += " AND revoked_at IS NULL"
            sql += " ORDER BY granted_at DESC"
            rows = conn.execute(sql, (tenant_id,)).fetchall()
            return [
                AllowlistGrant(
                    grant_id=r["grant_id"],
                    tenant_id=r["tenant_id"],
                    feature_key=r["feature_key"],
                    granted_at=r["granted_at"],
                    granted_by=r["granted_by"],
                    reason=r["reason"],
                    revoked_at=r["revoked_at"],
                    revoked_by=r["revoked_by"],
                    revoke_reason=r["revoke_reason"],
                )
                for r in rows
            ]
        finally:
            conn.close()


def list_active_grants_for_feature(feature_key: str) -> list[AllowlistGrant]:
    """Operator query: which tenants have been allowlisted onto this feature?"""
    if _use_pg():
        return []
    with _lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                """
                SELECT * FROM tenant_feature_allowlists
                WHERE feature_key=? AND revoked_at IS NULL
                ORDER BY granted_at DESC
                """,
                (feature_key,),
            ).fetchall()
            return [
                AllowlistGrant(
                    grant_id=r["grant_id"],
                    tenant_id=r["tenant_id"],
                    feature_key=r["feature_key"],
                    granted_at=r["granted_at"],
                    granted_by=r["granted_by"],
                    reason=r["reason"],
                    revoked_at=r["revoked_at"],
                    revoked_by=r["revoked_by"],
                    revoke_reason=r["revoke_reason"],
                )
                for r in rows
            ]
        finally:
            conn.close()
