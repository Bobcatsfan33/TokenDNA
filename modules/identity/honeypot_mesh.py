"""
TokenDNA — Active Deception / Honeypot Mesh

The existing ``deception_mesh`` is *passive* — it catches forged
attestations against known-good profiles. This module flips that to
*active*: emit attestation-valid decoys that no real workflow ever calls,
and any traffic to them is by definition adversarial reconnaissance.

Three decoy classes
-------------------
1. ``synthetic_agent``  — a fully-formed agent identity (agent_id,
                          plausible name, behavioral DNA fingerprint)
                          that is never deployed. Real agents never call
                          it. Network traffic targeting it = recon.

2. ``honeytoken_credential`` — an API-key-shaped string seeded into
                          public bait surfaces (gist, dummy S3, leaked
                          CI logs) and watched. Anyone presenting one is
                          mid-attack.

3. ``honeytoken_certificate`` — a cert that *looks* valid but is flagged
                          ``revoked`` server-side. A presenter is
                          credential-stuffing or replaying a stolen cert.

What this enables
-----------------
- ``record_decoy_hit`` writes a high-severity, high-confidence anomaly
  the moment a decoy receives traffic — feeds straight into
  ``intent_correlation`` upstream.
- ``is_honeytoken(token_value)`` is the runtime hook: edge-enforcement
  / network gateway / SDK calls this on every incoming credential and
  short-circuits to a deception-hit response without exposing whether
  the *real* token would have been valid.
- ``get_decoy_inventory`` + ``get_decoy_hits`` for the operator dashboard.

Trust model
-----------
- Each decoy carries a ``public_id`` (visible to attackers) and a
  ``secret_hash`` (SHA-256 of the actual credential value, never the
  plaintext). ``is_honeytoken`` looks up by hash so a leaked database
  dump still doesn't reveal active honeytokens.
- Honeytokens never authenticate. ``is_honeytoken == True`` is a
  terminal signal.
- Hits are tenant-scoped; cross-tenant lookups by an attacker probing
  ``public_id`` produce nothing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from modules.storage import db_backend

logger = logging.getLogger(__name__)
_lock = threading.Lock()


DECOY_KINDS: frozenset[str] = frozenset({
    "synthetic_agent", "honeytoken_credential", "honeytoken_certificate",
})


def _secret() -> bytes:
    from modules.security.secret_gate import secret_value

    return secret_value(
        "TOKENDNA_HONEYPOT_SECRET",
        "dev-honeypot-secret-do-not-use-in-prod",
    ).encode("utf-8")


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


def _hash_token(token: str) -> str:
    """Hash a raw token value for storage. Salted by the server secret so
    two tenants seeding the same plaintext (unlikely but possible) get
    distinct hashes — and a leaked DB dump can't be correlated to any
    plaintext via rainbow tables."""
    return hmac.new(_secret(), token.encode("utf-8"), hashlib.sha256).hexdigest()


# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS honeypot_decoys (
    decoy_id        TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    kind            TEXT NOT NULL,
    public_id       TEXT NOT NULL,
    secret_hash     TEXT NOT NULL,
    metadata_json   TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL,
    active          INTEGER NOT NULL DEFAULT 1,
    hits            INTEGER NOT NULL DEFAULT 0,
    last_hit_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_honeypot_tenant
    ON honeypot_decoys(tenant_id, kind, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_honeypot_secret
    ON honeypot_decoys(secret_hash);
CREATE INDEX IF NOT EXISTS idx_honeypot_public
    ON honeypot_decoys(public_id);

CREATE TABLE IF NOT EXISTS honeypot_hits (
    hit_id          TEXT PRIMARY KEY,
    decoy_id        TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    detected_at     TEXT NOT NULL,
    source_ip       TEXT,
    user_agent      TEXT,
    request_path    TEXT,
    request_meta    TEXT NOT NULL DEFAULT '{}',
    severity        TEXT NOT NULL DEFAULT 'critical',
    acknowledged    INTEGER NOT NULL DEFAULT 0,
    acknowledged_at TEXT,
    acknowledged_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_honeypot_hits_tenant
    ON honeypot_hits(tenant_id, acknowledged, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_honeypot_hits_decoy
    ON honeypot_hits(decoy_id, detected_at DESC);
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
class Decoy:
    decoy_id: str
    tenant_id: str
    kind: str
    public_id: str
    metadata: dict[str, Any]
    created_at: str
    active: bool
    hits: int
    last_hit_at: str | None
    # secret_value only set on the *creation* response; never returned later.
    secret_value: str | None = None

    def as_dict(self) -> dict[str, Any]:
        out = {
            "decoy_id": self.decoy_id,
            "tenant_id": self.tenant_id,
            "kind": self.kind,
            "public_id": self.public_id,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
            "active": self.active,
            "hits": self.hits,
            "last_hit_at": self.last_hit_at,
        }
        if self.secret_value is not None:
            out["secret_value"] = self.secret_value
            out["secret_warning"] = (
                "This is the only time the secret will be visible. Seed it into "
                "your bait surfaces immediately and discard."
            )
        return out


# ── Synthetic agent / honeytoken creation ─────────────────────────────────────

def _generate_synthetic_agent_id() -> str:
    """Produce an agent_id that *looks* like a real one. The point is that
    these are indistinguishable from real agents to an attacker scanning the
    catalog — the only thing that flags them is that no legitimate workflow
    calls them."""
    return f"agt-{secrets.token_hex(8)}"


def _generate_credential() -> str:
    """A plausible-looking API key. Prefix matches the production scheme so
    the bait blends in (it'll fail authentication anyway)."""
    return "tdna_" + secrets.token_urlsafe(40)


def synthesize_decoy_agent(
    tenant_id: str,
    name_hint: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> Decoy:
    """Create a synthetic agent decoy. Returns the decoy with its plausible
    public agent_id; nothing is "deployed" — the agent_id is just registered
    as a tripwire."""
    return _create_decoy(
        tenant_id=tenant_id,
        kind="synthetic_agent",
        public_id=_generate_synthetic_agent_id(),
        secret_value=_generate_credential(),
        metadata={
            **(metadata or {}),
            "name_hint": name_hint or "anomaly-scanner-bot",
            "purpose": "tripwire — never call this agent",
        },
    )


def seed_honeytoken(
    tenant_id: str,
    kind: str = "honeytoken_credential",
    metadata: dict[str, Any] | None = None,
) -> Decoy:
    """Seed a honeytoken. Returns the *one and only* visibility of the
    secret_value — caller plants it on bait surfaces immediately. Subsequent
    fetches of the decoy never expose the secret again."""
    if kind not in {"honeytoken_credential", "honeytoken_certificate"}:
        raise ValueError(f"unknown_honeytoken_kind:{kind}")
    secret_value = _generate_credential()
    public_id = (
        f"htkn:{secrets.token_hex(8)}"
        if kind == "honeytoken_credential"
        else f"hcert:{secrets.token_hex(8)}"
    )
    return _create_decoy(
        tenant_id=tenant_id,
        kind=kind,
        public_id=public_id,
        secret_value=secret_value,
        metadata=metadata or {},
    )


def _create_decoy(
    *,
    tenant_id: str,
    kind: str,
    public_id: str,
    secret_value: str,
    metadata: dict[str, Any],
) -> Decoy:
    if _use_pg():
        raise NotImplementedError("honeypot_mesh PG path not implemented")
    if kind not in DECOY_KINDS:
        raise ValueError(f"unknown_kind:{kind}")
    decoy_id = f"decoy:{uuid.uuid4().hex[:24]}"
    now = _iso(_now())
    secret_hash = _hash_token(secret_value)
    with _lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                INSERT INTO honeypot_decoys
                    (decoy_id, tenant_id, kind, public_id, secret_hash,
                     metadata_json, created_at, active, hits)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0)
                """,
                (
                    decoy_id, tenant_id, kind, public_id, secret_hash,
                    json.dumps(metadata, sort_keys=True), now,
                ),
            )
            conn.commit()
        finally:
            conn.close()
    return Decoy(
        decoy_id=decoy_id,
        tenant_id=tenant_id,
        kind=kind,
        public_id=public_id,
        metadata=metadata,
        created_at=now,
        active=True,
        hits=0,
        last_hit_at=None,
        secret_value=secret_value,
    )


# ── Detection ────────────────────────────────────────────────────────────────

def is_honeytoken(token_value: str) -> dict[str, Any] | None:
    """
    Look up a presented credential in the honeypot bank. Hash-only — the
    raw plaintext is never compared in cleartext SQL.

    Returns the (tenant-scoped, secret-stripped) decoy dict if matched, or
    None. Designed to be called from the auth path BEFORE the actual
    credential check so the system never reveals via timing or response
    code whether the caller's input would have been a real credential.
    """
    if _use_pg() or not token_value:
        return None
    h = _hash_token(token_value)
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM honeypot_decoys WHERE secret_hash=? AND active=1",
                (h,),
            ).fetchone()
        finally:
            conn.close()
    if not row:
        return None
    return _row_to_safe_dict(row)


def _row_to_safe_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "decoy_id": row["decoy_id"],
        "tenant_id": row["tenant_id"],
        "kind": row["kind"],
        "public_id": row["public_id"],
        "metadata": json.loads(row["metadata_json"] or "{}"),
        "created_at": row["created_at"],
        "active": bool(row["active"]),
        "hits": int(row["hits"] or 0),
        "last_hit_at": row["last_hit_at"],
    }


# ── Hit recording ─────────────────────────────────────────────────────────────

def record_decoy_hit(
    decoy_id: str,
    *,
    source_ip: str | None = None,
    user_agent: str | None = None,
    request_path: str | None = None,
    request_meta: dict[str, Any] | None = None,
    severity: str = "critical",
    tenant_id: str | None = None,
) -> dict[str, Any] | None:
    """Log that a decoy was touched. Bumps the hit counter on the decoy
    row in the same transaction. Returns the hit record; None if the
    decoy doesn't exist or is cross-tenant."""
    if _use_pg():
        return None
    now = _iso(_now())
    hit_id = f"hhit:{uuid.uuid4().hex[:24]}"
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM honeypot_decoys WHERE decoy_id=?",
                (decoy_id,),
            ).fetchone()
            if not row:
                return None
            if tenant_id is not None and row["tenant_id"] != tenant_id:
                return None
            conn.execute(
                """
                INSERT INTO honeypot_hits
                    (hit_id, decoy_id, tenant_id, detected_at, source_ip,
                     user_agent, request_path, request_meta, severity,
                     acknowledged)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    hit_id, decoy_id, row["tenant_id"], now,
                    source_ip, user_agent, request_path,
                    json.dumps(request_meta or {}, sort_keys=True),
                    severity,
                ),
            )
            conn.execute(
                """
                UPDATE honeypot_decoys
                SET hits = hits + 1, last_hit_at = ?
                WHERE decoy_id = ?
                """,
                (now, decoy_id),
            )
            conn.commit()
        finally:
            conn.close()
    logger.warning(
        "honeypot hit decoy=%s tenant=%s ip=%s severity=%s",
        decoy_id, row["tenant_id"], source_ip or "?", severity,
    )
    return {
        "hit_id": hit_id,
        "decoy_id": decoy_id,
        "tenant_id": row["tenant_id"],
        "kind": row["kind"],
        "public_id": row["public_id"],
        "detected_at": now,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "request_path": request_path,
        "severity": severity,
    }


def acknowledge_hit(
    hit_id: str,
    acknowledged_by: str,
    tenant_id: str | None = None,
) -> bool:
    if _use_pg():
        return False
    now = _iso(_now())
    with _lock:
        conn = _get_conn()
        try:
            sql = (
                "UPDATE honeypot_hits "
                "SET acknowledged=1, acknowledged_at=?, acknowledged_by=? "
                "WHERE hit_id=? AND acknowledged=0"
            )
            params: list[Any] = [now, acknowledged_by, hit_id]
            if tenant_id is not None:
                sql += " AND tenant_id=?"
                params.append(tenant_id)
            cur = conn.execute(sql, tuple(params))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


# ── Listing ───────────────────────────────────────────────────────────────────

def get_decoy_inventory(
    tenant_id: str,
    kind: str | None = None,
    active_only: bool = True,
) -> list[dict[str, Any]]:
    if _use_pg():
        return []
    with _lock:
        conn = _get_conn()
        try:
            sql = "SELECT * FROM honeypot_decoys WHERE tenant_id=?"
            params: list[Any] = [tenant_id]
            if kind:
                sql += " AND kind=?"
                params.append(kind)
            if active_only:
                sql += " AND active=1"
            sql += " ORDER BY created_at DESC"
            rows = conn.execute(sql, tuple(params)).fetchall()
            return [_row_to_safe_dict(r) for r in rows]
        finally:
            conn.close()


def get_decoy_hits(
    tenant_id: str,
    decoy_id: str | None = None,
    acknowledged: bool | None = False,
    limit: int = 200,
) -> list[dict[str, Any]]:
    if _use_pg():
        return []
    with _lock:
        conn = _get_conn()
        try:
            sql = "SELECT * FROM honeypot_hits WHERE tenant_id=?"
            params: list[Any] = [tenant_id]
            if decoy_id is not None:
                sql += " AND decoy_id=?"
                params.append(decoy_id)
            if acknowledged is False:
                sql += " AND acknowledged=0"
            elif acknowledged is True:
                sql += " AND acknowledged=1"
            sql += " ORDER BY detected_at DESC LIMIT ?"
            params.append(min(int(limit), 500))
            rows = conn.execute(sql, tuple(params)).fetchall()
            return [
                {
                    "hit_id": r["hit_id"],
                    "decoy_id": r["decoy_id"],
                    "tenant_id": r["tenant_id"],
                    "detected_at": r["detected_at"],
                    "source_ip": r["source_ip"],
                    "user_agent": r["user_agent"],
                    "request_path": r["request_path"],
                    "request_meta": json.loads(r["request_meta"] or "{}"),
                    "severity": r["severity"],
                    "acknowledged": bool(r["acknowledged"]),
                    "acknowledged_at": r["acknowledged_at"],
                    "acknowledged_by": r["acknowledged_by"],
                }
                for r in rows
            ]
        finally:
            conn.close()


def deactivate_decoy(decoy_id: str, tenant_id: str | None = None) -> bool:
    if _use_pg():
        return False
    with _lock:
        conn = _get_conn()
        try:
            sql = "UPDATE honeypot_decoys SET active=0 WHERE decoy_id=? AND active=1"
            params: list[Any] = [decoy_id]
            if tenant_id is not None:
                sql += " AND tenant_id=?"
                params.append(tenant_id)
            cur = conn.execute(sql, tuple(params))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()
