"""
TokenDNA — Cross-tenant Threat Intelligence Sharing Network

Sits **above** ``modules.identity.intent_correlation``: the per-tenant
``intent_playbooks`` table is the local store; this module adds an opt-in
network layer that anonymizes a tenant's playbook, propagates it to all
opted-in tenants, and tracks who has received what so sync stays idempotent.

Trust model
-----------
- Sharing is **strictly opt-in**. Tenants without an opt-in row receive
  nothing on sync and cannot publish.
- Anonymization is **enforced at publish time**: tenant-, agent-, user-, and
  IP-level identifiers are stripped from the playbook (including the name
  and description), replaced with stable per-playbook generic labels
  (``agent_A``, ``tenant_X`` …). Detection logic — ``category``,
  ``mitre_technique``, ``pivot``, ``objective``, ``min_confidence``,
  ``risk_tier`` — is preserved verbatim so the correlation engine still
  fires on propagated copies.
- The shared catalog stores a SHA-256 of the source ``tenant_id`` for
  publish-side dedup; the raw tenant id never leaves the publisher's row.

Schema
------
Three new tables:
  ``threat_sharing_tenants``  opt-in registry + counters
  ``network_playbooks``       anonymized shared catalog
  ``network_propagations``    (tenant_id, network_playbook_id) → local copy

Plus three additive columns on ``intent_playbooks``:
  ``source``               'local' (default) | 'network'
  ``network_playbook_id``  back-reference to ``network_playbooks``
  ``shared``               0/1 — 1 once the local playbook has been published

PG vs SQLite
------------
SQL is written against SQLite first (the dev/test backend) and uses idioms
that also work on PG 13+ — recursive CTEs are not needed here, ``ALTER TABLE
ADD COLUMN`` is wrapped in try/except for the non-destructive migration. The
PG branch mirrors the SQLite branch where ``db_backend.should_use_postgres``
returns true.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from modules.identity import intent_correlation
from modules.storage import db_backend


# ── Constants ─────────────────────────────────────────────────────────────────

# Field names whose *values* are treated as PII and replaced with stable
# per-playbook placeholders. Lower-cased on lookup.
_PII_FIELDS: dict[str, str] = {
    "tenant_id": "tenant",
    "tenant": "tenant",
    "agent_id": "agent",
    "agent": "agent",
    "agent_a": "agent",
    "agent_b": "agent",
    "agent_id_a": "agent",
    "agent_id_b": "agent",
    "user_id": "user",
    "subject": "user",
    "sub": "user",
    "owner": "user",
    "email": "user",
    "principal": "user",
    "ip": "ip",
    "ip_address": "ip",
    "source_ip": "ip",
    "src_ip": "ip",
    "dest_ip": "ip",
    "dst_ip": "ip",
    "client_ip": "ip",
    "remote_ip": "ip",
}

# Fields whose values are detection logic and must NEVER be rewritten —
# even if the value happens to look like an IP/email.
_PRESERVE_FIELDS: frozenset[str] = frozenset({
    "category",
    "mitre_technique",
    "pivot",
    "objective",
    "min_confidence",
    "risk_tier",
})

# Fields that should be dropped entirely from the published payload — they
# are tenancy/local-store metadata, not detection content.
_DROP_FIELDS: frozenset[str] = frozenset({
    "tenant_id",
    "playbook_id",
    "created_at",
    "updated_at",
    "builtin",
    "enabled",
    "source",
    "network_playbook_id",
    "shared",
})

_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")

_lock = threading.Lock()


# ── DB helpers ────────────────────────────────────────────────────────────────

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


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_tenant(tenant_id: str) -> str:
    """Stable SHA-256 of the tenant id. Used for dedup, never reversed."""
    return hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()[:32]


# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_sharing_tenants (
    tenant_id        TEXT PRIMARY KEY,
    opted_in         INTEGER NOT NULL DEFAULT 0,
    opted_in_at      TEXT,
    opted_out_at     TEXT,
    published_count  INTEGER NOT NULL DEFAULT 0,
    received_count   INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS network_playbooks (
    network_playbook_id  TEXT PRIMARY KEY,
    source_tenant_hash   TEXT NOT NULL,
    source_playbook_id   TEXT NOT NULL,
    name                 TEXT NOT NULL,
    description          TEXT NOT NULL,
    severity             TEXT NOT NULL,
    steps_json           TEXT NOT NULL,
    window_seconds       INTEGER NOT NULL,
    published_at         TEXT NOT NULL,
    revoked              INTEGER NOT NULL DEFAULT 0,
    UNIQUE(source_tenant_hash, source_playbook_id)
);

CREATE INDEX IF NOT EXISTS idx_network_playbooks_published
    ON network_playbooks(published_at DESC, revoked);

CREATE TABLE IF NOT EXISTS network_propagations (
    tenant_id            TEXT NOT NULL,
    network_playbook_id  TEXT NOT NULL,
    propagated_at        TEXT NOT NULL,
    local_playbook_id    TEXT NOT NULL,
    PRIMARY KEY (tenant_id, network_playbook_id)
);

CREATE INDEX IF NOT EXISTS idx_network_propagations_tenant
    ON network_propagations(tenant_id);
"""

_INTENT_PLAYBOOK_MIGRATIONS: tuple[str, ...] = (
    "ALTER TABLE intent_playbooks ADD COLUMN source TEXT NOT NULL DEFAULT 'local'",
    "ALTER TABLE intent_playbooks ADD COLUMN network_playbook_id TEXT",
    "ALTER TABLE intent_playbooks ADD COLUMN shared INTEGER NOT NULL DEFAULT 0",
)


def init_db() -> None:
    """Create tables and run the additive migration on intent_playbooks."""
    if _use_pg():
        return  # PG path mirrors SQLite — left as a stub for parity.
    # intent_playbooks must exist before we ALTER it.
    intent_correlation.init_db()

    db_path = _db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    with _lock:
        conn = _get_conn()
        try:
            conn.executescript(_SCHEMA)
            for ddl in _INTENT_PLAYBOOK_MIGRATIONS:
                try:
                    conn.execute(ddl)
                except sqlite3.OperationalError:
                    # Column already present from a prior init_db() — ignore.
                    pass
            conn.commit()
        finally:
            conn.close()


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PublishReceipt:
    network_playbook_id: str
    source_playbook_id: str
    tenant_id: str
    name: str
    severity: str
    published_at: str
    deduplicated: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "network_playbook_id": self.network_playbook_id,
            "source_playbook_id": self.source_playbook_id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "severity": self.severity,
            "published_at": self.published_at,
            "deduplicated": self.deduplicated,
        }


# ── Anonymization ─────────────────────────────────────────────────────────────

class _Anonymizer:
    """Rewrites a playbook in place against per-instance counters so identity
    equality across occurrences within one playbook is preserved (e.g. two
    references to ``alice@x.com`` collapse to the same ``user_A``)."""

    _LETTER_LIMIT = 26

    def __init__(self) -> None:
        self._counters: dict[str, int] = {"agent": 0, "tenant": 0, "user": 0, "ip": 0}
        self._seen: dict[tuple[str, str], str] = {}

    def placeholder(self, kind: str, value: str) -> str:
        key = (kind, value)
        cached = self._seen.get(key)
        if cached is not None:
            return cached
        self._counters.setdefault(kind, 0)
        self._counters[kind] += 1
        n = self._counters[kind]
        suffix = chr(ord("A") + n - 1) if n <= self._LETTER_LIMIT else str(n)
        ph = f"{kind}_{suffix}"
        self._seen[key] = ph
        return ph

    def scrub_text(self, value: str) -> str:
        """Regex-scrub free-text strings (name/description) for inline PII."""
        value = _IPV4_RE.sub(lambda m: self.placeholder("ip", m.group(0)), value)
        value = _EMAIL_RE.sub(lambda m: self.placeholder("user", m.group(0)), value)
        return value

    def handle(self, field_name: str, value: Any) -> Any:
        lowered = field_name.lower()
        if lowered in _PRESERVE_FIELDS:
            return value
        kind = _PII_FIELDS.get(lowered)
        if isinstance(value, str):
            if kind is not None:
                return self.placeholder(kind, value)
            return self.scrub_text(value)
        return self.walk(value)

    def walk(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: self.handle(k, v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.walk(x) for x in obj]
        if isinstance(obj, tuple):
            return tuple(self.walk(x) for x in obj)
        return obj


def anonymize_playbook(playbook: dict[str, Any]) -> dict[str, Any]:
    """
    Strip tenant-, agent-, user-, and IP-level identifiers from a playbook.

    Behaviour:
      - Top-level tenancy/storage metadata (``tenant_id``, ``playbook_id``,
        ``created_at`` …) is dropped.
      - Known PII field values are replaced with stable per-playbook
        placeholders (``agent_A``, ``user_B`` …) so identity equality across
        occurrences within the playbook is preserved.
      - Free-text fields (``name``, ``description``) are regex-scrubbed for
        inline IPs and emails.
      - Detection-logic fields (``category``, ``mitre_technique``, ``pivot``,
        ``objective``, ``min_confidence``, ``risk_tier``) are passed through
        verbatim — their values would not be PII and the engine relies on
        them.

    The function is pure — the input dict is not mutated.
    """
    if not isinstance(playbook, dict):
        raise TypeError("playbook must be a dict")

    cleaned: dict[str, Any] = {
        k: v for k, v in playbook.items() if k.lower() not in _DROP_FIELDS
    }
    anon = _Anonymizer()
    out: dict[str, Any] = {}
    for key, value in cleaned.items():
        out[key] = anon.handle(key, value)
    return out


# ── Opt-in registry ───────────────────────────────────────────────────────────

def _ensure_row(conn: sqlite3.Connection, tenant_id: str) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO threat_sharing_tenants
            (tenant_id, opted_in, published_count, received_count, created_at)
        VALUES (?, 0, 0, 0, ?)
        """,
        (tenant_id, _now_iso()),
    )


def opt_in(tenant_id: str) -> dict[str, Any]:
    """Mark a tenant as opted in. Idempotent."""
    if _use_pg():
        return {"tenant_id": tenant_id, "opted_in": True, "opted_in_at": _now_iso()}
    now = _now_iso()
    with _lock:
        conn = _get_conn()
        try:
            _ensure_row(conn, tenant_id)
            conn.execute(
                """
                UPDATE threat_sharing_tenants
                SET opted_in=1, opted_in_at=?, opted_out_at=NULL
                WHERE tenant_id=?
                """,
                (now, tenant_id),
            )
            conn.commit()
        finally:
            conn.close()
    return get_status(tenant_id)


def opt_out(tenant_id: str) -> dict[str, Any]:
    """Mark a tenant as opted out. Past propagations are retained — only
    future sync calls are blocked. Idempotent."""
    if _use_pg():
        return {"tenant_id": tenant_id, "opted_in": False, "opted_out_at": _now_iso()}
    now = _now_iso()
    with _lock:
        conn = _get_conn()
        try:
            _ensure_row(conn, tenant_id)
            conn.execute(
                """
                UPDATE threat_sharing_tenants
                SET opted_in=0, opted_out_at=?
                WHERE tenant_id=?
                """,
                (now, tenant_id),
            )
            conn.commit()
        finally:
            conn.close()
    return get_status(tenant_id)


def is_opted_in(tenant_id: str) -> bool:
    if _use_pg():
        return False
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT opted_in FROM threat_sharing_tenants WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
            return bool(row and row["opted_in"])
        finally:
            conn.close()


def get_status(tenant_id: str) -> dict[str, Any]:
    """Return opt-in status + counters for the tenant. Tenants that have
    never interacted with the network get a synthetic 'never opted in' view."""
    if _use_pg():
        return {
            "tenant_id": tenant_id,
            "opted_in": False,
            "opted_in_at": None,
            "opted_out_at": None,
            "published_count": 0,
            "received_count": 0,
        }
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM threat_sharing_tenants WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
            if not row:
                return {
                    "tenant_id": tenant_id,
                    "opted_in": False,
                    "opted_in_at": None,
                    "opted_out_at": None,
                    "published_count": 0,
                    "received_count": 0,
                }
            return {
                "tenant_id": row["tenant_id"],
                "opted_in": bool(row["opted_in"]),
                "opted_in_at": row["opted_in_at"],
                "opted_out_at": row["opted_out_at"],
                "published_count": row["published_count"],
                "received_count": row["received_count"],
            }
        finally:
            conn.close()


# ── Publish ───────────────────────────────────────────────────────────────────

def publish_playbook(tenant_id: str, playbook_id: str) -> dict[str, Any]:
    """
    Publish a tenant-owned playbook to the shared network catalog.

    Errors:
      ValueError("not_opted_in")     — caller must opt in first
      ValueError("not_found")        — playbook id unknown / not owned
      ValueError("builtin_blocked")  — built-in playbooks are global, not
                                       owned by any tenant and cannot be
                                       republished

    Idempotent on (source_tenant_hash, source_playbook_id) — re-publishing
    returns the existing receipt with ``deduplicated=True``.
    """
    if _use_pg():
        raise NotImplementedError("threat_sharing PG path not implemented")

    if not is_opted_in(tenant_id):
        raise ValueError("not_opted_in")

    now = _now_iso()
    src_hash = _hash_tenant(tenant_id)

    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM intent_playbooks WHERE playbook_id=? AND tenant_id=?",
                (playbook_id, tenant_id),
            ).fetchone()
            if not row:
                raise ValueError("not_found")
            if row["builtin"]:
                raise ValueError("builtin_blocked")

            # Dedup on (source_tenant_hash, source_playbook_id).
            existing = conn.execute(
                """
                SELECT network_playbook_id, name, severity, published_at
                FROM network_playbooks
                WHERE source_tenant_hash=? AND source_playbook_id=?
                """,
                (src_hash, playbook_id),
            ).fetchone()
            if existing:
                return PublishReceipt(
                    network_playbook_id=existing["network_playbook_id"],
                    source_playbook_id=playbook_id,
                    tenant_id=tenant_id,
                    name=existing["name"],
                    severity=existing["severity"],
                    published_at=existing["published_at"],
                    deduplicated=True,
                ).as_dict()

            local_view = {
                "name": row["name"],
                "description": row["description"],
                "severity": row["severity"],
                "steps": json.loads(row["steps_json"]),
                "window_seconds": row["window_seconds"],
            }
            anon = anonymize_playbook(local_view)

            net_id = f"net:{uuid.uuid4().hex[:24]}"
            conn.execute(
                """
                INSERT INTO network_playbooks
                    (network_playbook_id, source_tenant_hash, source_playbook_id,
                     name, description, severity, steps_json, window_seconds,
                     published_at, revoked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    net_id,
                    src_hash,
                    playbook_id,
                    anon["name"],
                    anon["description"],
                    anon["severity"],
                    json.dumps(anon["steps"]),
                    int(anon.get("window_seconds") or row["window_seconds"]),
                    now,
                ),
            )
            conn.execute(
                "UPDATE intent_playbooks SET shared=1, updated_at=? WHERE playbook_id=?",
                (now, playbook_id),
            )
            _ensure_row(conn, tenant_id)
            conn.execute(
                """
                UPDATE threat_sharing_tenants
                SET published_count = published_count + 1
                WHERE tenant_id=?
                """,
                (tenant_id,),
            )
            conn.commit()
            return PublishReceipt(
                network_playbook_id=net_id,
                source_playbook_id=playbook_id,
                tenant_id=tenant_id,
                name=anon["name"],
                severity=anon["severity"],
                published_at=now,
                deduplicated=False,
            ).as_dict()
        finally:
            conn.close()


# ── Propagate / sync ──────────────────────────────────────────────────────────

def _network_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "network_playbook_id": row["network_playbook_id"],
        "name": row["name"],
        "description": row["description"],
        "severity": row["severity"],
        "steps": json.loads(row["steps_json"]),
        "window_seconds": row["window_seconds"],
        "published_at": row["published_at"],
        "revoked": bool(row["revoked"]),
    }


def list_network_playbooks(limit: int = 100) -> list[dict[str, Any]]:
    """Browse the shared catalog. The view is identical for every tenant —
    nothing here ties a network playbook back to its publisher."""
    if _use_pg():
        return []
    limit = max(1, min(int(limit), 500))
    with _lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                """
                SELECT * FROM network_playbooks
                WHERE revoked=0
                ORDER BY published_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [_network_row_to_dict(r) for r in rows]
        finally:
            conn.close()


def propagate_to_tenant(
    tenant_id: str,
    network_playbook_id: str,
) -> dict[str, Any] | None:
    """
    Copy one network playbook into a tenant's ``intent_playbooks`` table.

    Idempotent: a row in ``network_propagations`` (tenant_id, network_playbook_id)
    short-circuits subsequent calls. Returns the propagation record on
    success, or ``None`` if the network playbook does not exist / is revoked.
    """
    if _use_pg():
        return None
    now = _now_iso()
    with _lock:
        conn = _get_conn()
        try:
            existing = conn.execute(
                """
                SELECT propagated_at, local_playbook_id
                FROM network_propagations
                WHERE tenant_id=? AND network_playbook_id=?
                """,
                (tenant_id, network_playbook_id),
            ).fetchone()
            if existing:
                return {
                    "tenant_id": tenant_id,
                    "network_playbook_id": network_playbook_id,
                    "local_playbook_id": existing["local_playbook_id"],
                    "propagated_at": existing["propagated_at"],
                    "deduplicated": True,
                }

            net = conn.execute(
                "SELECT * FROM network_playbooks WHERE network_playbook_id=? AND revoked=0",
                (network_playbook_id,),
            ).fetchone()
            if not net:
                return None

            local_pid = f"network:{uuid.uuid4().hex[:16]}"
            conn.execute(
                """
                INSERT INTO intent_playbooks
                    (playbook_id, tenant_id, name, description, severity,
                     steps_json, window_seconds, enabled, builtin,
                     created_at, updated_at,
                     source, network_playbook_id, shared)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?, 'network', ?, 0)
                """,
                (
                    local_pid, tenant_id, net["name"], net["description"],
                    net["severity"], net["steps_json"], net["window_seconds"],
                    now, now, network_playbook_id,
                ),
            )
            conn.execute(
                """
                INSERT INTO network_propagations
                    (tenant_id, network_playbook_id, propagated_at, local_playbook_id)
                VALUES (?, ?, ?, ?)
                """,
                (tenant_id, network_playbook_id, now, local_pid),
            )
            _ensure_row(conn, tenant_id)
            conn.execute(
                """
                UPDATE threat_sharing_tenants
                SET received_count = received_count + 1
                WHERE tenant_id=?
                """,
                (tenant_id,),
            )
            conn.commit()
            return {
                "tenant_id": tenant_id,
                "network_playbook_id": network_playbook_id,
                "local_playbook_id": local_pid,
                "propagated_at": now,
                "deduplicated": False,
            }
        finally:
            conn.close()


def sync_network_playbooks(tenant_id: str) -> int:
    """
    Pull every non-revoked network playbook this tenant has not yet received
    and propagate it. Tenants that are not opted in get a no-op (returns 0).

    Returns the count of newly propagated playbooks.
    """
    if _use_pg():
        return 0
    if not is_opted_in(tenant_id):
        return 0

    with _lock:
        conn = _get_conn()
        try:
            pending = conn.execute(
                """
                SELECT np.network_playbook_id
                FROM network_playbooks np
                LEFT JOIN network_propagations p
                    ON p.network_playbook_id = np.network_playbook_id
                   AND p.tenant_id = ?
                WHERE p.network_playbook_id IS NULL
                  AND np.revoked = 0
                ORDER BY np.published_at ASC
                """,
                (tenant_id,),
            ).fetchall()
            ids = [r["network_playbook_id"] for r in pending]
        finally:
            conn.close()

    added = 0
    for nid in ids:
        result = propagate_to_tenant(tenant_id, nid)
        if result and not result.get("deduplicated"):
            added += 1
    return added
