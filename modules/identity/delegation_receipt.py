"""
TokenDNA — Delegation Receipts

A *Delegation Receipt* is an immutable, signed record issued every time one
principal hands authority to another. Receipts link via ``parent_receipt_id``
back to a root receipt issued by the originating human. The chain answers:

    Who authorized this agent to act, through what intermediaries,
    under what scope, and is the cryptographic proof intact?

Threat model
------------
- A compromised agent must not be able to grant its successor authority it
  did not itself receive. ``issue_receipt`` enforces ``child.scope ⊆
  parent.scope`` and ``new.delegator_id == parent.delegatee_id``.
- A leaked receipt body alone must not pass verification. The signature is
  HMAC-SHA256 over a canonical field set with a server-side secret.
- Revocation of an upstream link must invalidate every descendant in one
  atomic operation (``revoke_receipt(..., cascade=True)``).

Scope semantics
---------------
``scope`` is a list of action strings. A child scope is a subset of a
parent scope iff every child action is covered by some parent action under
glob rules:

    parent "*"          covers anything
    parent "ns:*"       covers "ns" and "ns:<anything>"
    parent "ns:read"    covers only "ns:read"

Empty child scopes are vacuously a subset.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from modules.storage import db_backend


# ── Constants & helpers ───────────────────────────────────────────────────────

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


def _parse_iso(s: str) -> datetime:
    # Python 3.9 fromisoformat does not handle trailing 'Z'.
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def _secret() -> bytes:
    """HMAC key for receipt signatures. Override in production via env."""
    return os.getenv(
        "TOKENDNA_DELEGATION_SECRET",
        "dev-delegation-secret-do-not-use-in-prod",
    ).encode("utf-8")


# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS delegation_receipts (
    receipt_id           TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL,
    delegator_id         TEXT NOT NULL,
    delegatee_id         TEXT NOT NULL,
    scope_json           TEXT NOT NULL,
    ceiling_json         TEXT,
    issued_at            TEXT NOT NULL,
    expires_at           TEXT NOT NULL,
    parent_receipt_id    TEXT,
    human_principal_id   TEXT NOT NULL,
    depth                INTEGER NOT NULL,
    signature            TEXT NOT NULL,
    revoked              INTEGER NOT NULL DEFAULT 0,
    revoked_at           TEXT,
    revoked_by           TEXT,
    FOREIGN KEY(parent_receipt_id) REFERENCES delegation_receipts(receipt_id)
);

CREATE INDEX IF NOT EXISTS idx_delegation_receipts_tenant_delegatee
    ON delegation_receipts(tenant_id, delegatee_id);
CREATE INDEX IF NOT EXISTS idx_delegation_receipts_parent
    ON delegation_receipts(parent_receipt_id);
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
class DelegationReceipt:
    receipt_id: str
    tenant_id: str
    delegator_id: str
    delegatee_id: str
    scope: list[str]
    ceiling: dict[str, Any] | None
    issued_at: str
    expires_at: str
    parent_receipt_id: str | None
    human_principal_id: str
    depth: int
    signature: str
    revoked: bool = False
    revoked_at: str | None = None
    revoked_by: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "tenant_id": self.tenant_id,
            "delegator_id": self.delegator_id,
            "delegatee_id": self.delegatee_id,
            "scope": list(self.scope),
            "ceiling": dict(self.ceiling) if self.ceiling else None,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "parent_receipt_id": self.parent_receipt_id,
            "human_principal_id": self.human_principal_id,
            "depth": self.depth,
            "signature": self.signature,
            "revoked": self.revoked,
            "revoked_at": self.revoked_at,
            "revoked_by": self.revoked_by,
        }


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    reason: str
    receipt_id: str
    checked_at: str = field(default_factory=lambda: _iso(_now()))

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "receipt_id": self.receipt_id,
            "checked_at": self.checked_at,
        }


# ── Canonicalization & signature ──────────────────────────────────────────────

def _canonical_scope_json(scope: list[str]) -> str:
    """Sort + JSON-dump scope for deterministic hashing."""
    return json.dumps(sorted(str(s) for s in scope), separators=(",", ":"))


def _scope_hash(scope: list[str]) -> str:
    return hashlib.sha256(_canonical_scope_json(scope).encode("utf-8")).hexdigest()


def _signing_payload(
    *,
    receipt_id: str,
    tenant_id: str,
    delegator_id: str,
    delegatee_id: str,
    scope: list[str],
    issued_at: str,
    expires_at: str,
    parent_receipt_id: str | None,
) -> bytes:
    parts = [
        receipt_id,
        tenant_id,
        delegator_id,
        delegatee_id,
        _scope_hash(scope),
        issued_at,
        expires_at,
        parent_receipt_id or "",
    ]
    return "|".join(parts).encode("utf-8")


def _sign(payload: bytes) -> str:
    return hmac.new(_secret(), payload, hashlib.sha256).hexdigest()


# ── Scope subset semantics ────────────────────────────────────────────────────

def _action_covers(parent: str, child: str) -> bool:
    if parent == "*":
        return True
    if parent == child:
        return True
    if parent.endswith(":*"):
        prefix = parent[:-2]
        return child == prefix or child.startswith(prefix + ":")
    return False


def _is_subset(parent_scope: list[str], child_scope: list[str]) -> bool:
    """Return True iff every child action is covered by some parent action."""
    if not child_scope:
        return True
    for c in child_scope:
        if not any(_action_covers(p, c) for p in parent_scope):
            return False
    return True


# ── DB → dataclass ────────────────────────────────────────────────────────────

def _row_to_receipt(row: sqlite3.Row) -> DelegationReceipt:
    return DelegationReceipt(
        receipt_id=row["receipt_id"],
        tenant_id=row["tenant_id"],
        delegator_id=row["delegator_id"],
        delegatee_id=row["delegatee_id"],
        scope=json.loads(row["scope_json"]),
        ceiling=json.loads(row["ceiling_json"]) if row["ceiling_json"] else None,
        issued_at=row["issued_at"],
        expires_at=row["expires_at"],
        parent_receipt_id=row["parent_receipt_id"],
        human_principal_id=row["human_principal_id"],
        depth=row["depth"],
        signature=row["signature"],
        revoked=bool(row["revoked"]),
        revoked_at=row["revoked_at"],
        revoked_by=row["revoked_by"],
    )


def _fetch_receipt(conn: sqlite3.Connection, receipt_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM delegation_receipts WHERE receipt_id=?",
        (receipt_id,),
    ).fetchone()


def get_receipt(receipt_id: str, tenant_id: str | None = None) -> DelegationReceipt | None:
    """Look up a receipt by id. ``tenant_id`` enforces tenant isolation."""
    if _use_pg():
        return None
    with _lock:
        conn = _get_conn()
        try:
            row = _fetch_receipt(conn, receipt_id)
            if not row:
                return None
            if tenant_id is not None and row["tenant_id"] != tenant_id:
                return None
            return _row_to_receipt(row)
        finally:
            conn.close()


# ── Issue ─────────────────────────────────────────────────────────────────────

class DelegationError(ValueError):
    """Raised when a delegation cannot be issued."""


def issue_receipt(
    tenant_id: str,
    delegator_id: str,
    delegatee_id: str,
    scope: list[str],
    expires_in_seconds: int,
    parent_receipt_id: str | None = None,
    ceiling: dict[str, Any] | None = None,
) -> DelegationReceipt:
    """
    Issue a signed delegation receipt.

    Root (human-issued) receipts pass ``parent_receipt_id=None`` and a
    ``delegator_id`` of the form ``"human:<user_id>"``.

    Non-root receipts MUST:
      - reference an existing, non-revoked, non-expired parent;
      - have ``delegator_id == parent.delegatee_id`` (you cannot delegate
        authority you did not receive);
      - declare a ``scope`` that is a subset of the parent's scope.

    Raises ``DelegationError`` on any of the above.
    """
    if not isinstance(scope, list) or not all(isinstance(s, str) for s in scope):
        raise DelegationError("scope_must_be_list_of_strings")
    if expires_in_seconds <= 0:
        raise DelegationError("expires_in_seconds_must_be_positive")
    if _use_pg():
        raise NotImplementedError("delegation_receipt PG path not implemented")

    issued_at_dt = _now()
    expires_at_dt = issued_at_dt + timedelta(seconds=expires_in_seconds)
    issued_at = _iso(issued_at_dt)
    expires_at = _iso(expires_at_dt)
    receipt_id = f"rcpt:{uuid.uuid4().hex}"

    with _lock:
        conn = _get_conn()
        try:
            if parent_receipt_id is None:
                # Root receipt: delegator must be a human principal.
                if not delegator_id.startswith("human:"):
                    raise DelegationError("root_delegator_must_be_human")
                human_principal_id = delegator_id
                depth = 0
            else:
                parent_row = _fetch_receipt(conn, parent_receipt_id)
                if parent_row is None:
                    raise DelegationError("parent_not_found")
                if parent_row["tenant_id"] != tenant_id:
                    raise DelegationError("parent_cross_tenant")
                if parent_row["revoked"]:
                    raise DelegationError("parent_revoked")
                if _parse_iso(parent_row["expires_at"]) <= issued_at_dt:
                    raise DelegationError("parent_expired")
                if parent_row["delegatee_id"] != delegator_id:
                    # Only the agent the parent receipt was issued TO can
                    # further delegate.
                    raise DelegationError("delegator_not_parent_delegatee")
                parent_scope: list[str] = json.loads(parent_row["scope_json"])
                if not _is_subset(parent_scope, scope):
                    raise DelegationError("scope_exceeds_parent")
                # Child cannot outlive the parent.
                if expires_at_dt > _parse_iso(parent_row["expires_at"]):
                    expires_at_dt = _parse_iso(parent_row["expires_at"])
                    expires_at = _iso(expires_at_dt)
                human_principal_id = parent_row["human_principal_id"]
                depth = int(parent_row["depth"]) + 1

            signature = _sign(_signing_payload(
                receipt_id=receipt_id,
                tenant_id=tenant_id,
                delegator_id=delegator_id,
                delegatee_id=delegatee_id,
                scope=scope,
                issued_at=issued_at,
                expires_at=expires_at,
                parent_receipt_id=parent_receipt_id,
            ))

            conn.execute(
                """
                INSERT INTO delegation_receipts
                    (receipt_id, tenant_id, delegator_id, delegatee_id,
                     scope_json, ceiling_json, issued_at, expires_at,
                     parent_receipt_id, human_principal_id, depth,
                     signature, revoked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    receipt_id, tenant_id, delegator_id, delegatee_id,
                    json.dumps(list(scope)),
                    json.dumps(dict(ceiling)) if ceiling else None,
                    issued_at, expires_at,
                    parent_receipt_id, human_principal_id, depth,
                    signature,
                ),
            )
            conn.commit()

            return DelegationReceipt(
                receipt_id=receipt_id,
                tenant_id=tenant_id,
                delegator_id=delegator_id,
                delegatee_id=delegatee_id,
                scope=list(scope),
                ceiling=dict(ceiling) if ceiling else None,
                issued_at=issued_at,
                expires_at=expires_at,
                parent_receipt_id=parent_receipt_id,
                human_principal_id=human_principal_id,
                depth=depth,
                signature=signature,
            )
        finally:
            conn.close()


# ── Verify ────────────────────────────────────────────────────────────────────

def verify_receipt(receipt_id: str, tenant_id: str | None = None) -> VerificationResult:
    """
    Re-derive the signature and check expiry/revocation. Does not walk the
    chain — call ``export_chain_report`` if you need per-hop verification.
    """
    if _use_pg():
        return VerificationResult(valid=False, reason="pg_not_implemented",
                                  receipt_id=receipt_id)
    with _lock:
        conn = _get_conn()
        try:
            row = _fetch_receipt(conn, receipt_id)
        finally:
            conn.close()
    if row is None:
        return VerificationResult(valid=False, reason="not_found", receipt_id=receipt_id)
    if tenant_id is not None and row["tenant_id"] != tenant_id:
        return VerificationResult(valid=False, reason="cross_tenant", receipt_id=receipt_id)

    expected = _sign(_signing_payload(
        receipt_id=row["receipt_id"],
        tenant_id=row["tenant_id"],
        delegator_id=row["delegator_id"],
        delegatee_id=row["delegatee_id"],
        scope=json.loads(row["scope_json"]),
        issued_at=row["issued_at"],
        expires_at=row["expires_at"],
        parent_receipt_id=row["parent_receipt_id"],
    ))
    if not hmac.compare_digest(expected, row["signature"]):
        return VerificationResult(valid=False, reason="signature_invalid",
                                  receipt_id=receipt_id)
    if row["revoked"]:
        return VerificationResult(valid=False, reason="revoked", receipt_id=receipt_id)
    if _parse_iso(row["expires_at"]) <= _now():
        return VerificationResult(valid=False, reason="expired", receipt_id=receipt_id)
    return VerificationResult(valid=True, reason="ok", receipt_id=receipt_id)


# ── Chain traversal ───────────────────────────────────────────────────────────

def get_chain(receipt_id: str, tenant_id: str | None = None) -> list[DelegationReceipt]:
    """
    Walk parent links from the leaf back to the root. Returns the chain in
    root → leaf order. Empty list if the leaf is unknown or cross-tenant.
    """
    if _use_pg():
        return []
    chain_rev: list[DelegationReceipt] = []
    seen: set[str] = set()
    with _lock:
        conn = _get_conn()
        try:
            current_id: str | None = receipt_id
            while current_id:
                if current_id in seen:
                    break  # defensive: should never happen with PK constraint
                seen.add(current_id)
                row = _fetch_receipt(conn, current_id)
                if row is None:
                    return []
                if tenant_id is not None and row["tenant_id"] != tenant_id:
                    return []
                chain_rev.append(_row_to_receipt(row))
                current_id = row["parent_receipt_id"]
        finally:
            conn.close()
    chain_rev.reverse()
    return chain_rev


def _descendant_ids(conn: sqlite3.Connection, root_id: str) -> list[str]:
    """All receipts that have ``root_id`` somewhere in their parent chain.
    Uses a recursive CTE — same idiom as trust_graph delegation depth."""
    rows = conn.execute(
        """
        WITH RECURSIVE descendants(receipt_id) AS (
            SELECT receipt_id FROM delegation_receipts WHERE parent_receipt_id = ?
            UNION ALL
            SELECT dr.receipt_id
            FROM delegation_receipts dr
            JOIN descendants d ON dr.parent_receipt_id = d.receipt_id
        )
        SELECT receipt_id FROM descendants
        """,
        (root_id,),
    ).fetchall()
    return [r["receipt_id"] for r in rows]


# ── Revoke ────────────────────────────────────────────────────────────────────

def revoke_receipt(
    receipt_id: str,
    revoked_by: str,
    cascade: bool = True,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """
    Mark a receipt revoked. If ``cascade`` (default), every receipt that has
    this receipt anywhere in its parent chain is revoked in the same
    transaction. Idempotent — already-revoked receipts keep their original
    ``revoked_at`` / ``revoked_by`` values.

    Returns ``{"revoked_ids": [...], "cascaded": bool}``. ``revoked_ids`` is
    the set of newly-revoked ids (not including those already revoked).
    """
    if _use_pg():
        return {"revoked_ids": [], "cascaded": cascade}
    now = _iso(_now())
    with _lock:
        conn = _get_conn()
        try:
            row = _fetch_receipt(conn, receipt_id)
            if row is None:
                raise DelegationError("not_found")
            if tenant_id is not None and row["tenant_id"] != tenant_id:
                raise DelegationError("cross_tenant")

            target_ids: list[str] = [receipt_id]
            if cascade:
                target_ids.extend(_descendant_ids(conn, receipt_id))

            newly_revoked: list[str] = []
            for tid in target_ids:
                cur = conn.execute(
                    """
                    UPDATE delegation_receipts
                    SET revoked = 1, revoked_at = ?, revoked_by = ?
                    WHERE receipt_id = ? AND revoked = 0
                    """,
                    (now, revoked_by, tid),
                )
                if cur.rowcount > 0:
                    newly_revoked.append(tid)
            conn.commit()
            return {"revoked_ids": newly_revoked, "cascaded": cascade}
        finally:
            conn.close()


# ── Receipts for an agent ─────────────────────────────────────────────────────

def get_receipts_for_agent(
    tenant_id: str,
    agent_id: str,
    include_revoked: bool = False,
) -> list[DelegationReceipt]:
    """All receipts where ``agent_id`` is the delegatee. Active by default
    (non-revoked, non-expired)."""
    if _use_pg():
        return []
    now_iso = _iso(_now())
    with _lock:
        conn = _get_conn()
        try:
            params: list[Any] = [tenant_id, agent_id]
            sql = (
                "SELECT * FROM delegation_receipts "
                "WHERE tenant_id=? AND delegatee_id=?"
            )
            if not include_revoked:
                sql += " AND revoked=0 AND expires_at > ?"
                params.append(now_iso)
            sql += " ORDER BY issued_at DESC"
            rows = conn.execute(sql, tuple(params)).fetchall()
            return [_row_to_receipt(r) for r in rows]
        finally:
            conn.close()


# ── Liability / chain report ──────────────────────────────────────────────────

def export_chain_report(receipt_id: str, tenant_id: str | None = None) -> dict[str, Any]:
    """
    Human-readable chain export designed for downstream PDF rendering.
    Each hop reports its delegator, delegatee, scope, timestamps, and a
    re-verified ``signature_valid`` flag. The chain is also rolled up into
    an ``overall_valid`` boolean: true iff every hop verifies, no hop is
    revoked, and no hop is expired.
    """
    chain = get_chain(receipt_id, tenant_id=tenant_id)
    if not chain:
        return {
            "receipt_id": receipt_id,
            "found": False,
            "overall_valid": False,
            "reason": "not_found_or_cross_tenant",
            "hops": [],
        }
    hops: list[dict[str, Any]] = []
    overall_valid = True
    overall_reason = "ok"
    for r in chain:
        v = verify_receipt(r.receipt_id, tenant_id=tenant_id)
        if not v.valid and overall_valid:
            overall_valid = False
            overall_reason = f"hop_{r.depth}:{v.reason}"
        hops.append({
            "depth": r.depth,
            "receipt_id": r.receipt_id,
            "delegator_id": r.delegator_id,
            "delegatee_id": r.delegatee_id,
            "scope": list(r.scope),
            "ceiling": dict(r.ceiling) if r.ceiling else None,
            "issued_at": r.issued_at,
            "expires_at": r.expires_at,
            "parent_receipt_id": r.parent_receipt_id,
            "signature": r.signature,
            "signature_valid": v.valid,
            "verification_reason": v.reason,
            "revoked": r.revoked,
            "revoked_at": r.revoked_at,
            "revoked_by": r.revoked_by,
        })
    leaf = chain[-1]
    return {
        "receipt_id": leaf.receipt_id,
        "found": True,
        "tenant_id": leaf.tenant_id,
        "human_principal_id": leaf.human_principal_id,
        "current_delegatee_id": leaf.delegatee_id,
        "depth": leaf.depth,
        "overall_valid": overall_valid,
        "overall_reason": overall_reason,
        "hops": hops,
        "exported_at": _iso(_now()),
    }
