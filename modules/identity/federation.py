"""
TokenDNA — Federated Agent Trust (FAT)

Closes the cross-organization agent attribution gap from RSA'26 — the "SAML
moment" for AI agents.  When an agent from Acme calls a resource at Beta Corp,
this module establishes which org's policy framework applies, who is liable,
and how trust is bootstrapped between two organizations' agent populations.

Design
──────

Two TokenDNA-using organizations bootstrap mutual trust via a *federation
handshake* — a signed exchange of:

  * org_id           — stable identifier of each side
  * federation_key   — public verification material (Ed25519 / HMAC-SHA256)
  * policy_summary   — minimum policy posture each side commits to
  * scope            — list of agent label patterns each side will accept
                       cross-org actions from
  * expires_at       — handshake validity window

The handshake produces a ``FederationTrust`` record stored in both orgs.
Subsequent cross-org agent actions reference the trust by ``trust_id``;
``policy_guard.CONST-06`` will BLOCK any cross-org action that does not
present a valid handshake.

Storage
───────
SQLite default; PG-compatible schema mirrors the SQLite one.  Two tables:

  federation_trusts        — established handshake records (mutual trust)
  federation_handshakes    — pending + historical handshake attempts

Audit events (defined in modules.security.audit_log):

  FEDERATION_HANDSHAKE_INITIATED   — local org started a handshake offer
  FEDERATION_HANDSHAKE_ACCEPTED    — remote org accepted, trust established
  FEDERATION_HANDSHAKE_REJECTED    — remote org rejected the offer
  FEDERATION_TRUST_REVOKED         — operator revoked an established trust
  CROSS_ORG_ACTION_BLOCKED         — policy_guard CONST-06 fired
  CROSS_ORG_ACTION_APPROVED        — operator approved a cross-org action

All federation actions go through ``_emit_audit`` for SOC 2 review.
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
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from modules.security.audit_log import AuditEventType, AuditOutcome, log_event
from modules.storage.pg_connection import AdaptedCursor, get_db_conn

log = logging.getLogger(__name__)

_lock = threading.Lock()


# ── Configuration ─────────────────────────────────────────────────────────────

# How long a handshake offer remains valid before the remote org must accept.
FEDERATION_HANDSHAKE_TTL_HOURS = int(os.getenv("FEDERATION_HANDSHAKE_TTL_H", "72"))

# Default trust validity window (operators can override per-handshake).
FEDERATION_TRUST_DEFAULT_DAYS = int(os.getenv("FEDERATION_TRUST_DEFAULT_DAYS", "90"))

# HMAC secret used to sign handshake material when no Ed25519 key is configured.
# In production this is set via env var; in tests we generate a per-process
# default so the signing path is exercised end-to-end.
_DEFAULT_HMAC = os.getenv("FEDERATION_HMAC_KEY") or secrets.token_hex(32)


# ── Domain types ──────────────────────────────────────────────────────────────


class HandshakeStatus(str, Enum):
    PENDING   = "pending"     # offer sent, awaiting remote acceptance
    ACCEPTED  = "accepted"    # mutual trust established
    REJECTED  = "rejected"    # remote declined
    EXPIRED   = "expired"     # TTL passed without acceptance
    REVOKED   = "revoked"     # operator revoked after acceptance


class TrustStatus(str, Enum):
    ACTIVE   = "active"
    REVOKED  = "revoked"
    EXPIRED  = "expired"


@dataclass
class FederationOffer:
    """An offer from local org → remote org to establish federation."""
    handshake_id:    str
    local_org_id:    str
    remote_org_id:   str
    federation_key:  str       # public verification material (hex)
    policy_summary:  dict[str, Any]
    accepted_scope:  list[str]  # agent label patterns
    initiated_at:    str
    expires_at:      str
    signature:       str       # HMAC over canonical offer
    status:          str = HandshakeStatus.PENDING.value
    metadata:        dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "handshake_id":    self.handshake_id,
            "local_org_id":    self.local_org_id,
            "remote_org_id":   self.remote_org_id,
            "federation_key":  self.federation_key,
            "policy_summary":  self.policy_summary,
            "accepted_scope":  self.accepted_scope,
            "initiated_at":    self.initiated_at,
            "expires_at":      self.expires_at,
            "signature":       self.signature,
            "status":          self.status,
            "metadata":        self.metadata,
        }


@dataclass
class FederationTrust:
    """An established mutual trust between two TokenDNA-using orgs."""
    trust_id:         str
    local_org_id:     str
    remote_org_id:    str
    local_federation_key:   str
    remote_federation_key:  str
    accepted_scope:   list[str]   # agent label patterns either side may act for
    established_at:   str
    expires_at:       str
    status:           str = TrustStatus.ACTIVE.value
    revoked_at:       str | None = None
    revoked_by:       str | None = None
    revoked_reason:   str | None = None
    metadata:         dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "trust_id":               self.trust_id,
            "local_org_id":           self.local_org_id,
            "remote_org_id":          self.remote_org_id,
            "local_federation_key":   self.local_federation_key,
            "remote_federation_key":  self.remote_federation_key,
            "accepted_scope":         self.accepted_scope,
            "established_at":         self.established_at,
            "expires_at":             self.expires_at,
            "status":                 self.status,
            "revoked_at":             self.revoked_at,
            "revoked_by":             self.revoked_by,
            "revoked_reason":         self.revoked_reason,
            "metadata":               self.metadata,
        }

    def is_active_for(self, agent_label: str, now: datetime | None = None) -> bool:
        """True if this trust covers the given agent label and has not expired."""
        if self.status != TrustStatus.ACTIVE.value:
            return False
        ts = (now or datetime.now(timezone.utc)).isoformat()
        if ts > self.expires_at:
            return False
        return _matches_scope(agent_label, self.accepted_scope)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def _cursor():
    """Yield a backend-portable AdaptedCursor (SQLite or Postgres)."""
    with _lock:
        with get_db_conn(db_path=_db_path()) as conn:
            yield AdaptedCursor(conn.cursor())


def _matches_scope(agent_label: str, scope_patterns: list[str]) -> bool:
    """
    Trivial glob-style match against the accepted_scope patterns.  Patterns
    end with ``*`` for prefix-match or are equality-matched otherwise.  An
    empty scope list matches nothing (security default — explicit allow only).
    """
    if not scope_patterns:
        return False
    for pat in scope_patterns:
        if pat.endswith("*"):
            if agent_label.startswith(pat[:-1]):
                return True
        elif agent_label == pat:
            return True
    return False


def _canonical_offer(
    *,
    local_org_id: str,
    remote_org_id: str,
    federation_key: str,
    policy_summary: dict[str, Any],
    accepted_scope: list[str],
    initiated_at: str,
    expires_at: str,
) -> bytes:
    """Deterministic JSON for HMAC signing — sorted keys, compact separators."""
    payload = {
        "local_org_id":   local_org_id,
        "remote_org_id":  remote_org_id,
        "federation_key": federation_key,
        "policy_summary": policy_summary,
        "accepted_scope": sorted(accepted_scope),
        "initiated_at":   initiated_at,
        "expires_at":     expires_at,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _sign(canonical_bytes: bytes) -> str:
    return hmac.new(
        _DEFAULT_HMAC.encode(),
        canonical_bytes,
        hashlib.sha256,
    ).hexdigest()


def _emit_audit(
    event_type: AuditEventType,
    outcome: AuditOutcome,
    *,
    tenant_id: str,
    subject: str,
    resource: str,
    detail: dict[str, Any],
) -> None:
    """Best-effort audit emission — never block the caller on logging failure."""
    try:
        log_event(
            event_type,
            outcome,
            tenant_id=tenant_id,
            subject=subject,
            resource=resource,
            detail=detail,
        )
    except Exception:
        log.exception("audit log emit failed for %s", event_type)


# ── Schema ────────────────────────────────────────────────────────────────────


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS federation_handshakes (
    handshake_id     TEXT PRIMARY KEY,
    local_org_id     TEXT NOT NULL,
    remote_org_id    TEXT NOT NULL,
    federation_key   TEXT NOT NULL,
    policy_summary   TEXT NOT NULL DEFAULT '{}',
    accepted_scope   TEXT NOT NULL DEFAULT '[]',
    initiated_at     TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    signature        TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending',
    metadata         TEXT NOT NULL DEFAULT '{}',
    accepted_at      TEXT,
    accepted_by      TEXT,
    rejected_at      TEXT,
    rejected_reason  TEXT
);

CREATE INDEX IF NOT EXISTS idx_fed_handshakes_local_remote
    ON federation_handshakes(local_org_id, remote_org_id, status);

CREATE TABLE IF NOT EXISTS federation_trusts (
    trust_id              TEXT PRIMARY KEY,
    local_org_id          TEXT NOT NULL,
    remote_org_id         TEXT NOT NULL,
    local_federation_key  TEXT NOT NULL,
    remote_federation_key TEXT NOT NULL,
    accepted_scope        TEXT NOT NULL DEFAULT '[]',
    established_at        TEXT NOT NULL,
    expires_at            TEXT NOT NULL,
    status                TEXT NOT NULL DEFAULT 'active',
    revoked_at            TEXT,
    revoked_by            TEXT,
    revoked_reason        TEXT,
    metadata              TEXT NOT NULL DEFAULT '{}',
    UNIQUE(local_org_id, remote_org_id)
);

CREATE INDEX IF NOT EXISTS idx_fed_trusts_status
    ON federation_trusts(status);
"""


def init_db() -> None:
    """Create FAT schema tables.  Idempotent."""
    with _cursor() as cur:
        for stmt in [s for s in _SCHEMA_SQL.split(";") if s.strip()]:
            cur.execute(stmt)


# ── Public API ────────────────────────────────────────────────────────────────


def initiate_handshake(
    *,
    local_org_id: str,
    remote_org_id: str,
    accepted_scope: list[str],
    policy_summary: dict[str, Any] | None = None,
    ttl_hours: int | None = None,
) -> FederationOffer:
    """
    Local org offers federation to a remote org.  Returns a signed
    ``FederationOffer`` that the remote org can verify and accept.

    The offer is persisted as a PENDING handshake.  Acceptance via
    ``accept_handshake`` produces a ``FederationTrust`` record on both sides.
    """
    if not local_org_id or not remote_org_id:
        raise ValueError("local_org_id and remote_org_id are required")
    if local_org_id == remote_org_id:
        raise ValueError("federation requires two distinct orgs")
    if not accepted_scope:
        raise ValueError("accepted_scope must specify at least one agent pattern")

    init_db()

    handshake_id = str(uuid.uuid4())
    initiated_at = _iso_now()
    expires = datetime.now(timezone.utc) + timedelta(
        hours=ttl_hours or FEDERATION_HANDSHAKE_TTL_HOURS
    )
    expires_at = expires.isoformat()
    federation_key = secrets.token_hex(32)
    summary = policy_summary or {}

    canonical = _canonical_offer(
        local_org_id=local_org_id,
        remote_org_id=remote_org_id,
        federation_key=federation_key,
        policy_summary=summary,
        accepted_scope=accepted_scope,
        initiated_at=initiated_at,
        expires_at=expires_at,
    )
    signature = _sign(canonical)

    with _cursor() as cur:
        cur.execute(
            """
            INSERT INTO federation_handshakes
                (handshake_id, local_org_id, remote_org_id, federation_key,
                 policy_summary, accepted_scope, initiated_at, expires_at,
                 signature, status, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', '{}')
            """,
            (
                handshake_id, local_org_id, remote_org_id, federation_key,
                json.dumps(summary), json.dumps(accepted_scope),
                initiated_at, expires_at, signature,
            ),
        )

    offer = FederationOffer(
        handshake_id=handshake_id,
        local_org_id=local_org_id,
        remote_org_id=remote_org_id,
        federation_key=federation_key,
        policy_summary=summary,
        accepted_scope=accepted_scope,
        initiated_at=initiated_at,
        expires_at=expires_at,
        signature=signature,
        status=HandshakeStatus.PENDING.value,
    )

    _emit_audit(
        AuditEventType.FEDERATION_HANDSHAKE_INITIATED,
        AuditOutcome.SUCCESS,
        tenant_id=local_org_id,
        subject="federation",
        resource=remote_org_id,
        detail={
            "handshake_id": handshake_id,
            "expires_at": expires_at,
            "scope_size": len(accepted_scope),
        },
    )
    return offer


def verify_offer_signature(offer: FederationOffer) -> bool:
    """Recompute the canonical signature and compare."""
    canonical = _canonical_offer(
        local_org_id=offer.local_org_id,
        remote_org_id=offer.remote_org_id,
        federation_key=offer.federation_key,
        policy_summary=offer.policy_summary,
        accepted_scope=offer.accepted_scope,
        initiated_at=offer.initiated_at,
        expires_at=offer.expires_at,
    )
    expected = _sign(canonical)
    return hmac.compare_digest(expected, offer.signature)


def accept_handshake(
    *,
    handshake_id: str,
    accepting_org_id: str,
    remote_federation_key: str,
    accepted_by: str,
) -> FederationTrust:
    """
    Remote org accepts a pending offer.  Establishes a ``FederationTrust``
    on the remote side.  The originating org must call
    ``record_remote_acceptance`` to persist the trust on its own side.
    """
    init_db()
    offer = get_handshake(handshake_id)
    if offer is None:
        raise ValueError(f"handshake {handshake_id} not found")
    if offer.status != HandshakeStatus.PENDING.value:
        raise ValueError(
            f"handshake {handshake_id} is not pending (status={offer.status})"
        )
    if accepting_org_id != offer.remote_org_id:
        raise ValueError(
            f"only remote_org_id={offer.remote_org_id} may accept this offer"
        )
    if _iso_now() > offer.expires_at:
        _mark_handshake_expired(handshake_id)
        raise ValueError(f"handshake {handshake_id} has expired")
    if not verify_offer_signature(offer):
        raise ValueError(f"handshake {handshake_id} signature does not verify")

    now = _iso_now()
    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(days=FEDERATION_TRUST_DEFAULT_DAYS)
    ).isoformat()

    trust_id = str(uuid.uuid4())
    with _cursor() as cur:
        cur.execute(
            """
            UPDATE federation_handshakes
            SET status='accepted', accepted_at=?, accepted_by=?
            WHERE handshake_id=?
            """,
            (now, accepted_by, handshake_id),
        )
        cur.execute(
            """
            INSERT INTO federation_trusts
                (trust_id, local_org_id, remote_org_id,
                 local_federation_key, remote_federation_key,
                 accepted_scope, established_at, expires_at,
                 status, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', '{}')
            """,
            (
                trust_id, accepting_org_id, offer.local_org_id,
                remote_federation_key, offer.federation_key,
                json.dumps(offer.accepted_scope), now, expires_at,
            ),
        )

    trust = FederationTrust(
        trust_id=trust_id,
        local_org_id=accepting_org_id,
        remote_org_id=offer.local_org_id,
        local_federation_key=remote_federation_key,
        remote_federation_key=offer.federation_key,
        accepted_scope=offer.accepted_scope,
        established_at=now,
        expires_at=expires_at,
    )

    _emit_audit(
        AuditEventType.FEDERATION_HANDSHAKE_ACCEPTED,
        AuditOutcome.SUCCESS,
        tenant_id=accepting_org_id,
        subject=accepted_by,
        resource=offer.local_org_id,
        detail={
            "handshake_id": handshake_id,
            "trust_id": trust_id,
            "expires_at": expires_at,
        },
    )
    _emit_audit(
        AuditEventType.FEDERATION_TRUST_ESTABLISHED,
        AuditOutcome.SUCCESS,
        tenant_id=accepting_org_id,
        subject="federation",
        resource=offer.local_org_id,
        detail={
            "trust_id": trust_id,
            "scope_size": len(offer.accepted_scope),
        },
    )
    return trust


def reject_handshake(
    *,
    handshake_id: str,
    rejecting_org_id: str,
    reason: str = "",
) -> None:
    """Remote org declines a pending offer."""
    init_db()
    offer = get_handshake(handshake_id)
    if offer is None:
        raise ValueError(f"handshake {handshake_id} not found")
    if offer.status != HandshakeStatus.PENDING.value:
        raise ValueError(
            f"handshake {handshake_id} is not pending (status={offer.status})"
        )
    if rejecting_org_id != offer.remote_org_id:
        raise ValueError(
            f"only remote_org_id={offer.remote_org_id} may reject this offer"
        )

    now = _iso_now()
    with _cursor() as cur:
        cur.execute(
            """
            UPDATE federation_handshakes
            SET status='rejected', rejected_at=?, rejected_reason=?
            WHERE handshake_id=?
            """,
            (now, reason, handshake_id),
        )
    _emit_audit(
        AuditEventType.FEDERATION_HANDSHAKE_REJECTED,
        AuditOutcome.FAILURE,
        tenant_id=rejecting_org_id,
        subject="federation",
        resource=offer.local_org_id,
        detail={"handshake_id": handshake_id, "reason": reason},
    )


def revoke_trust(
    *,
    trust_id: str,
    local_org_id: str,
    revoked_by: str,
    reason: str = "",
) -> FederationTrust | None:
    """Operator-initiated revocation of an established trust."""
    init_db()
    now = _iso_now()
    with _cursor() as cur:
        cur.execute(
            """
            UPDATE federation_trusts
            SET status='revoked', revoked_at=?, revoked_by=?, revoked_reason=?
            WHERE trust_id=? AND local_org_id=? AND status='active'
            """,
            (now, revoked_by, reason, trust_id, local_org_id),
        )
        if cur.rowcount == 0:
            return None
    trust = get_trust(trust_id)
    _emit_audit(
        AuditEventType.FEDERATION_TRUST_REVOKED,
        AuditOutcome.SUCCESS,
        tenant_id=local_org_id,
        subject=revoked_by,
        resource=trust.remote_org_id if trust else "?",
        detail={"trust_id": trust_id, "reason": reason},
    )
    return trust


def find_active_trust(
    *,
    local_org_id: str,
    remote_org_id: str,
    agent_label: str,
) -> FederationTrust | None:
    """
    Look up an active mutual trust covering ``agent_label`` between the two
    orgs.  Used by ``policy_guard`` to decide whether a cross-org action has
    a valid handshake backing it.  Returns None if no trust exists, the
    trust is revoked, the trust has expired, or the agent label is outside
    the accepted scope.
    """
    init_db()
    with _cursor() as cur:
        cur.execute(
            """
            SELECT * FROM federation_trusts
            WHERE local_org_id=? AND remote_org_id=? AND status='active'
            ORDER BY established_at DESC LIMIT 1
            """,
            (local_org_id, remote_org_id),
        )
        row = cur.fetchone()
    if not row:
        return None
    trust = _row_to_trust(row)
    if not trust.is_active_for(agent_label):
        return None
    return trust


def list_trusts(
    *,
    local_org_id: str,
    status: str | None = None,
    limit: int = 100,
) -> list[FederationTrust]:
    init_db()
    clauses = ["local_org_id = ?"]
    params: list[Any] = [local_org_id]
    if status:
        clauses.append("status = ?")
        params.append(status)
    where = " AND ".join(clauses)
    params.append(min(limit, 500))
    with _cursor() as cur:
        cur.execute(
            f"SELECT * FROM federation_trusts WHERE {where} "
            f"ORDER BY established_at DESC LIMIT ?",
            params,
        )
        rows = cur.fetchall()
    return [_row_to_trust(r) for r in rows]


def get_trust(trust_id: str) -> FederationTrust | None:
    init_db()
    with _cursor() as cur:
        cur.execute(
            "SELECT * FROM federation_trusts WHERE trust_id=?",
            (trust_id,),
        )
        row = cur.fetchone()
    return _row_to_trust(row) if row else None


def get_handshake(handshake_id: str) -> FederationOffer | None:
    init_db()
    with _cursor() as cur:
        cur.execute(
            "SELECT * FROM federation_handshakes WHERE handshake_id=?",
            (handshake_id,),
        )
        row = cur.fetchone()
    return _row_to_offer(row) if row else None


def list_handshakes(
    *,
    local_org_id: str | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[FederationOffer]:
    init_db()
    clauses: list[str] = []
    params: list[Any] = []
    if local_org_id:
        clauses.append("local_org_id = ?")
        params.append(local_org_id)
    if status:
        clauses.append("status = ?")
        params.append(status)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(min(limit, 500))
    with _cursor() as cur:
        cur.execute(
            f"SELECT * FROM federation_handshakes{where} "
            f"ORDER BY initiated_at DESC LIMIT ?",
            params,
        )
        rows = cur.fetchall()
    return [_row_to_offer(r) for r in rows]


# ── Internal helpers ──────────────────────────────────────────────────────────


def _mark_handshake_expired(handshake_id: str) -> None:
    with _cursor() as cur:
        cur.execute(
            """
            UPDATE federation_handshakes
            SET status='expired'
            WHERE handshake_id=? AND status='pending'
            """,
            (handshake_id,),
        )


def _row_to_offer(row: Any) -> FederationOffer:
    return FederationOffer(
        handshake_id=row["handshake_id"],
        local_org_id=row["local_org_id"],
        remote_org_id=row["remote_org_id"],
        federation_key=row["federation_key"],
        policy_summary=json.loads(row["policy_summary"] or "{}"),
        accepted_scope=json.loads(row["accepted_scope"] or "[]"),
        initiated_at=row["initiated_at"],
        expires_at=row["expires_at"],
        signature=row["signature"],
        status=row["status"],
        metadata=json.loads(row["metadata"] or "{}"),
    )


def _row_to_trust(row: Any) -> FederationTrust:
    return FederationTrust(
        trust_id=row["trust_id"],
        local_org_id=row["local_org_id"],
        remote_org_id=row["remote_org_id"],
        local_federation_key=row["local_federation_key"],
        remote_federation_key=row["remote_federation_key"],
        accepted_scope=json.loads(row["accepted_scope"] or "[]"),
        established_at=row["established_at"],
        expires_at=row["expires_at"],
        status=row["status"],
        revoked_at=row["revoked_at"],
        revoked_by=row["revoked_by"],
        revoked_reason=row["revoked_reason"],
        metadata=json.loads(row["metadata"] or "{}"),
    )
