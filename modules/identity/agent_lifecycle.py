"""
TokenDNA — Ghost Agent Offboarding Enforcement (Sprint 5-3)

Closes RSA'26 Gap 3: "1/3 of enterprise agents run on third-party platforms.
Pilots end but agents keep running. Only 21% of orgs maintain real-time agent
inventory. Decommissioned agents hold live credentials indefinitely."

This module provides complete agent lifecycle management:

  1. Agent inventory
     Centralised registry of every agent in the tenant. Includes platform,
     owner, last-seen timestamp, and current lifecycle state.

  2. Lifecycle state machine
     States: active → suspended → decommissioned
     Transitions are gated and logged. Decommissioned is terminal.

  3. Automatic credential revocation
     On decommission, any registered credentials (federation verifiers keyed
     to the agent) are revoked via trust_federation.revoke_verifier().

  4. Orphan detection
     Agents with no activity in >30 days are flagged as orphaned.  A separate
     query surfaces orphans to operators so they can decide whether to suspend
     or decommission.

  5. Deception-mesh integration
     On decommission, the agent's last-known token/credential identifier is
     forwarded to the deception-mesh decoy table so the credential now acts
     as a honeypot — any usage after decommission is an active-threat signal.

API surface (wired in api.py)
────────────────────────────
POST /api/agents/register              Register a new agent in inventory
POST /api/agents/decommission/{id}     Decommission + auto-revoke credentials
POST /api/agents/suspend/{id}          Suspend (reversible)
POST /api/agents/reactivate/{id}       Reactivate a suspended agent
POST /api/agents/heartbeat/{id}        Record agent activity (updates last_seen)
GET  /api/agents/inventory             Full tenant inventory with lifecycle state
GET  /api/agents/orphans               Agents with no activity in >30 days
GET  /api/agents/{id}                  Single agent record
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

log = logging.getLogger(__name__)

_lock = threading.Lock()

# ── constants ─────────────────────────────────────────────────────────────────

ORPHAN_DAYS = int(os.getenv("AGENT_ORPHAN_DAYS", "30"))

VALID_STATES = {"active", "suspended", "decommissioned"}

# Allowed state transitions: current → set of next states
_TRANSITIONS: dict[str, set[str]] = {
    "active": {"suspended", "decommissioned"},
    "suspended": {"active", "decommissioned"},
    "decommissioned": set(),  # terminal
}


# ── DB helpers ────────────────────────────────────────────────────────────────

def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


# ── schema ────────────────────────────────────────────────────────────────────

def init_db() -> None:
    """Create lifecycle tables if they don't exist."""
    db_path = _db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    with _cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_inventory (
                agent_id           TEXT NOT NULL,
                tenant_id          TEXT NOT NULL,
                display_name       TEXT NOT NULL,
                platform           TEXT NOT NULL DEFAULT 'unknown',
                owner              TEXT,
                credential_ids     TEXT NOT NULL DEFAULT '[]',
                last_token_id      TEXT,
                status             TEXT NOT NULL DEFAULT 'active',
                last_seen_at       TEXT,
                suspended_at       TEXT,
                suspended_by       TEXT,
                decommissioned_at  TEXT,
                decommissioned_by  TEXT,
                decommission_reason TEXT,
                metadata_json      TEXT NOT NULL DEFAULT '{}',
                created_at         TEXT NOT NULL,
                updated_at         TEXT NOT NULL,
                PRIMARY KEY (agent_id, tenant_id)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_lifecycle_events (
                event_id      TEXT PRIMARY KEY,
                agent_id      TEXT NOT NULL,
                tenant_id     TEXT NOT NULL,
                event_type    TEXT NOT NULL,
                from_state    TEXT,
                to_state      TEXT,
                actor         TEXT,
                reason        TEXT,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at    TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS deception_mesh_decoys (
                decoy_id      TEXT PRIMARY KEY,
                agent_id      TEXT NOT NULL,
                tenant_id     TEXT NOT NULL,
                token_id      TEXT NOT NULL,
                source        TEXT NOT NULL DEFAULT 'ghost_agent',
                activated_at  TEXT NOT NULL,
                hits          INTEGER NOT NULL DEFAULT 0,
                last_hit_at   TEXT
            )
            """
        )
        # Indexes
        for idx_sql in [
            "CREATE INDEX IF NOT EXISTS idx_agent_inv_tenant ON agent_inventory(tenant_id)",
            "CREATE INDEX IF NOT EXISTS idx_agent_inv_status ON agent_inventory(tenant_id, status)",
            "CREATE INDEX IF NOT EXISTS idx_agent_inv_last_seen ON agent_inventory(last_seen_at)",
            "CREATE INDEX IF NOT EXISTS idx_lifecycle_events_agent ON agent_lifecycle_events(agent_id, tenant_id)",
            "CREATE INDEX IF NOT EXISTS idx_decoy_tenant ON deception_mesh_decoys(tenant_id)",
        ]:
            cur.execute(idx_sql)


# ── helpers ───────────────────────────────────────────────────────────────────

def _row_to_agent(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "agent_id": row["agent_id"],
        "tenant_id": row["tenant_id"],
        "display_name": row["display_name"],
        "platform": row["platform"],
        "owner": row["owner"],
        "credential_ids": json.loads(row["credential_ids"] or "[]"),
        "last_token_id": row["last_token_id"],
        "status": row["status"],
        "last_seen_at": row["last_seen_at"],
        "suspended_at": row["suspended_at"],
        "suspended_by": row["suspended_by"],
        "decommissioned_at": row["decommissioned_at"],
        "decommissioned_by": row["decommissioned_by"],
        "decommission_reason": row["decommission_reason"],
        "metadata": json.loads(row["metadata_json"] or "{}"),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _log_event(
    cur: sqlite3.Cursor,
    *,
    agent_id: str,
    tenant_id: str,
    event_type: str,
    from_state: str | None = None,
    to_state: str | None = None,
    actor: str | None = None,
    reason: str | None = None,
    metadata: dict | None = None,
) -> str:
    event_id = str(uuid.uuid4())
    cur.execute(
        """
        INSERT INTO agent_lifecycle_events
            (event_id, agent_id, tenant_id, event_type, from_state, to_state,
             actor, reason, metadata_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            agent_id,
            tenant_id,
            event_type,
            from_state,
            to_state,
            actor,
            reason,
            json.dumps(metadata or {}),
            _iso_now(),
        ),
    )
    return event_id


# ── public API ────────────────────────────────────────────────────────────────

def register_agent(
    *,
    tenant_id: str,
    agent_id: str | None = None,
    display_name: str,
    platform: str = "unknown",
    owner: str | None = None,
    credential_ids: list[str] | None = None,
    last_token_id: str | None = None,
    metadata: dict | None = None,
) -> dict[str, Any]:
    """
    Register a new agent in the inventory.

    Returns the created agent record.  Raises ValueError if agent_id already
    exists for this tenant.
    """
    agent_id = agent_id or str(uuid.uuid4())
    now = _iso_now()
    with _cursor() as cur:
        existing = cur.execute(
            "SELECT agent_id FROM agent_inventory WHERE agent_id = ? AND tenant_id = ?",
            (agent_id, tenant_id),
        ).fetchone()
        if existing:
            raise ValueError(f"Agent '{agent_id}' already registered for tenant '{tenant_id}'")
        cur.execute(
            """
            INSERT INTO agent_inventory
                (agent_id, tenant_id, display_name, platform, owner,
                 credential_ids, last_token_id, status,
                 last_seen_at, metadata_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)
            """,
            (
                agent_id,
                tenant_id,
                display_name,
                platform,
                owner,
                json.dumps(credential_ids or []),
                last_token_id,
                now,
                json.dumps(metadata or {}),
                now,
                now,
            ),
        )
        _log_event(
            cur,
            agent_id=agent_id,
            tenant_id=tenant_id,
            event_type="registered",
            to_state="active",
            actor=owner,
            reason="initial registration",
        )
    return get_agent(tenant_id=tenant_id, agent_id=agent_id)


def get_agent(*, tenant_id: str, agent_id: str) -> dict[str, Any]:
    """Return a single agent record or raise KeyError if not found."""
    with _cursor() as cur:
        row = cur.execute(
            "SELECT * FROM agent_inventory WHERE agent_id = ? AND tenant_id = ?",
            (agent_id, tenant_id),
        ).fetchone()
    if not row:
        raise KeyError(f"Agent '{agent_id}' not found for tenant '{tenant_id}'")
    return _row_to_agent(row)


def record_heartbeat(*, tenant_id: str, agent_id: str) -> dict[str, Any]:
    """
    Record that an agent is alive (updates last_seen_at).

    Raises KeyError if agent not found.
    Raises ValueError if agent is decommissioned.
    """
    agent = get_agent(tenant_id=tenant_id, agent_id=agent_id)
    if agent["status"] == "decommissioned":
        raise ValueError(
            f"Agent '{agent_id}' is decommissioned — heartbeats are not accepted"
        )
    now = _iso_now()
    with _cursor() as cur:
        cur.execute(
            "UPDATE agent_inventory SET last_seen_at = ?, updated_at = ? WHERE agent_id = ? AND tenant_id = ?",
            (now, now, agent_id, tenant_id),
        )
    return get_agent(tenant_id=tenant_id, agent_id=agent_id)


def suspend_agent(
    *,
    tenant_id: str,
    agent_id: str,
    actor: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    """
    Suspend an active agent (reversible).

    Raises ValueError on invalid transition.
    """
    agent = get_agent(tenant_id=tenant_id, agent_id=agent_id)
    if "suspended" not in _TRANSITIONS.get(agent["status"], set()):
        raise ValueError(
            f"Cannot suspend agent in state '{agent['status']}'"
        )
    now = _iso_now()
    with _cursor() as cur:
        cur.execute(
            """
            UPDATE agent_inventory
            SET status = 'suspended',
                suspended_at = ?,
                suspended_by = ?,
                updated_at = ?
            WHERE agent_id = ? AND tenant_id = ?
            """,
            (now, actor, now, agent_id, tenant_id),
        )
        _log_event(
            cur,
            agent_id=agent_id,
            tenant_id=tenant_id,
            event_type="suspended",
            from_state=agent["status"],
            to_state="suspended",
            actor=actor,
            reason=reason,
        )
    log.info("Agent %s suspended by %s", agent_id, actor)
    return get_agent(tenant_id=tenant_id, agent_id=agent_id)


def reactivate_agent(
    *,
    tenant_id: str,
    agent_id: str,
    actor: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    """
    Reactivate a suspended agent.

    Raises ValueError on invalid transition.
    """
    agent = get_agent(tenant_id=tenant_id, agent_id=agent_id)
    if "active" not in _TRANSITIONS.get(agent["status"], set()):
        raise ValueError(
            f"Cannot reactivate agent in state '{agent['status']}'"
        )
    now = _iso_now()
    with _cursor() as cur:
        cur.execute(
            """
            UPDATE agent_inventory
            SET status = 'active',
                suspended_at = NULL,
                suspended_by = NULL,
                updated_at = ?
            WHERE agent_id = ? AND tenant_id = ?
            """,
            (now, agent_id, tenant_id),
        )
        _log_event(
            cur,
            agent_id=agent_id,
            tenant_id=tenant_id,
            event_type="reactivated",
            from_state=agent["status"],
            to_state="active",
            actor=actor,
            reason=reason,
        )
    return get_agent(tenant_id=tenant_id, agent_id=agent_id)


def decommission_agent(
    *,
    tenant_id: str,
    agent_id: str,
    actor: str | None = None,
    reason: str | None = None,
    revoke_credentials: bool = True,
) -> dict[str, Any]:
    """
    Decommission an agent (terminal — cannot be undone).

    Side effects:
      - Credential revocation: every credential_id registered to the agent is
        revoked via trust_federation.revoke_verifier() when revoke_credentials=True.
      - Deception mesh: the agent's last_token_id (if any) is converted to a
        honeypot decoy in the deception_mesh_decoys table.

    Raises ValueError on invalid transition.
    """
    agent = get_agent(tenant_id=tenant_id, agent_id=agent_id)
    if "decommissioned" not in _TRANSITIONS.get(agent["status"], set()):
        raise ValueError(
            f"Cannot decommission agent in state '{agent['status']}'"
        )

    now = _iso_now()
    revoked: list[str] = []
    revoke_errors: list[str] = []

    # 1. Credential revocation
    if revoke_credentials:
        cred_ids: list[str] = agent.get("credential_ids") or []
        for cred_id in cred_ids:
            try:
                from modules.identity import trust_federation as _tf  # noqa: PLC0415
                _tf.revoke_verifier(
                    verifier_id=cred_id,
                    tenant_id=tenant_id,
                    reason=f"agent decommissioned: {reason or 'no reason given'}",
                )
                revoked.append(cred_id)
                log.info("Revoked credential %s for decommissioned agent %s", cred_id, agent_id)
            except Exception as exc:  # noqa: BLE001
                revoke_errors.append(f"{cred_id}: {exc}")
                log.warning("Failed to revoke credential %s: %s", cred_id, exc)

    # 2. Persist decommission state
    with _cursor() as cur:
        cur.execute(
            """
            UPDATE agent_inventory
            SET status = 'decommissioned',
                decommissioned_at = ?,
                decommissioned_by = ?,
                decommission_reason = ?,
                updated_at = ?
            WHERE agent_id = ? AND tenant_id = ?
            """,
            (now, actor, reason, now, agent_id, tenant_id),
        )
        _log_event(
            cur,
            agent_id=agent_id,
            tenant_id=tenant_id,
            event_type="decommissioned",
            from_state=agent["status"],
            to_state="decommissioned",
            actor=actor,
            reason=reason,
            metadata={
                "credentials_revoked": revoked,
                "revoke_errors": revoke_errors,
            },
        )

        # 3. Deception mesh — convert last_token_id to honeypot decoy
        token_id = agent.get("last_token_id")
        if token_id:
            decoy_id = str(uuid.uuid4())
            cur.execute(
                """
                INSERT INTO deception_mesh_decoys
                    (decoy_id, agent_id, tenant_id, token_id, source, activated_at)
                VALUES (?, ?, ?, ?, 'ghost_agent', ?)
                """,
                (decoy_id, agent_id, tenant_id, token_id, now),
            )
            log.info(
                "Deception mesh: token %s for agent %s converted to decoy %s",
                token_id,
                agent_id,
                decoy_id,
            )

    result = get_agent(tenant_id=tenant_id, agent_id=agent_id)
    result["credentials_revoked"] = revoked
    result["revoke_errors"] = revoke_errors
    return result


def list_inventory(
    *,
    tenant_id: str,
    status: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """
    Return agent inventory for a tenant.

    Optionally filter by lifecycle status.
    """
    if status and status not in VALID_STATES:
        raise ValueError(f"Invalid status '{status}'. Must be one of: {sorted(VALID_STATES)}")
    limit = min(max(limit, 1), 1000)
    with _cursor() as cur:
        if status:
            rows = cur.execute(
                """
                SELECT * FROM agent_inventory
                WHERE tenant_id = ? AND status = ?
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (tenant_id, status, limit),
            ).fetchall()
        else:
            rows = cur.execute(
                """
                SELECT * FROM agent_inventory
                WHERE tenant_id = ?
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
    return [_row_to_agent(r) for r in rows]


def list_orphans(
    *,
    tenant_id: str,
    orphan_days: int = ORPHAN_DAYS,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """
    Return agents that have not been seen in >orphan_days days.

    Only non-decommissioned agents are returned — already-decommissioned
    agents are handled separately.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=orphan_days)).isoformat()
    limit = min(max(limit, 1), 1000)
    with _cursor() as cur:
        rows = cur.execute(
            """
            SELECT * FROM agent_inventory
            WHERE tenant_id = ?
              AND status != 'decommissioned'
              AND (last_seen_at IS NULL OR last_seen_at < ?)
            ORDER BY last_seen_at ASC
            LIMIT ?
            """,
            (tenant_id, cutoff, limit),
        ).fetchall()
    agents = [_row_to_agent(r) for r in rows]
    # Annotate with days_inactive
    for agent in agents:
        if agent["last_seen_at"]:
            last = datetime.fromisoformat(agent["last_seen_at"])
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            delta = datetime.now(timezone.utc) - last
            agent["days_inactive"] = delta.days
        else:
            agent["days_inactive"] = None
    return agents


def get_lifecycle_events(
    *,
    tenant_id: str,
    agent_id: str,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Return the full lifecycle event log for an agent."""
    with _cursor() as cur:
        rows = cur.execute(
            """
            SELECT * FROM agent_lifecycle_events
            WHERE agent_id = ? AND tenant_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (agent_id, tenant_id, min(max(limit, 1), 500)),
        ).fetchall()
    return [
        {
            "event_id": r["event_id"],
            "agent_id": r["agent_id"],
            "tenant_id": r["tenant_id"],
            "event_type": r["event_type"],
            "from_state": r["from_state"],
            "to_state": r["to_state"],
            "actor": r["actor"],
            "reason": r["reason"],
            "metadata": json.loads(r["metadata_json"] or "{}"),
            "created_at": r["created_at"],
        }
        for r in rows
    ]


def get_decoys(*, tenant_id: str, limit: int = 200) -> list[dict[str, Any]]:
    """Return active deception-mesh decoys for this tenant."""
    with _cursor() as cur:
        rows = cur.execute(
            """
            SELECT * FROM deception_mesh_decoys
            WHERE tenant_id = ?
            ORDER BY activated_at DESC
            LIMIT ?
            """,
            (tenant_id, min(max(limit, 1), 1000)),
        ).fetchall()
    return [
        {
            "decoy_id": r["decoy_id"],
            "agent_id": r["agent_id"],
            "tenant_id": r["tenant_id"],
            "token_id": r["token_id"],
            "source": r["source"],
            "activated_at": r["activated_at"],
            "hits": r["hits"],
            "last_hit_at": r["last_hit_at"],
        }
        for r in rows
    ]


def record_decoy_hit(*, tenant_id: str, token_id: str) -> dict[str, Any] | None:
    """
    Record that a decommissioned token was used (honeypot hit).

    Returns the updated decoy record, or None if the token isn't a known decoy.
    """
    now = _iso_now()
    with _cursor() as cur:
        row = cur.execute(
            "SELECT decoy_id FROM deception_mesh_decoys WHERE tenant_id = ? AND token_id = ?",
            (tenant_id, token_id),
        ).fetchone()
        if not row:
            return None
        cur.execute(
            """
            UPDATE deception_mesh_decoys
            SET hits = hits + 1, last_hit_at = ?
            WHERE decoy_id = ?
            """,
            (now, row["decoy_id"]),
        )
    log.warning(
        "⚠️  Deception mesh HIT — tenant=%s token=%s (decommissioned agent credential used!)",
        tenant_id,
        token_id,
    )
    with _cursor() as cur:
        r = cur.execute(
            "SELECT * FROM deception_mesh_decoys WHERE decoy_id = ?",
            (row["decoy_id"],),
        ).fetchone()
    return dict(r)
