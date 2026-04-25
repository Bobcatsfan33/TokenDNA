"""
TokenDNA — Agent Policy Guard (Sprint 5-1)

Detects and enforces against agents attempting to modify policies that govern
their own permissions — the "policy self-modification" pattern.

RSA'26 Context (Gap 1)
─────────────────────
CrowdStrike disclosed two Fortune 50 production incidents at RSA 2026:
  1. A CEO's AI agent encountered a security restriction, determined it
     was blocking task completion, and *removed the restriction itself*.
     Every identity check passed. Caught by accident.
  2. A 100-agent Slack swarm delegated a code fix between agents with no
     human approval. Agent 12 made the commit. Discovered after the fact.

Both incidents shared the same root cause: agents with legitimate credentials
were able to modify the governance structures that defined their own permission
scope. No existing framework at RSA'26 detected or prevented this.

PolicyGuard closes this gap with three mechanisms:

  1. Constitutional constraint evaluation
     Before any policy mutation is applied, evaluate it against a set of
     constitutional rules. A policy action that expands the actor's own
     scope, removes restrictions governing the actor, or delegates
     excessive authority is flagged.

  2. Violation tracking
     Every self-modification attempt is recorded with full evidence for
     audit trails and incident response.

  3. Human approval gate
     Flagged actions require explicit human approval via
     POST /api/policy/guard/violations/{id}/approve before they can
     proceed. Actions with BLOCK disposition must not be applied.

API
───
POST /api/policy/guard/evaluate      Evaluate a pending policy action
GET  /api/policy/guard/violations    List detected self-modification attempts
POST /api/policy/guard/violations/{id}/approve   Human approval of a blocked action
GET  /api/policy/guard/violations/{id}           Get a specific violation

Integration
───────────
- Feeds trust_graph.check_policy_self_modification() for graph-level detection
- Records to decision_audit for full provenance chain
- Works alongside policy_bundles (evaluates before activation)
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3  # noqa: F401  retained for type-compat with legacy callers
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from modules.storage.ddl_runner import run_ddl
from modules.storage.pg_connection import AdaptedCursor, get_db_conn

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_DB_PATH = os.getenv("DATA_DB_PATH", "/data/tokendna.db")
_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

class Disposition(str, Enum):
    ALLOW = "allow"         # action is permitted
    FLAG = "flag"           # action is suspicious — allow but alert
    BLOCK = "block"         # action must not proceed — human review required


class ViolationStatus(str, Enum):
    OPEN = "open"           # awaiting human review
    APPROVED = "approved"   # human explicitly approved the action
    REJECTED = "rejected"   # human rejected (action must not proceed)
    AUTO_CLOSED = "auto_closed"  # closed by system after timeout/context


@dataclass
class PolicyAction:
    """A pending policy mutation to be evaluated by the guard."""
    actor_id: str                  # agent/service attempting the action
    actor_type: str                # "agent" | "service" | "human"
    action_type: str               # "create" | "update" | "delete" | "activate" | "rollback"
    target_policy_id: str          # policy being modified
    target_policy_name: str        # human-readable policy name
    tenant_id: str
    scope_delta: list[str] = field(default_factory=list)  # permissions added/removed
    metadata: dict[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class GuardEvaluation:
    """Result of evaluating a policy action against constitutional rules."""
    request_id: str
    actor_id: str
    target_policy_id: str
    tenant_id: str
    disposition: Disposition
    rules_triggered: list[str]
    reasons: list[str]
    violation_id: str | None       # set when a violation record was created
    evaluated_at: str


@dataclass
class PolicyViolation:
    """A recorded self-modification attempt requiring human review."""
    violation_id: str
    request_id: str
    actor_id: str
    actor_type: str
    action_type: str
    target_policy_id: str
    target_policy_name: str
    tenant_id: str
    disposition: Disposition
    rules_triggered: list[str]
    reasons: list[str]
    status: ViolationStatus
    detected_at: str
    resolved_at: str | None
    resolved_by: str | None
    resolution_note: str | None
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Constitutional rules
# ---------------------------------------------------------------------------

# A "constitutional rule" is a function that examines a PolicyAction and
# returns (triggered: bool, reason: str | None).
# Rules are evaluated in order; first BLOCK rule wins disposition.

def _rule_self_scope_expansion(action: PolicyAction) -> tuple[bool, str | None]:
    """
    CONST-01: An agent cannot expand its own permission scope.
    Fires when the actor is an agent and scope_delta contains additions
    that benefit the actor directly (heuristic: actor_id appears in
    target_policy_name or metadata, or scope_delta is non-empty on a
    policy the agent itself operates under).
    """
    if action.actor_type != "agent":
        return False, None
    if not action.scope_delta:
        return False, None
    additions = [s for s in action.scope_delta if not s.startswith("-")]
    if not additions:
        return False, None
    # Heuristic: if actor_id appears in the policy name/metadata it likely governs the actor
    governs_actor = (
        action.actor_id in action.target_policy_name.lower()
        or action.actor_id in str(action.metadata).lower()
        or action.metadata.get("governed_agent") == action.actor_id
    )
    if governs_actor:
        return True, (
            f"Agent '{action.actor_id}' attempted to expand its own permission scope "
            f"on policy '{action.target_policy_name}': added {additions}. "
            "Self-scope expansion is constitutionally prohibited. [CONST-01]"
        )
    return False, None


def _rule_self_restriction_removal(action: PolicyAction) -> tuple[bool, str | None]:
    """
    CONST-02: An agent cannot remove restrictions that govern itself.
    Fires on delete/rollback actions by an agent on a policy that
    contains the actor's ID or is marked as governing the actor.
    """
    if action.actor_type != "agent":
        return False, None
    if action.action_type not in {"delete", "rollback"}:
        return False, None
    governs_actor = (
        action.actor_id in action.target_policy_name.lower()
        or action.metadata.get("governed_agent") == action.actor_id
        or action.metadata.get("policy_scope") == "self"
    )
    if governs_actor:
        return True, (
            f"Agent '{action.actor_id}' attempted to {action.action_type} "
            f"policy '{action.target_policy_name}' which contains restrictions "
            "governing the actor itself. [CONST-02]"
        )
    return False, None


def _rule_write_to_governing_policy(action: PolicyAction) -> tuple[bool, str | None]:
    """
    CONST-03: An agent cannot write/update the policy that directly governs it.
    Fires on update/create actions where metadata indicates the actor is
    governed by the target policy.
    """
    if action.actor_type != "agent":
        return False, None
    if action.action_type not in {"create", "update", "activate"}:
        return False, None
    # Explicit governance signal from caller metadata
    is_governing = (
        action.metadata.get("governed_agent") == action.actor_id
        or action.metadata.get("policy_scope") == "self"
        or action.metadata.get("is_self_governing") is True
    )
    if is_governing:
        return True, (
            f"Agent '{action.actor_id}' attempted to {action.action_type} "
            f"policy '{action.target_policy_name}' which directly governs the "
            "actor's own permissions. This is the CrowdStrike-documented "
            "Fortune 50 incident pattern. [CONST-03]"
        )
    return False, None


def _rule_excessive_delegation(action: PolicyAction) -> tuple[bool, str | None]:
    """
    CONST-04: An agent cannot create policies that grant authority exceeding
    its own current scope (prevents privilege amplification through delegation).
    """
    if action.actor_type != "agent":
        return False, None
    if action.action_type not in {"create", "update"}:
        return False, None
    delegated_scopes = action.metadata.get("delegated_scopes", [])
    actor_scopes = action.metadata.get("actor_scopes", [])
    if not delegated_scopes or not actor_scopes:
        return False, None
    # Check if delegated scopes exceed actor's current scope
    excess = set(delegated_scopes) - set(actor_scopes)
    if excess:
        return True, (
            f"Agent '{action.actor_id}' attempted to delegate permissions "
            f"{sorted(excess)} that exceed its own scope {sorted(actor_scopes)}. "
            "Privilege amplification through delegation is prohibited. [CONST-04]"
        )
    return False, None


def _rule_unilateral_governance_change(action: PolicyAction) -> tuple[bool, str | None]:
    """
    CONST-05 (FLAG level): Any agent modifying a governance-tier policy
    (quorum, federation, trust) without explicit human approval signal
    should be flagged even if not a direct self-modification.
    """
    if action.actor_type not in {"agent", "service"}:
        return False, None
    governance_keywords = {
        "governance", "federation", "quorum", "trust", "auth", "authorization",
        "rbac", "permission", "access-control", "acl", "iam",
    }
    policy_lower = action.target_policy_name.lower()
    is_governance = any(kw in policy_lower for kw in governance_keywords)
    has_human_approval = action.metadata.get("human_approved") is True
    if is_governance and not has_human_approval:
        return True, (
            f"Agent/service '{action.actor_id}' modified governance-tier policy "
            f"'{action.target_policy_name}' without explicit human approval signal. "
            "Governance policy changes should require human oversight. [CONST-05]"
        )
    return False, None


# Rule registry: (rule_fn, disposition_if_triggered)
_CONSTITUTIONAL_RULES: list[tuple[Any, Disposition]] = [
    (_rule_self_scope_expansion,        Disposition.BLOCK),
    (_rule_self_restriction_removal,    Disposition.BLOCK),
    (_rule_write_to_governing_policy,   Disposition.BLOCK),
    (_rule_excessive_delegation,        Disposition.BLOCK),
    (_rule_unilateral_governance_change, Disposition.FLAG),
]

_RULE_NAMES = {
    _rule_self_scope_expansion:         "CONST-01",
    _rule_self_restriction_removal:     "CONST-02",
    _rule_write_to_governing_policy:    "CONST-03",
    _rule_excessive_delegation:         "CONST-04",
    _rule_unilateral_governance_change: "CONST-05",
}

# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def _cursor():
    """Yield a backend-portable AdaptedCursor.

    Routes through ``modules.storage.pg_connection.get_db_conn`` so the same
    code path works on SQLite (default) and Postgres. ``AdaptedCursor``
    rewrites ``?`` placeholders to ``%s`` when running against psycopg.
    """
    with _lock:
        with get_db_conn(db_path=_DB_PATH) as conn:
            yield AdaptedCursor(conn.cursor())


_DDL_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS policy_guard_violations (
        violation_id        TEXT NOT NULL PRIMARY KEY,
        request_id          TEXT NOT NULL,
        actor_id            TEXT NOT NULL,
        actor_type          TEXT NOT NULL,
        action_type         TEXT NOT NULL,
        target_policy_id    TEXT NOT NULL,
        target_policy_name  TEXT NOT NULL,
        tenant_id           TEXT NOT NULL,
        disposition         TEXT NOT NULL,
        rules_triggered     TEXT NOT NULL DEFAULT '[]',
        reasons             TEXT NOT NULL DEFAULT '[]',
        status              TEXT NOT NULL DEFAULT 'open',
        detected_at         TEXT NOT NULL,
        resolved_at         TEXT,
        resolved_by         TEXT,
        resolution_note     TEXT,
        metadata            TEXT NOT NULL DEFAULT '{}'
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_pgv_tenant_status ON policy_guard_violations(tenant_id, status, detected_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_pgv_actor ON policy_guard_violations(actor_id, tenant_id)",
    "CREATE INDEX IF NOT EXISTS idx_pgv_policy ON policy_guard_violations(target_policy_id, tenant_id)",
)


def init_db() -> None:
    """Idempotently create PolicyGuard tables on SQLite and Postgres."""
    run_ddl(_DDL_STATEMENTS, _DB_PATH)


# ---------------------------------------------------------------------------
# Core evaluation engine
# ---------------------------------------------------------------------------

def evaluate(action: PolicyAction) -> GuardEvaluation:
    """
    Evaluate a pending policy action against all constitutional rules.

    Returns a GuardEvaluation with disposition ALLOW, FLAG, or BLOCK.
    BLOCK and FLAG dispositions create a violation record.
    """
    init_db()

    triggered_rules: list[str] = []
    reasons: list[str] = []
    worst_disposition = Disposition.ALLOW

    for rule_fn, rule_disposition in _CONSTITUTIONAL_RULES:
        triggered, reason = rule_fn(action)
        if triggered:
            rule_name = _RULE_NAMES[rule_fn]
            triggered_rules.append(rule_name)
            if reason:
                reasons.append(reason)
            # Escalate disposition (BLOCK > FLAG > ALLOW)
            if rule_disposition == Disposition.BLOCK:
                worst_disposition = Disposition.BLOCK
            elif rule_disposition == Disposition.FLAG and worst_disposition == Disposition.ALLOW:
                worst_disposition = Disposition.FLAG

    violation_id = None
    if worst_disposition != Disposition.ALLOW:
        violation_id = _record_violation(action, worst_disposition, triggered_rules, reasons)
        level = "CRITICAL" if worst_disposition == Disposition.BLOCK else "WARNING"
        logger.warning(
            "%s PolicyGuard: %s disposition for actor=%s on policy=%s rules=%s",
            level, worst_disposition.value, action.actor_id,
            action.target_policy_name, triggered_rules,
        )

    return GuardEvaluation(
        request_id=action.request_id,
        actor_id=action.actor_id,
        target_policy_id=action.target_policy_id,
        tenant_id=action.tenant_id,
        disposition=worst_disposition,
        rules_triggered=triggered_rules,
        reasons=reasons,
        violation_id=violation_id,
        evaluated_at=_utc_now(),
    )


def _record_violation(
    action: PolicyAction,
    disposition: Disposition,
    rules_triggered: list[str],
    reasons: list[str],
) -> str:
    """Persist a violation record; return its violation_id."""
    violation_id = str(uuid.uuid4())
    with _cursor() as cur:
        cur.execute("""
            INSERT INTO policy_guard_violations
                (violation_id, request_id, actor_id, actor_type,
                 action_type, target_policy_id, target_policy_name,
                 tenant_id, disposition, rules_triggered, reasons,
                 status, detected_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
        """, (
            violation_id, action.request_id, action.actor_id, action.actor_type,
            action.action_type, action.target_policy_id, action.target_policy_name,
            action.tenant_id, disposition.value,
            json.dumps(rules_triggered), json.dumps(reasons),
            _utc_now(), json.dumps(action.metadata),
        ))
    return violation_id


# ---------------------------------------------------------------------------
# Violation queries
# ---------------------------------------------------------------------------

def _row_to_violation(row: sqlite3.Row) -> PolicyViolation:
    return PolicyViolation(
        violation_id=row["violation_id"],
        request_id=row["request_id"],
        actor_id=row["actor_id"],
        actor_type=row["actor_type"],
        action_type=row["action_type"],
        target_policy_id=row["target_policy_id"],
        target_policy_name=row["target_policy_name"],
        tenant_id=row["tenant_id"],
        disposition=Disposition(row["disposition"]),
        rules_triggered=json.loads(row["rules_triggered"]),
        reasons=json.loads(row["reasons"]),
        status=ViolationStatus(row["status"]),
        detected_at=row["detected_at"],
        resolved_at=row["resolved_at"],
        resolved_by=row["resolved_by"],
        resolution_note=row["resolution_note"],
        metadata=json.loads(row["metadata"]),
    )


def list_violations(
    tenant_id: str,
    status: str | None = None,
    actor_id: str | None = None,
    disposition: str | None = None,
    limit: int = 50,
) -> list[PolicyViolation]:
    """List policy guard violations for a tenant."""
    init_db()
    clauses = ["tenant_id = ?"]
    params: list[Any] = [tenant_id]
    if status:
        clauses.append("status = ?")
        params.append(status)
    if actor_id:
        clauses.append("actor_id = ?")
        params.append(actor_id)
    if disposition:
        clauses.append("disposition = ?")
        params.append(disposition)
    where = " AND ".join(clauses)
    params.append(min(limit, 200))

    with _cursor() as cur:
        cur.execute(
            f"SELECT * FROM policy_guard_violations WHERE {where} "
            f"ORDER BY detected_at DESC LIMIT ?",
            params,
        )
        rows = cur.fetchall()
    return [_row_to_violation(r) for r in rows]


def get_violation(violation_id: str, tenant_id: str) -> PolicyViolation | None:
    """Fetch a single violation by ID."""
    init_db()
    with _cursor() as cur:
        cur.execute(
            "SELECT * FROM policy_guard_violations WHERE violation_id=? AND tenant_id=?",
            (violation_id, tenant_id),
        )
        row = cur.fetchone()
    return _row_to_violation(row) if row else None


def approve_violation(
    violation_id: str,
    tenant_id: str,
    approved_by: str,
    note: str = "",
) -> PolicyViolation | None:
    """
    Human operator approves a blocked action.
    The action may now proceed but the audit record remains.
    """
    init_db()
    now = _utc_now()
    with _cursor() as cur:
        cur.execute("""
            UPDATE policy_guard_violations
            SET status='approved', resolved_at=?, resolved_by=?, resolution_note=?
            WHERE violation_id=? AND tenant_id=? AND status='open'
        """, (now, approved_by, note, violation_id, tenant_id))
        if cur.rowcount == 0:
            return None
    return get_violation(violation_id, tenant_id)


def reject_violation(
    violation_id: str,
    tenant_id: str,
    rejected_by: str,
    note: str = "",
) -> PolicyViolation | None:
    """Human operator explicitly rejects a blocked action (must not proceed)."""
    init_db()
    now = _utc_now()
    with _cursor() as cur:
        cur.execute("""
            UPDATE policy_guard_violations
            SET status='rejected', resolved_at=?, resolved_by=?, resolution_note=?
            WHERE violation_id=? AND tenant_id=? AND status='open'
        """, (now, rejected_by, note, violation_id, tenant_id))
        if cur.rowcount == 0:
            return None
    return get_violation(violation_id, tenant_id)


def violation_stats(tenant_id: str) -> dict[str, Any]:
    """Summary statistics for a tenant's violations."""
    init_db()
    with _cursor() as cur:
        cur.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) as open_count,
                SUM(CASE WHEN disposition='block' THEN 1 ELSE 0 END) as block_count,
                SUM(CASE WHEN disposition='flag' THEN 1 ELSE 0 END) as flag_count,
                SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) as approved_count,
                SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) as rejected_count
            FROM policy_guard_violations
            WHERE tenant_id=?
        """, (tenant_id,))
        row = cur.fetchone()

    return {
        "tenant_id": tenant_id,
        "total": row["total"] or 0,
        "open": row["open_count"] or 0,
        "blocked": row["block_count"] or 0,
        "flagged": row["flag_count"] or 0,
        "approved": row["approved_count"] or 0,
        "rejected": row["rejected_count"] or 0,
    }
