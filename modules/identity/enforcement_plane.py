"""
TokenDNA — Real-Time Policy Enforcement Plane (Phase 5-3, Part 1)

The ZTIX Enforcement Edge extends policy evaluation to inline enforcement —
sub-millisecond decisions that run BEFORE an agent action executes.

─────────────────────────────────────────────────────────────
Architecture
─────────────────────────────────────────────────────────────

1. Policy Engine
   Policies are named rulesets that evaluate an (agent, action, resource,
   context) tuple and return allow/block/audit.  Each rule has:
     - conditions: list of field comparisons (action_type, resource,
       agent_id, any context key)
     - logic: "any" (OR) or "all" (AND)
     - decision: allow | block | audit
     - risk_score: 0.0–1.0 attached to the decision

2. Enforcement Modes (per policy)
   - enforce : decisions are authoritative — blocks are real blocks
   - shadow  : decisions are computed and logged but never block.
               Lets operators run enforcement in parallel with live traffic
               to measure false-positive rate before going live.
   - canary  : random canary_pct fraction of evaluations are enforced;
               the rest are allowed.  Promotes to 100% when confidence
               threshold is met.

3. Kill Switch
   Instant revocation of an agent's ability to act across all enforcement
   points.  A kill-switched agent returns "block" regardless of policy.
   Activation is logged, requires actor_id.  Deactivation requires
   actor_id.  Both are immutable events.

4. Shadow Report
   Summary of what WOULD have been blocked in shadow mode — lets operators
   review false positives before flipping to enforce.

─────────────────────────────────────────────────────────────
Policy Rule Format
─────────────────────────────────────────────────────────────

{
  "conditions": [
    {"field": "action_type", "op": "in",         "value": ["write","delete"]},
    {"field": "resource",    "op": "startswith",  "value": "/prod/"},
    {"field": "context.env", "op": "eq",          "value": "production"}
  ],
  "logic": "any",          // "any" (OR) | "all" (AND)
  "decision": "block",     // allow | block | audit
  "risk_score": 0.85
}

Supported operators: eq, neq, in, not_in, startswith, contains, gt, lt

─────────────────────────────────────────────────────────────
API
─────────────────────────────────────────────────────────────
POST /api/enforcement/policies                Create policy
GET  /api/enforcement/policies                List policies
GET  /api/enforcement/policies/{id}           Get policy
PATCH /api/enforcement/policies/{id}          Update policy
DELETE /api/enforcement/policies/{id}         Deactivate policy

POST /api/enforcement/evaluate                Evaluate an agent action
GET  /api/enforcement/decisions               Decision log
GET  /api/enforcement/shadow/report           Shadow mode false-positive report

POST /api/enforcement/killswitch/{agent_id}   Activate kill switch
DELETE /api/enforcement/killswitch/{agent_id} Deactivate kill switch
GET  /api/enforcement/killswitch/{agent_id}   Kill switch status
GET  /api/enforcement/killswitch              List all active kill switches
"""

from __future__ import annotations

import json
import logging
import math
import os
import random
import re
import sqlite3
import threading
import uuid

from modules.storage.ddl_runner import run_ddl
from modules.storage.pg_connection import AdaptedCursor, get_db_conn
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────

_DB_PATH = os.getenv(
    "TOKENDNA_ENFORCEMENT_DB",
    os.path.expanduser("~/.tokendna/enforcement_plane.db"),
)

DRIFT_BLOCK_THRESHOLD = float(os.getenv("ENFORCEMENT_BLOCK_THRESHOLD", "0.75"))
DRIFT_AUDIT_THRESHOLD = float(os.getenv("ENFORCEMENT_AUDIT_THRESHOLD", "0.45"))

_lock = threading.Lock()
_db_initialized = False


# ── DB bootstrap ───────────────────────────────────────────────────────────────


_DDL_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS ep_policies (
        policy_id    TEXT PRIMARY KEY,
        tenant_id    TEXT NOT NULL,
        name         TEXT NOT NULL,
        description  TEXT,
        rules_json   TEXT NOT NULL,
        mode         TEXT NOT NULL DEFAULT 'shadow',
        canary_pct   REAL NOT NULL DEFAULT 0.0,
        status       TEXT NOT NULL DEFAULT 'active',
        created_at   TEXT NOT NULL,
        updated_at   TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_ep_policies_tenant ON ep_policies(tenant_id, status)",
    """
    CREATE TABLE IF NOT EXISTS ep_decisions (
        decision_id      TEXT PRIMARY KEY,
        tenant_id        TEXT NOT NULL,
        agent_id         TEXT NOT NULL,
        policy_id        TEXT,
        action_type      TEXT NOT NULL,
        resource         TEXT,
        context_json     TEXT,
        decision         TEXT NOT NULL,
        mode_at_time     TEXT NOT NULL,
        shadow_would     TEXT,
        risk_score       REAL NOT NULL DEFAULT 0.0,
        reasons_json     TEXT,
        kill_switched    INTEGER NOT NULL DEFAULT 0,
        created_at       TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_ep_decisions_tenant ON ep_decisions(tenant_id, agent_id, created_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS ep_kill_switches (
        switch_id       TEXT PRIMARY KEY,
        tenant_id       TEXT NOT NULL,
        agent_id        TEXT NOT NULL,
        activated_by    TEXT NOT NULL,
        reason          TEXT,
        activated_at    TEXT NOT NULL,
        deactivated_by  TEXT,
        deactivated_at  TEXT,
        active          INTEGER NOT NULL DEFAULT 1
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_ep_ks_lookup ON ep_kill_switches(tenant_id, agent_id, active)",
)


def init_db(db_path: str = _DB_PATH) -> None:
    global _db_initialized
    if _db_initialized:
        return
    with _lock:
        if _db_initialized:
            return
        run_ddl(_DDL_STATEMENTS, db_path)
        _db_initialized = True


@contextmanager
def _cursor(db_path: str = _DB_PATH):
    """Yield a backend-portable AdaptedCursor (SQLite or Postgres)."""
    with get_db_conn(db_path=db_path) as conn:
        yield AdaptedCursor(conn.cursor())


# ── Policy CRUD ────────────────────────────────────────────────────────────────


def create_policy(
    *,
    tenant_id: str,
    name: str,
    rules: list[dict[str, Any]],
    mode: str = "shadow",
    canary_pct: float = 0.0,
    description: str = "",
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Create an enforcement policy.

    Args:
        rules:      List of rule dicts (see module docstring for format).
        mode:       ``shadow`` | ``enforce`` | ``canary``
        canary_pct: 0.0–1.0; fraction of traffic enforced when mode=canary.
    """
    if mode not in ("shadow", "enforce", "canary"):
        raise ValueError(f"Invalid mode '{mode}'. Must be shadow|enforce|canary")
    if not 0.0 <= canary_pct <= 1.0:
        raise ValueError(f"canary_pct must be 0.0–1.0, got {canary_pct}")
    _validate_rules(rules)

    init_db(db_path)
    policy_id = str(uuid.uuid4())
    now = _now()
    with _cursor(db_path) as cur:
        cur.execute(
            """
            INSERT INTO ep_policies
                (policy_id, tenant_id, name, description, rules_json,
                 mode, canary_pct, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
            """,
            (policy_id, tenant_id, name, description,
             json.dumps(rules), mode, canary_pct, now, now),
        )
    return get_policy(policy_id, tenant_id, db_path=db_path)


def get_policy(
    policy_id: str,
    tenant_id: str,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    init_db(db_path)
    with _cursor(db_path) as cur:
        row = cur.execute(
            "SELECT * FROM ep_policies WHERE policy_id = ? AND tenant_id = ?",
            (policy_id, tenant_id),
        ).fetchone()
    if row is None:
        raise KeyError(f"Policy '{policy_id}' not found for tenant '{tenant_id}'")
    return _row_to_policy(row)


def list_policies(
    tenant_id: str,
    *,
    status: str | None = "active",
    db_path: str = _DB_PATH,
) -> list[dict[str, Any]]:
    init_db(db_path)
    sql = "SELECT * FROM ep_policies WHERE tenant_id = ?"
    params: list[Any] = [tenant_id]
    if status is not None:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY created_at DESC"
    with _cursor(db_path) as cur:
        rows = cur.execute(sql, params).fetchall()
    return [_row_to_policy(r) for r in rows]


def update_policy(
    policy_id: str,
    tenant_id: str,
    *,
    name: str | None = None,
    description: str | None = None,
    rules: list[dict[str, Any]] | None = None,
    mode: str | None = None,
    canary_pct: float | None = None,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    init_db(db_path)
    current = get_policy(policy_id, tenant_id, db_path=db_path)
    new_mode = mode if mode is not None else current["mode"]
    new_canary = canary_pct if canary_pct is not None else current["canary_pct"]
    new_rules = rules if rules is not None else current["rules"]
    if mode and mode not in ("shadow", "enforce", "canary"):
        raise ValueError(f"Invalid mode '{mode}'")
    if rules:
        _validate_rules(rules)
    now = _now()
    with _cursor(db_path) as cur:
        cur.execute(
            """
            UPDATE ep_policies SET
                name        = ?,
                description = ?,
                rules_json  = ?,
                mode        = ?,
                canary_pct  = ?,
                updated_at  = ?
            WHERE policy_id = ? AND tenant_id = ?
            """,
            (
                name        if name        is not None else current["name"],
                description if description is not None else current["description"],
                json.dumps(new_rules),
                new_mode, new_canary, now,
                policy_id, tenant_id,
            ),
        )
    return get_policy(policy_id, tenant_id, db_path=db_path)


def deactivate_policy(
    policy_id: str,
    tenant_id: str,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    init_db(db_path)
    with _cursor(db_path) as cur:
        cur.execute(
            "UPDATE ep_policies SET status='inactive', updated_at=? WHERE policy_id=? AND tenant_id=?",
            (_now(), policy_id, tenant_id),
        )
    return get_policy(policy_id, tenant_id, db_path=db_path)


def _row_to_policy(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "policy_id":   row["policy_id"],
        "tenant_id":   row["tenant_id"],
        "name":        row["name"],
        "description": row["description"] or "",
        "rules":       json.loads(row["rules_json"] or "[]"),
        "mode":        row["mode"],
        "canary_pct":  float(row["canary_pct"]),
        "status":      row["status"],
        "created_at":  row["created_at"],
        "updated_at":  row["updated_at"],
    }


# ── Rule Evaluation ────────────────────────────────────────────────────────────


def _validate_rules(rules: list[dict[str, Any]]) -> None:
    valid_ops = {"eq", "neq", "in", "not_in", "startswith", "contains", "gt", "lt"}
    valid_decisions = {"allow", "block", "audit"}
    for i, rule in enumerate(rules):
        if "conditions" not in rule:
            raise ValueError(f"Rule {i} missing 'conditions'")
        if "decision" not in rule:
            raise ValueError(f"Rule {i} missing 'decision'")
        if rule["decision"] not in valid_decisions:
            raise ValueError(f"Rule {i} decision must be allow|block|audit")
        for cond in rule["conditions"]:
            if cond.get("op") not in valid_ops:
                raise ValueError(f"Rule {i} condition op must be one of {valid_ops}")


def _eval_condition(
    condition: dict[str, Any],
    action_type: str,
    resource: str,
    context: dict[str, Any],
    agent_id: str,
) -> bool:
    """Evaluate a single condition against the request context."""
    field = condition.get("field", "")
    op = condition.get("op", "eq")
    expected = condition.get("value")

    # Resolve field value
    if field == "action_type":
        actual = action_type
    elif field == "resource":
        actual = resource
    elif field == "agent_id":
        actual = agent_id
    elif field.startswith("context."):
        key = field[len("context."):]
        actual = context.get(key, "")
    else:
        actual = context.get(field, "")

    # Apply operator
    actual_str = str(actual) if actual is not None else ""
    try:
        if op == "eq":
            return actual == expected or actual_str == str(expected)
        elif op == "neq":
            return actual != expected and actual_str != str(expected)
        elif op == "in":
            return actual in (expected or []) or actual_str in (expected or [])
        elif op == "not_in":
            return actual not in (expected or []) and actual_str not in (expected or [])
        elif op == "startswith":
            return actual_str.startswith(str(expected or ""))
        elif op == "contains":
            return str(expected or "") in actual_str
        elif op == "gt":
            return float(actual or 0) > float(expected or 0)
        elif op == "lt":
            return float(actual or 0) < float(expected or 0)
    except (TypeError, ValueError):
        return False
    return False


def _eval_rule(
    rule: dict[str, Any],
    action_type: str,
    resource: str,
    context: dict[str, Any],
    agent_id: str,
) -> tuple[bool, str, float]:
    """Returns (matched, decision, risk_score)."""
    conditions = rule.get("conditions", [])
    logic = rule.get("logic", "all")
    results = [
        _eval_condition(c, action_type, resource, context, agent_id)
        for c in conditions
    ]
    if logic == "any":
        matched = any(results)
    else:
        matched = all(results) if results else False
    decision = rule.get("decision", "allow")
    risk_score = float(rule.get("risk_score", 0.5 if decision == "block" else 0.1))
    return matched, decision, risk_score


# ── Evaluation ─────────────────────────────────────────────────────────────────


def evaluate(
    tenant_id: str,
    agent_id: str,
    action_type: str,
    resource: str = "",
    context: dict[str, Any] | None = None,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Evaluate a pending agent action against all active policies.

    Returns a decision dict with keys:
      - decision:    "allow" | "block" | "audit"
      - blocked:     bool
      - risk_score:  0.0–1.0
      - reasons:     list[str]
      - kill_switched: bool
      - mode:        effective mode that produced this decision
      - policy_id:   matching policy id (if any)
    """
    init_db(db_path)
    context = context or {}

    # ── 1. Kill switch check — overrides everything ────────────────────────────
    if _is_kill_switched(tenant_id, agent_id, db_path=db_path):
        return _record_decision(
            tenant_id=tenant_id,
            agent_id=agent_id,
            policy_id=None,
            action_type=action_type,
            resource=resource,
            context=context,
            decision="block",
            mode_at_time="enforce",
            shadow_would=None,
            risk_score=1.0,
            reasons=["kill_switch_active"],
            kill_switched=True,
            db_path=db_path,
        )

    # ── 2. Evaluate active policies in order ───────────────────────────────────
    policies = list_policies(tenant_id, status="active", db_path=db_path)

    best_decision = "allow"
    best_risk = 0.0
    matching_policy_id = None
    reasons: list[str] = []
    effective_mode = "enforce"

    for policy in policies:
        rules = policy["rules"]
        mode = policy["mode"]
        canary_pct = policy["canary_pct"]

        for rule in rules:
            matched, rule_decision, risk = _eval_rule(
                rule, action_type, resource, context, agent_id
            )
            if not matched:
                continue

            reasons.append(f"policy:{policy['name']}:{rule_decision}")
            if risk > best_risk:
                best_risk = risk
                best_decision = rule_decision
                matching_policy_id = policy["policy_id"]
                effective_mode = mode

    # ── 3. Apply mode ──────────────────────────────────────────────────────────
    shadow_would: str | None = None

    if effective_mode == "shadow":
        # Record what would have happened, but always allow
        shadow_would = best_decision
        final_decision = "allow"
    elif effective_mode == "canary":
        policy_obj = next(
            (p for p in policies if p["policy_id"] == matching_policy_id), None
        )
        pct = policy_obj["canary_pct"] if policy_obj else 0.0
        if random.random() < pct:
            final_decision = best_decision
        else:
            shadow_would = best_decision
            final_decision = "allow"
    else:
        final_decision = best_decision

    return _record_decision(
        tenant_id=tenant_id,
        agent_id=agent_id,
        policy_id=matching_policy_id,
        action_type=action_type,
        resource=resource,
        context=context,
        decision=final_decision,
        mode_at_time=effective_mode,
        shadow_would=shadow_would,
        risk_score=best_risk,
        reasons=reasons,
        kill_switched=False,
        db_path=db_path,
    )


def _record_decision(
    *,
    tenant_id: str,
    agent_id: str,
    policy_id: str | None,
    action_type: str,
    resource: str,
    context: dict[str, Any],
    decision: str,
    mode_at_time: str,
    shadow_would: str | None,
    risk_score: float,
    reasons: list[str],
    kill_switched: bool,
    db_path: str,
) -> dict[str, Any]:
    decision_id = str(uuid.uuid4())
    now = _now()
    with _cursor(db_path) as cur:
        cur.execute(
            """
            INSERT INTO ep_decisions
                (decision_id, tenant_id, agent_id, policy_id, action_type,
                 resource, context_json, decision, mode_at_time, shadow_would,
                 risk_score, reasons_json, kill_switched, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                decision_id, tenant_id, agent_id, policy_id,
                action_type, resource, json.dumps(context),
                decision, mode_at_time, shadow_would,
                risk_score, json.dumps(reasons),
                int(kill_switched), now,
            ),
        )
    return {
        "decision_id":   decision_id,
        "agent_id":      agent_id,
        "action_type":   action_type,
        "resource":      resource,
        "decision":      decision,
        "blocked":       decision == "block",
        "risk_score":    risk_score,
        "reasons":       reasons,
        "kill_switched": kill_switched,
        "mode":          mode_at_time,
        "shadow_would":  shadow_would,
        "policy_id":     policy_id,
        "created_at":    now,
    }


def list_decisions(
    tenant_id: str,
    *,
    agent_id: str | None = None,
    decision: str | None = None,
    limit: int = 100,
    db_path: str = _DB_PATH,
) -> list[dict[str, Any]]:
    init_db(db_path)
    sql = "SELECT * FROM ep_decisions WHERE tenant_id = ?"
    params: list[Any] = [tenant_id]
    if agent_id:
        sql += " AND agent_id = ?"
        params.append(agent_id)
    if decision:
        sql += " AND decision = ?"
        params.append(decision)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with _cursor(db_path) as cur:
        rows = cur.execute(sql, params).fetchall()
    return [_row_to_decision(r) for r in rows]


def shadow_report(
    tenant_id: str,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Report of what shadow mode caught vs. let through."""
    init_db(db_path)
    with _cursor(db_path) as cur:
        total = cur.execute(
            "SELECT COUNT(*) FROM ep_decisions WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()[0]

        would_block = cur.execute(
            "SELECT COUNT(*) FROM ep_decisions WHERE tenant_id = ? AND shadow_would = 'block'",
            (tenant_id,),
        ).fetchone()[0]

        would_audit = cur.execute(
            "SELECT COUNT(*) FROM ep_decisions WHERE tenant_id = ? AND shadow_would = 'audit'",
            (tenant_id,),
        ).fetchone()[0]

        actually_blocked = cur.execute(
            "SELECT COUNT(*) FROM ep_decisions WHERE tenant_id = ? AND decision = 'block'",
            (tenant_id,),
        ).fetchone()[0]

        kill_switch_blocks = cur.execute(
            "SELECT COUNT(*) FROM ep_decisions WHERE tenant_id = ? AND kill_switched = 1",
            (tenant_id,),
        ).fetchone()[0]

    return {
        "tenant_id":       tenant_id,
        "total_decisions": total,
        "shadow_would_block": would_block,
        "shadow_would_audit": would_audit,
        "actually_blocked":   actually_blocked,
        "kill_switch_blocks": kill_switch_blocks,
        "false_positive_estimate": would_block - actually_blocked if would_block > actually_blocked else 0,
    }


def _row_to_decision(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "decision_id":   row["decision_id"],
        "tenant_id":     row["tenant_id"],
        "agent_id":      row["agent_id"],
        "policy_id":     row["policy_id"],
        "action_type":   row["action_type"],
        "resource":      row["resource"] or "",
        "context":       json.loads(row["context_json"] or "{}"),
        "decision":      row["decision"],
        "blocked":       row["decision"] == "block",
        "mode":          row["mode_at_time"],
        "shadow_would":  row["shadow_would"],
        "risk_score":    float(row["risk_score"]),
        "reasons":       json.loads(row["reasons_json"] or "[]"),
        "kill_switched": bool(row["kill_switched"]),
        "created_at":    row["created_at"],
    }


# ── Kill Switch ────────────────────────────────────────────────────────────────


def activate_kill_switch(
    tenant_id: str,
    agent_id: str,
    activated_by: str,
    reason: str = "",
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Instantly revoke an agent's ability to act."""
    if not activated_by:
        raise ValueError("activated_by is required to activate a kill switch")
    init_db(db_path)
    # Deactivate any existing active switch first (idempotent)
    now = _now()
    with _cursor(db_path) as cur:
        cur.execute(
            "UPDATE ep_kill_switches SET active=0 WHERE tenant_id=? AND agent_id=? AND active=1",
            (tenant_id, agent_id),
        )
        switch_id = str(uuid.uuid4())
        cur.execute(
            """
            INSERT INTO ep_kill_switches
                (switch_id, tenant_id, agent_id, activated_by, reason,
                 activated_at, active)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            """,
            (switch_id, tenant_id, agent_id, activated_by, reason, now),
        )
    return get_kill_switch_status(tenant_id, agent_id, db_path=db_path)


def deactivate_kill_switch(
    tenant_id: str,
    agent_id: str,
    deactivated_by: str,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    if not deactivated_by:
        raise ValueError("deactivated_by is required")
    init_db(db_path)
    now = _now()
    with _cursor(db_path) as cur:
        cur.execute(
            """
            UPDATE ep_kill_switches
               SET active=0, deactivated_by=?, deactivated_at=?
             WHERE tenant_id=? AND agent_id=? AND active=1
            """,
            (deactivated_by, now, tenant_id, agent_id),
        )
    return get_kill_switch_status(tenant_id, agent_id, db_path=db_path)


def get_kill_switch_status(
    tenant_id: str,
    agent_id: str,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    init_db(db_path)
    with _cursor(db_path) as cur:
        row = cur.execute(
            """
            SELECT * FROM ep_kill_switches
             WHERE tenant_id = ? AND agent_id = ?
             ORDER BY activated_at DESC LIMIT 1
            """,
            (tenant_id, agent_id),
        ).fetchone()
    if row is None:
        return {"agent_id": agent_id, "active": False, "history": []}
    return _row_to_switch(row)


def list_active_kill_switches(
    tenant_id: str,
    *,
    db_path: str = _DB_PATH,
) -> list[dict[str, Any]]:
    init_db(db_path)
    with _cursor(db_path) as cur:
        rows = cur.execute(
            "SELECT * FROM ep_kill_switches WHERE tenant_id = ? AND active = 1 ORDER BY activated_at DESC",
            (tenant_id,),
        ).fetchall()
    return [_row_to_switch(r) for r in rows]


def _is_kill_switched(
    tenant_id: str,
    agent_id: str,
    *,
    db_path: str,
) -> bool:
    with _cursor(db_path) as cur:
        row = cur.execute(
            "SELECT 1 FROM ep_kill_switches WHERE tenant_id=? AND agent_id=? AND active=1",
            (tenant_id, agent_id),
        ).fetchone()
    return row is not None


def _row_to_switch(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "switch_id":      row["switch_id"],
        "tenant_id":      row["tenant_id"],
        "agent_id":       row["agent_id"],
        "active":         bool(row["active"]),
        "activated_by":   row["activated_by"],
        "reason":         row["reason"] or "",
        "activated_at":   row["activated_at"],
        "deactivated_by": row["deactivated_by"],
        "deactivated_at": row["deactivated_at"],
    }


# ── Helpers ────────────────────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
