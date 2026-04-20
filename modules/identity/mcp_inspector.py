"""
TokenDNA — MCP Intent-Aware Inspection (Sprint 5-4)

Cisco called out "intent-aware inspection of tool requests" at RSA as a
critical unsolved problem.  TokenDNA already has mcp_attestation.py (server
integrity / capability attestation).  This module surfaces the *runtime call*
layer — inspecting individual tool invocations BEFORE they execute.

The core insight: OAuth says *who* called the tool.  TokenDNA says *whether
the call is what it claims to be.*

─────────────────────────────────────────────────────────────
Architecture
─────────────────────────────────────────────────────────────

1. Tool registry
   Each tool has a declared intent profile:
     - access_mode:     read | write | execute | admin | exfil
     - allowed_params:  whitelist of safe parameter keys
     - forbidden_params: keys that must never appear (exfiltration risk)
     - param_constraints: optional per-param value rules (regex, range, enum)

2. Per-call inspection (POST /api/mcp/inspect)
   Given a tool_name + params dict, returns:
     - allowed: bool
     - violations: list of detected intent mismatches
     - risk_score: 0.0–1.0
     - recommendation: allow | flag | block

3. Chain analysis
   Each call is appended to the session's tool-call chain.
   Chain patterns are matched against known attack sequences:
     - read_then_exfil:    read file → send_email (exfiltration)
     - privilege_ladder:   read → write → execute (privilege escalation)
     - scope_creep:        expand_scope → write_policy → execute_action
     - lateral_move:       connect → enumerate → connect_new_host
     - data_staging:       read_bulk → compress → upload

4. Intent Correlation bridge
   When a chain pattern fires, an event is forwarded to the
   intent_correlation engine so it can appear in the existing
   exploit-intent-match flow.

─────────────────────────────────────────────────────────────
API
─────────────────────────────────────────────────────────────
POST /api/mcp/inspect                    Inspect a pending tool call
POST /api/mcp/tools/register             Register a tool with intent profile
GET  /api/mcp/violations                 Tool calls that violated declared intent
GET  /api/mcp/chain/{session_id}         Full tool-call chain for a session
GET  /api/mcp/tools                      List registered tool profiles
GET  /api/mcp/tools/{tool_name}          Single tool profile
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)

_lock = threading.Lock()

# ── Configuration ─────────────────────────────────────────────────────────────

DRIFT_BLOCK_THRESHOLD = float(os.getenv("MCP_DRIFT_BLOCK_THRESHOLD", "0.8"))
DRIFT_FLAG_THRESHOLD = float(os.getenv("MCP_DRIFT_FLAG_THRESHOLD", "0.5"))

# ── Known attack chain patterns ───────────────────────────────────────────────
# Each pattern is a list of access_mode sequences to match against recent calls.
# Partial suffix match — the last N calls must match the pattern.

CHAIN_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "read_then_exfil",
        "description": "File read followed by exfiltration attempt",
        "sequence": ["read", "exfil"],
        "severity": "critical",
        "mitre_technique": "T1048",
    },
    {
        "name": "privilege_ladder",
        "description": "Progressive privilege escalation: read → write → execute",
        "sequence": ["read", "write", "execute"],
        "severity": "high",
        "mitre_technique": "T1078",
    },
    {
        "name": "scope_creep",
        "description": "Agent expands its own policy scope before acting",
        "sequence": ["admin", "write", "execute"],
        "severity": "critical",
        "mitre_technique": "T1548",
    },
    {
        "name": "data_staging",
        "description": "Bulk read followed by write (staging for exfil)",
        "sequence": ["read", "read", "write"],
        "severity": "high",
        "mitre_technique": "T1074",
    },
    {
        "name": "lateral_move",
        "description": "Connect, enumerate, connect new host",
        "sequence": ["execute", "read", "execute"],
        "severity": "high",
        "mitre_technique": "T1021",
    },
    {
        "name": "admin_takeover",
        "description": "Admin action immediately followed by write and exfil",
        "sequence": ["admin", "exfil"],
        "severity": "critical",
        "mitre_technique": "T1136",
    },
]

# ── Built-in tool profiles ────────────────────────────────────────────────────
# These seed the tool registry on init_db().  Operators can add custom tools
# via POST /api/mcp/tools/register.

_BUILTIN_TOOLS: list[dict[str, Any]] = [
    {
        "tool_name": "read_file",
        "access_mode": "read",
        "description": "Read a file by path",
        "allowed_params": ["path", "encoding", "lines", "offset"],
        "forbidden_params": ["write", "delete", "execute", "command", "shell"],
        "param_constraints": {
            "path": {"type": "string", "max_length": 4096},
        },
        "tenant_id": "__builtin__",
    },
    {
        "tool_name": "write_file",
        "access_mode": "write",
        "description": "Write or create a file",
        "allowed_params": ["path", "content", "mode", "encoding"],
        "forbidden_params": ["execute", "command", "shell", "rm", "delete"],
        "param_constraints": {
            "path": {"type": "string", "max_length": 4096},
        },
        "tenant_id": "__builtin__",
    },
    {
        "tool_name": "execute_command",
        "access_mode": "execute",
        "description": "Execute a shell command",
        "allowed_params": ["command", "args", "cwd", "timeout"],
        "forbidden_params": [],
        "param_constraints": {
            "timeout": {"type": "number", "max": 300},
        },
        "tenant_id": "__builtin__",
    },
    {
        "tool_name": "send_email",
        "access_mode": "exfil",
        "description": "Send an email (potential exfil vector)",
        "allowed_params": ["to", "subject", "body", "from"],
        "forbidden_params": ["attachment_path", "bcc_all"],
        "param_constraints": {
            "to": {"type": "string"},
        },
        "tenant_id": "__builtin__",
    },
    {
        "tool_name": "http_request",
        "access_mode": "exfil",
        "description": "Make an outbound HTTP request",
        "allowed_params": ["url", "method", "headers", "body", "timeout"],
        "forbidden_params": [],
        "param_constraints": {
            "method": {"type": "enum", "values": ["GET", "POST", "PUT", "PATCH", "DELETE"]},
        },
        "tenant_id": "__builtin__",
    },
    {
        "tool_name": "update_policy",
        "access_mode": "admin",
        "description": "Update an agent policy rule",
        "allowed_params": ["policy_id", "rules", "actor", "reason"],
        "forbidden_params": ["agent_id_self", "override_all"],
        "param_constraints": {},
        "tenant_id": "__builtin__",
    },
    {
        "tool_name": "list_files",
        "access_mode": "read",
        "description": "List files in a directory",
        "allowed_params": ["path", "recursive", "pattern"],
        "forbidden_params": ["delete", "write", "execute"],
        "param_constraints": {},
        "tenant_id": "__builtin__",
    },
    {
        "tool_name": "database_query",
        "access_mode": "read",
        "description": "Execute a read-only database query",
        "allowed_params": ["query", "params", "database", "timeout"],
        "forbidden_params": ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE"],
        "param_constraints": {},
        "tenant_id": "__builtin__",
    },
    {
        "tool_name": "database_write",
        "access_mode": "write",
        "description": "Execute a database write operation",
        "allowed_params": ["query", "params", "database", "timeout"],
        "forbidden_params": ["DROP", "ALTER", "TRUNCATE"],
        "param_constraints": {},
        "tenant_id": "__builtin__",
    },
    {
        "tool_name": "expand_scope",
        "access_mode": "admin",
        "description": "Expand agent permission scope",
        "allowed_params": ["agent_id", "scope", "justification", "approver"],
        "forbidden_params": [],
        "param_constraints": {
            "approver": {"type": "string", "required": True},
        },
        "tenant_id": "__builtin__",
    },
]


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


# ── Schema ────────────────────────────────────────────────────────────────────

def init_db() -> None:
    """Create MCP inspector tables if they don't exist and seed built-in tools."""
    db_path = _db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    with _cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS mcp_tool_profiles (
                tool_name          TEXT NOT NULL,
                tenant_id          TEXT NOT NULL,
                access_mode        TEXT NOT NULL,
                description        TEXT NOT NULL DEFAULT '',
                allowed_params     TEXT NOT NULL DEFAULT '[]',
                forbidden_params   TEXT NOT NULL DEFAULT '[]',
                param_constraints  TEXT NOT NULL DEFAULT '{}',
                created_at         TEXT NOT NULL,
                updated_at         TEXT NOT NULL,
                PRIMARY KEY (tool_name, tenant_id)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS mcp_call_log (
                call_id         TEXT PRIMARY KEY,
                session_id      TEXT NOT NULL,
                tenant_id       TEXT NOT NULL,
                agent_id        TEXT,
                tool_name       TEXT NOT NULL,
                params_json     TEXT NOT NULL DEFAULT '{}',
                access_mode     TEXT,
                risk_score      REAL NOT NULL DEFAULT 0.0,
                recommendation  TEXT NOT NULL DEFAULT 'allow',
                violations_json TEXT NOT NULL DEFAULT '[]',
                chain_patterns  TEXT NOT NULL DEFAULT '[]',
                created_at      TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS mcp_violations (
                violation_id    TEXT PRIMARY KEY,
                call_id         TEXT NOT NULL,
                session_id      TEXT NOT NULL,
                tenant_id       TEXT NOT NULL,
                agent_id        TEXT,
                tool_name       TEXT NOT NULL,
                violation_type  TEXT NOT NULL,
                detail          TEXT NOT NULL,
                risk_score      REAL NOT NULL DEFAULT 0.0,
                resolved        INTEGER NOT NULL DEFAULT 0,
                resolved_by     TEXT,
                resolved_at     TEXT,
                created_at      TEXT NOT NULL
            )
            """
        )
        for idx_sql in [
            "CREATE INDEX IF NOT EXISTS idx_mcp_call_session ON mcp_call_log(session_id, tenant_id)",
            "CREATE INDEX IF NOT EXISTS idx_mcp_call_tenant ON mcp_call_log(tenant_id, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_mcp_violations_tenant ON mcp_violations(tenant_id, resolved)",
        ]:
            cur.execute(idx_sql)

        # Seed built-in tool profiles (idempotent — INSERT OR IGNORE)
        now = _iso_now()
        for tool in _BUILTIN_TOOLS:
            cur.execute(
                """
                INSERT OR IGNORE INTO mcp_tool_profiles
                    (tool_name, tenant_id, access_mode, description,
                     allowed_params, forbidden_params, param_constraints,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tool["tool_name"],
                    tool["tenant_id"],
                    tool["access_mode"],
                    tool.get("description", ""),
                    json.dumps(tool.get("allowed_params", [])),
                    json.dumps(tool.get("forbidden_params", [])),
                    json.dumps(tool.get("param_constraints", {})),
                    now,
                    now,
                ),
            )


# ── Tool profile management ───────────────────────────────────────────────────

def register_tool(
    *,
    tenant_id: str,
    tool_name: str,
    access_mode: str,
    description: str = "",
    allowed_params: list[str] | None = None,
    forbidden_params: list[str] | None = None,
    param_constraints: dict | None = None,
) -> dict[str, Any]:
    """Register or update a tool's intent profile."""
    valid_modes = {"read", "write", "execute", "admin", "exfil"}
    if access_mode not in valid_modes:
        raise ValueError(f"access_mode must be one of {sorted(valid_modes)}, got '{access_mode}'")
    now = _iso_now()
    with _cursor() as cur:
        cur.execute(
            """
            INSERT INTO mcp_tool_profiles
                (tool_name, tenant_id, access_mode, description,
                 allowed_params, forbidden_params, param_constraints,
                 created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tool_name, tenant_id) DO UPDATE SET
                access_mode       = excluded.access_mode,
                description       = excluded.description,
                allowed_params    = excluded.allowed_params,
                forbidden_params  = excluded.forbidden_params,
                param_constraints = excluded.param_constraints,
                updated_at        = excluded.updated_at
            """,
            (
                tool_name,
                tenant_id,
                access_mode,
                description,
                json.dumps(allowed_params or []),
                json.dumps(forbidden_params or []),
                json.dumps(param_constraints or {}),
                now,
                now,
            ),
        )
    return get_tool(tenant_id=tenant_id, tool_name=tool_name)


def get_tool(*, tenant_id: str, tool_name: str) -> dict[str, Any]:
    """Return a tool profile, checking tenant-specific first, then builtins."""
    with _cursor() as cur:
        # Try tenant-specific first, then builtin
        row = cur.execute(
            """
            SELECT * FROM mcp_tool_profiles
            WHERE tool_name = ? AND (tenant_id = ? OR tenant_id = '__builtin__')
            ORDER BY CASE WHEN tenant_id = ? THEN 0 ELSE 1 END
            LIMIT 1
            """,
            (tool_name, tenant_id, tenant_id),
        ).fetchone()
    if not row:
        return {}
    return _row_to_tool(row)


def list_tools(*, tenant_id: str) -> list[dict[str, Any]]:
    """List all tool profiles available to this tenant (own + builtins)."""
    with _cursor() as cur:
        rows = cur.execute(
            """
            SELECT * FROM mcp_tool_profiles
            WHERE tenant_id = ? OR tenant_id = '__builtin__'
            ORDER BY tool_name
            """,
            (tenant_id,),
        ).fetchall()
    return [_row_to_tool(r) for r in rows]


def _row_to_tool(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "tool_name": row["tool_name"],
        "tenant_id": row["tenant_id"],
        "access_mode": row["access_mode"],
        "description": row["description"],
        "allowed_params": json.loads(row["allowed_params"] or "[]"),
        "forbidden_params": json.loads(row["forbidden_params"] or "[]"),
        "param_constraints": json.loads(row["param_constraints"] or "{}"),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


# ── Core inspection logic ─────────────────────────────────────────────────────

def _inspect_params(
    params: dict[str, Any],
    profile: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Check params against the tool's intent profile.
    Returns a list of violation dicts (empty = clean).
    """
    violations: list[dict[str, Any]] = []
    forbidden = set(profile.get("forbidden_params") or [])
    constraints = profile.get("param_constraints") or {}

    # 1. Forbidden parameter keys
    for key in params:
        if key in forbidden:
            violations.append({
                "type": "forbidden_param",
                "detail": f"Parameter '{key}' is forbidden for tool '{profile['tool_name']}'",
                "severity": "high",
            })

    # 2. Forbidden parameter values (substring match against forbidden list)
    #    Catches cases like query="SELECT * FROM ... DROP TABLE ..."
    for fkey in forbidden:
        for pkey, pval in params.items():
            if isinstance(pval, str) and fkey.upper() in pval.upper():
                violations.append({
                    "type": "forbidden_value",
                    "detail": (
                        f"Parameter '{pkey}' contains forbidden token '{fkey}' "
                        f"in tool '{profile['tool_name']}'"
                    ),
                    "severity": "high",
                })

    # 3. Param constraints
    for param_name, rule in constraints.items():
        val = params.get(param_name)
        if rule.get("required") and val is None:
            violations.append({
                "type": "missing_required_param",
                "detail": f"Required parameter '{param_name}' is missing",
                "severity": "medium",
            })
            continue
        if val is None:
            continue
        if rule.get("type") == "string":
            max_len = rule.get("max_length")
            if max_len and isinstance(val, str) and len(val) > max_len:
                violations.append({
                    "type": "param_constraint_violation",
                    "detail": f"Parameter '{param_name}' exceeds max length {max_len}",
                    "severity": "low",
                })
        elif rule.get("type") == "number":
            max_val = rule.get("max")
            if max_val is not None and isinstance(val, (int, float)) and val > max_val:
                violations.append({
                    "type": "param_constraint_violation",
                    "detail": f"Parameter '{param_name}' value {val} exceeds max {max_val}",
                    "severity": "medium",
                })
        elif rule.get("type") == "enum":
            allowed_vals = set(rule.get("values", []))
            if val not in allowed_vals:
                violations.append({
                    "type": "param_constraint_violation",
                    "detail": (
                        f"Parameter '{param_name}' value '{val}' not in allowed "
                        f"values {sorted(allowed_vals)}"
                    ),
                    "severity": "medium",
                })

    return violations


def _compute_risk_score(violations: list[dict], chain_patterns: list[dict]) -> float:
    """
    Compute a 0.0–1.0 risk score.

    Base score from violation severity:
      critical → 0.9, high → 0.6, medium → 0.35, low → 0.15

    Chain patterns add on top (capped at 1.0).
    """
    if not violations and not chain_patterns:
        return 0.0

    severity_scores = {"critical": 0.9, "high": 0.6, "medium": 0.35, "low": 0.15}
    base = 0.0
    for v in violations:
        sev = v.get("severity", "low")
        base = max(base, severity_scores.get(sev, 0.15))

    chain_bonus = 0.0
    pattern_scores = {"critical": 0.6, "high": 0.35, "medium": 0.15}
    for p in chain_patterns:
        sev = p.get("severity", "medium")
        chain_bonus = max(chain_bonus, pattern_scores.get(sev, 0.1))

    return min(1.0, base + chain_bonus)


def _recommend(risk_score: float) -> str:
    if risk_score >= DRIFT_BLOCK_THRESHOLD:
        return "block"
    if risk_score >= DRIFT_FLAG_THRESHOLD:
        return "flag"
    return "allow"


def _match_chain_patterns(recent_modes: list[str]) -> list[dict[str, Any]]:
    """
    Check the recent access_mode sequence against known attack patterns.
    Returns matching patterns (empty = no match).
    """
    matched = []
    for pattern in CHAIN_PATTERNS:
        seq = pattern["sequence"]
        n = len(seq)
        # Check if the last N modes match the pattern
        if len(recent_modes) >= n and recent_modes[-n:] == seq:
            matched.append(pattern)
    return matched


def inspect_call(
    *,
    tenant_id: str,
    session_id: str,
    tool_name: str,
    params: dict[str, Any],
    agent_id: str | None = None,
    declared_intent: str | None = None,
) -> dict[str, Any]:
    """
    Inspect a pending MCP tool call.

    Returns a result dict with:
      call_id, allowed, risk_score, recommendation, violations, chain_patterns
    """
    call_id = str(uuid.uuid4())
    now = _iso_now()

    # 1. Look up tool profile
    profile = get_tool(tenant_id=tenant_id, tool_name=tool_name)
    unknown_tool = not profile
    if unknown_tool:
        # Unknown tool — treat as high-risk
        profile = {
            "tool_name": tool_name,
            "access_mode": "execute",
            "allowed_params": [],
            "forbidden_params": [],
            "param_constraints": {},
        }

    access_mode = profile.get("access_mode", "execute")

    # 2. Check for declared intent mismatch
    violations: list[dict[str, Any]] = []
    if unknown_tool:
        violations.append({
            "type": "unknown_tool",
            "detail": f"Tool '{tool_name}' is not registered — cannot verify intent",
            "severity": "high",
        })

    if declared_intent and declared_intent != access_mode:
        violations.append({
            "type": "intent_mismatch",
            "detail": (
                f"Agent declared intent '{declared_intent}' but tool '{tool_name}' "
                f"has access_mode '{access_mode}'"
            ),
            "severity": "critical",
        })

    # 3. Parameter inspection
    param_violations = _inspect_params(params, profile)
    violations.extend(param_violations)

    # 4. Chain analysis — fetch recent calls for this session
    with _cursor() as cur:
        recent_rows = cur.execute(
            """
            SELECT access_mode FROM mcp_call_log
            WHERE session_id = ? AND tenant_id = ?
            ORDER BY created_at DESC
            LIMIT 10
            """,
            (session_id, tenant_id),
        ).fetchall()

    recent_modes = [r["access_mode"] for r in reversed(recent_rows) if r["access_mode"]]
    recent_modes.append(access_mode)  # include current call
    chain_patterns = _match_chain_patterns(recent_modes)

    # 5. Score and recommend
    risk_score = _compute_risk_score(violations, chain_patterns)
    recommendation = _recommend(risk_score)

    # 6. Persist call log
    with _cursor() as cur:
        cur.execute(
            """
            INSERT INTO mcp_call_log
                (call_id, session_id, tenant_id, agent_id, tool_name,
                 params_json, access_mode, risk_score, recommendation,
                 violations_json, chain_patterns, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                call_id,
                session_id,
                tenant_id,
                agent_id,
                tool_name,
                json.dumps(params),
                access_mode,
                risk_score,
                recommendation,
                json.dumps(violations),
                json.dumps(chain_patterns),
                now,
            ),
        )

        # 7. Write violations to violations table
        for v in violations:
            vid = str(uuid.uuid4())
            cur.execute(
                """
                INSERT INTO mcp_violations
                    (violation_id, call_id, session_id, tenant_id, agent_id,
                     tool_name, violation_type, detail, risk_score, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    vid,
                    call_id,
                    session_id,
                    tenant_id,
                    agent_id,
                    tool_name,
                    v["type"],
                    v["detail"],
                    risk_score,
                    now,
                ),
            )

    # 8. Intent correlation bridge — forward chain pattern matches
    if chain_patterns:
        _forward_to_intent_correlation(
            tenant_id=tenant_id,
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            chain_patterns=chain_patterns,
            risk_score=risk_score,
        )

    allowed = recommendation == "allow"
    log.info(
        "MCP inspect: tenant=%s session=%s tool=%s score=%.2f rec=%s",
        tenant_id, session_id, tool_name, risk_score, recommendation,
    )
    if recommendation == "block":
        log.warning(
            "⛔ MCP BLOCKED: tenant=%s session=%s tool=%s violations=%d chain=%s",
            tenant_id, session_id, tool_name, len(violations),
            [p["name"] for p in chain_patterns],
        )

    return {
        "call_id": call_id,
        "session_id": session_id,
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "tool_name": tool_name,
        "access_mode": access_mode,
        "allowed": allowed,
        "risk_score": round(risk_score, 4),
        "recommendation": recommendation,
        "violations": violations,
        "chain_patterns": chain_patterns,
        "created_at": now,
    }


def _forward_to_intent_correlation(
    *,
    tenant_id: str,
    session_id: str,
    agent_id: str | None,
    tool_name: str,
    chain_patterns: list[dict],
    risk_score: float,
) -> None:
    """
    Forward chain pattern matches to the intent_correlation engine.
    Non-fatal — errors are logged but do not block the inspector.
    """
    try:
        from modules.identity import intent_correlation as _ic  # noqa: PLC0415
        # Build a synthetic UIS-style event the ICE can process
        for pattern in chain_patterns:
            event = {
                "event_id": str(uuid.uuid4()),
                "tenant_id": tenant_id,
                "subject": agent_id or session_id,
                "category": "mcp_intent_violation",
                "mitre_technique": pattern.get("mitre_technique", "T0000"),
                "risk_score": risk_score,
                "risk_tier": "critical" if risk_score >= 0.8 else "high",
                "narrative": {
                    "pivot": "mcp_chain_pattern",
                    "objective": pattern["description"],
                    "confidence": risk_score,
                },
                "metadata": {
                    "pattern_name": pattern["name"],
                    "tool_name": tool_name,
                    "session_id": session_id,
                },
            }
            _ic.process_event(event)
    except Exception as exc:  # noqa: BLE001
        log.debug("Intent correlation bridge skipped: %s", exc)


# ── Query functions ───────────────────────────────────────────────────────────

def list_violations(
    *,
    tenant_id: str,
    resolved: bool | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Return MCP violations for a tenant, optionally filtered by resolved state."""
    limit = min(max(limit, 1), 1000)
    with _cursor() as cur:
        if resolved is None:
            rows = cur.execute(
                """
                SELECT * FROM mcp_violations
                WHERE tenant_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
        else:
            rows = cur.execute(
                """
                SELECT * FROM mcp_violations
                WHERE tenant_id = ? AND resolved = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (tenant_id, 1 if resolved else 0, limit),
            ).fetchall()
    return [_row_to_violation(r) for r in rows]


def get_chain(*, tenant_id: str, session_id: str, limit: int = 200) -> list[dict[str, Any]]:
    """Return the full tool-call chain for a session."""
    limit = min(max(limit, 1), 1000)
    with _cursor() as cur:
        rows = cur.execute(
            """
            SELECT * FROM mcp_call_log
            WHERE session_id = ? AND tenant_id = ?
            ORDER BY created_at ASC
            LIMIT ?
            """,
            (session_id, tenant_id, limit),
        ).fetchall()
    return [_row_to_call(r) for r in rows]


def resolve_violation(
    *,
    tenant_id: str,
    violation_id: str,
    resolved_by: str,
) -> dict[str, Any]:
    """Mark a violation as resolved."""
    now = _iso_now()
    with _cursor() as cur:
        row = cur.execute(
            "SELECT violation_id FROM mcp_violations WHERE violation_id = ? AND tenant_id = ?",
            (violation_id, tenant_id),
        ).fetchone()
        if not row:
            raise KeyError(f"Violation '{violation_id}' not found for tenant '{tenant_id}'")
        cur.execute(
            """
            UPDATE mcp_violations
            SET resolved = 1, resolved_by = ?, resolved_at = ?
            WHERE violation_id = ? AND tenant_id = ?
            """,
            (resolved_by, now, violation_id, tenant_id),
        )
    with _cursor() as cur:
        updated = cur.execute(
            "SELECT * FROM mcp_violations WHERE violation_id = ?",
            (violation_id,),
        ).fetchone()
    return _row_to_violation(updated)


def _row_to_violation(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "violation_id": row["violation_id"],
        "call_id": row["call_id"],
        "session_id": row["session_id"],
        "tenant_id": row["tenant_id"],
        "agent_id": row["agent_id"],
        "tool_name": row["tool_name"],
        "violation_type": row["violation_type"],
        "detail": row["detail"],
        "risk_score": float(row["risk_score"]),
        "resolved": bool(row["resolved"]),
        "resolved_by": row["resolved_by"],
        "resolved_at": row["resolved_at"],
        "created_at": row["created_at"],
    }


def _row_to_call(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "call_id": row["call_id"],
        "session_id": row["session_id"],
        "tenant_id": row["tenant_id"],
        "agent_id": row["agent_id"],
        "tool_name": row["tool_name"],
        "params": json.loads(row["params_json"] or "{}"),
        "access_mode": row["access_mode"],
        "risk_score": float(row["risk_score"]),
        "recommendation": row["recommendation"],
        "violations": json.loads(row["violations_json"] or "[]"),
        "chain_patterns": json.loads(row["chain_patterns"] or "[]"),
        "created_at": row["created_at"],
    }
