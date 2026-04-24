"""
TokenDNA — MCP Security Gateway (Phase 5-1)

The MCP Security Gateway is the enforcement control plane for agent↔MCP server
interactions.  Where mcp_inspector.py evaluates individual tool calls, this
module governs the entire gateway relationship at four layers:

1. **Proxy Enforcement** — Tool calls flow through the gateway; blocked calls
   never reach the MCP server.  Three enforcement modes per session:
     - audit  : log everything, never block (shadow mode for onboarding)
     - flag   : return risk score + reasons; caller decides; events logged
     - block  : high-risk calls are rejected before they reach the server

2. **Tool Fingerprinting** — SHA-256 of every MCP server's full tool manifest
   (name + description + input_schema) tracked over time.  Silent capability
   drift — a tool that changes what it can do without going through a change
   process — is the supply-chain attack vector for MCP.

3. **Session Binding** — Every gateway session is anchored to a TokenDNA
   Passport (agent_id + passport_id).  Anonymous sessions are allowed in
   audit mode; strict/block mode rejects unbound sessions.

4. **Anomaly Detection** — Per-agent baseline of normal tool-call frequency
   is learned over time.  When an agent calls a tool at an unusual rate or
   calls a tool it has never used before, a scored anomaly alert is raised.

─────────────────────────────────────────────────────────────
Architecture
─────────────────────────────────────────────────────────────

Integration with mcp_inspector:
  mcp_inspector focuses on per-call intent matching (is this call consistent
  with the tool's declared intent profile?).  mcp_gateway focuses on the
  session and server layer — who is calling, what server are they calling,
  is the server still what it was yesterday, and is this call rate normal?

  The enforce() function calls mcp_inspector.inspect_call() internally and
  combines its risk score with gateway-level signals.

─────────────────────────────────────────────────────────────
API
─────────────────────────────────────────────────────────────
POST /api/mcp/gateway/session/open          Open a gateway-managed MCP session
POST /api/mcp/gateway/session/close/{id}    Close session + emit lifecycle event
GET  /api/mcp/gateway/sessions              List sessions (tenant-scoped)
GET  /api/mcp/gateway/sessions/{id}         Session detail + call log

POST /api/mcp/gateway/enforce               Core enforcement point
GET  /api/mcp/gateway/enforcements          Enforcement log (tenant-scoped)

POST /api/mcp/fingerprint/register          Register (or update) a server manifest
GET  /api/mcp/fingerprint/{server_id}       Latest fingerprint + drift history
GET  /api/mcp/fingerprint/alerts            Servers with unresolved manifest drift

POST /api/mcp/gateway/session/{id}/bind     Bind session to a TokenDNA Passport
GET  /api/mcp/gateway/session/{id}/binding  Get session passport binding

GET  /api/mcp/anomaly/baseline/{agent_id}   Current learned baseline
GET  /api/mcp/anomaly/alerts                Deviations above threshold
POST /api/mcp/anomaly/alerts/{id}/acknowledge   Acknowledge + clear anomaly alert
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────

_DB_PATH = os.getenv(
    "TOKENDNA_MCP_GATEWAY_DB",
    os.path.expanduser("~/.tokendna/mcp_gateway.db"),
)

# Enforcement thresholds
BLOCK_RISK_THRESHOLD = float(os.getenv("MCP_GATEWAY_BLOCK_THRESHOLD", "0.75"))
FLAG_RISK_THRESHOLD = float(os.getenv("MCP_GATEWAY_FLAG_THRESHOLD", "0.45"))

# Anomaly: z-score above this triggers an alert
ANOMALY_Z_THRESHOLD = float(os.getenv("MCP_ANOMALY_Z_THRESHOLD", "3.0"))
# Minimum calls before anomaly baseline is considered stable
ANOMALY_MIN_SAMPLES = int(os.getenv("MCP_ANOMALY_MIN_SAMPLES", "5"))

_lock = threading.Lock()
_db_initialized = False


# ── DB bootstrap ──────────────────────────────────────────────────────────────


def init_db(db_path: str = _DB_PATH) -> None:
    global _db_initialized
    if _db_initialized:
        return
    with _lock:
        if _db_initialized:
            return
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        with sqlite3.connect(db_path) as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                -- ── Sessions ──────────────────────────────────────────────
                CREATE TABLE IF NOT EXISTS gw_sessions (
                    session_id   TEXT PRIMARY KEY,
                    tenant_id    TEXT NOT NULL,
                    agent_id     TEXT NOT NULL,
                    server_id    TEXT NOT NULL,
                    mode         TEXT NOT NULL DEFAULT 'audit',   -- audit|flag|block
                    passport_id  TEXT,
                    status       TEXT NOT NULL DEFAULT 'open',    -- open|closed
                    opened_at    TEXT NOT NULL,
                    closed_at    TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_gw_sess_tenant
                    ON gw_sessions(tenant_id, status);

                -- ── Enforcement log ───────────────────────────────────────
                CREATE TABLE IF NOT EXISTS gw_enforcements (
                    enforcement_id  TEXT PRIMARY KEY,
                    session_id      TEXT NOT NULL,
                    tenant_id       TEXT NOT NULL,
                    agent_id        TEXT NOT NULL,
                    server_id       TEXT NOT NULL,
                    tool_name       TEXT NOT NULL,
                    params_json     TEXT,
                    outcome         TEXT NOT NULL,   -- allow|flag|block
                    risk_score      REAL NOT NULL DEFAULT 0.0,
                    reasons_json    TEXT,
                    inspector_used  INTEGER NOT NULL DEFAULT 0,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_gw_enforce_tenant
                    ON gw_enforcements(tenant_id, created_at DESC);

                -- ── Tool fingerprints ─────────────────────────────────────
                CREATE TABLE IF NOT EXISTS gw_fingerprints (
                    fingerprint_id  TEXT PRIMARY KEY,
                    tenant_id       TEXT NOT NULL,
                    server_id       TEXT NOT NULL,
                    tool_name       TEXT NOT NULL,
                    manifest_json   TEXT NOT NULL,
                    hash            TEXT NOT NULL,
                    created_at      TEXT NOT NULL
                );

                -- Only one "current" fingerprint per (tenant, server, tool)
                CREATE UNIQUE INDEX IF NOT EXISTS idx_gw_fp_current
                    ON gw_fingerprints(tenant_id, server_id, tool_name, hash);

                CREATE INDEX IF NOT EXISTS idx_gw_fp_lookup
                    ON gw_fingerprints(tenant_id, server_id, tool_name, created_at DESC);

                -- ── Fingerprint drift alerts ───────────────────────────────
                CREATE TABLE IF NOT EXISTS gw_fp_alerts (
                    alert_id      TEXT PRIMARY KEY,
                    tenant_id     TEXT NOT NULL,
                    server_id     TEXT NOT NULL,
                    tool_name     TEXT NOT NULL,
                    old_hash      TEXT NOT NULL,
                    new_hash      TEXT NOT NULL,
                    created_at    TEXT NOT NULL,
                    resolved      INTEGER NOT NULL DEFAULT 0,
                    resolved_by   TEXT,
                    resolved_at   TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_gw_fp_alerts_tenant
                    ON gw_fp_alerts(tenant_id, resolved);

                -- ── Anomaly baselines ─────────────────────────────────────
                CREATE TABLE IF NOT EXISTS gw_anomaly_baselines (
                    baseline_id   TEXT PRIMARY KEY,
                    tenant_id     TEXT NOT NULL,
                    agent_id      TEXT NOT NULL,
                    tool_name     TEXT NOT NULL,
                    sample_count  INTEGER NOT NULL DEFAULT 0,
                    mean          REAL NOT NULL DEFAULT 0.0,
                    m2            REAL NOT NULL DEFAULT 0.0,   -- Welford variance accumulator
                    last_updated  TEXT NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_gw_baseline_key
                    ON gw_anomaly_baselines(tenant_id, agent_id, tool_name);

                -- ── Anomaly alerts ────────────────────────────────────────
                CREATE TABLE IF NOT EXISTS gw_anomaly_alerts (
                    alert_id           TEXT PRIMARY KEY,
                    tenant_id          TEXT NOT NULL,
                    agent_id           TEXT NOT NULL,
                    tool_name          TEXT NOT NULL,
                    session_id         TEXT,
                    expected_rate      REAL NOT NULL,
                    actual_rate        REAL NOT NULL,
                    z_score            REAL NOT NULL,
                    first_call         INTEGER NOT NULL DEFAULT 0,
                    created_at         TEXT NOT NULL,
                    acknowledged       INTEGER NOT NULL DEFAULT 0,
                    acknowledged_by    TEXT,
                    acknowledged_at    TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_gw_anomaly_tenant
                    ON gw_anomaly_alerts(tenant_id, acknowledged);
                """
            )
        _db_initialized = True


@contextmanager
def _cursor(db_path: str = _DB_PATH):
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        yield conn.cursor()
        conn.commit()


# ── Sessions ───────────────────────────────────────────────────────────────────


def open_session(
    *,
    tenant_id: str,
    agent_id: str,
    server_id: str,
    mode: str = "audit",
    passport_id: str | None = None,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Open a new gateway-managed MCP session.

    Args:
        tenant_id:   Tenant the agent belongs to.
        agent_id:    Identity of the calling agent.
        server_id:   MCP server being accessed (URL or stable name).
        mode:        Enforcement mode — ``audit`` | ``flag`` | ``block``.
        passport_id: Optional TokenDNA passport binding.
    """
    if mode not in ("audit", "flag", "block"):
        raise ValueError(f"Invalid mode '{mode}'; must be audit|flag|block")
    init_db(db_path)
    session_id = str(uuid.uuid4())
    now = _now()
    with _cursor(db_path) as cur:
        cur.execute(
            """
            INSERT INTO gw_sessions
                (session_id, tenant_id, agent_id, server_id, mode,
                 passport_id, status, opened_at)
            VALUES (?, ?, ?, ?, ?, ?, 'open', ?)
            """,
            (session_id, tenant_id, agent_id, server_id, mode, passport_id, now),
        )
    return get_session(session_id, tenant_id, db_path=db_path)


def close_session(
    session_id: str,
    tenant_id: str,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Close an open session."""
    init_db(db_path)
    now = _now()
    with _cursor(db_path) as cur:
        cur.execute(
            """
            UPDATE gw_sessions
               SET status = 'closed', closed_at = ?
             WHERE session_id = ? AND tenant_id = ? AND status = 'open'
            """,
            (now, session_id, tenant_id),
        )
    return get_session(session_id, tenant_id, db_path=db_path)


def get_session(
    session_id: str,
    tenant_id: str,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    init_db(db_path)
    with _cursor(db_path) as cur:
        row = cur.execute(
            "SELECT * FROM gw_sessions WHERE session_id = ? AND tenant_id = ?",
            (session_id, tenant_id),
        ).fetchone()
    if row is None:
        raise KeyError(f"Session '{session_id}' not found for tenant '{tenant_id}'")
    return _row_to_session(row)


def list_sessions(
    tenant_id: str,
    *,
    status: str | None = None,
    agent_id: str | None = None,
    limit: int = 100,
    db_path: str = _DB_PATH,
) -> list[dict[str, Any]]:
    init_db(db_path)
    sql = "SELECT * FROM gw_sessions WHERE tenant_id = ?"
    params: list[Any] = [tenant_id]
    if status:
        sql += " AND status = ?"
        params.append(status)
    if agent_id:
        sql += " AND agent_id = ?"
        params.append(agent_id)
    sql += " ORDER BY opened_at DESC LIMIT ?"
    params.append(limit)
    with _cursor(db_path) as cur:
        rows = cur.execute(sql, params).fetchall()
    return [_row_to_session(r) for r in rows]


def bind_passport(
    session_id: str,
    tenant_id: str,
    passport_id: str,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Bind a TokenDNA Passport to an existing session."""
    init_db(db_path)
    with _cursor(db_path) as cur:
        cur.execute(
            "UPDATE gw_sessions SET passport_id = ? WHERE session_id = ? AND tenant_id = ?",
            (passport_id, session_id, tenant_id),
        )
    return get_session(session_id, tenant_id, db_path=db_path)


def _row_to_session(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "session_id": row["session_id"],
        "tenant_id": row["tenant_id"],
        "agent_id": row["agent_id"],
        "server_id": row["server_id"],
        "mode": row["mode"],
        "passport_id": row["passport_id"],
        "status": row["status"],
        "opened_at": row["opened_at"],
        "closed_at": row["closed_at"],
    }


# ── Enforcement ────────────────────────────────────────────────────────────────


def enforce(
    session_id: str,
    tenant_id: str,
    tool_name: str,
    params: dict[str, Any],
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Gateway enforcement point.

    Evaluates a pending tool call and returns an enforcement decision.
    The decision combines:
      1. Session state checks (session open, passport binding in block mode)
      2. mcp_inspector intent analysis (if the tool is registered)
      3. Anomaly scoring against the per-agent baseline

    Returns a dict with keys:
      - outcome:    "allow" | "flag" | "block"
      - risk_score: 0.0–1.0
      - reasons:    list of str explaining the decision
      - blocked:    bool — shorthand for outcome == "block"
    """
    init_db(db_path)

    reasons: list[str] = []
    risk_score = 0.0
    inspector_used = False

    # ── 1. Load session ────────────────────────────────────────────────────────
    try:
        session = get_session(session_id, tenant_id, db_path=db_path)
    except KeyError:
        return _enforcement_result(
            session_id=session_id,
            tenant_id=tenant_id,
            agent_id="unknown",
            server_id="unknown",
            tool_name=tool_name,
            params=params,
            risk_score=1.0,
            reasons=["session_not_found"],
            mode="block",
            inspector_used=False,
            db_path=db_path,
        )

    mode = session["mode"]
    agent_id = session["agent_id"]
    server_id = session["server_id"]

    # ── 2. Session state checks ────────────────────────────────────────────────
    if session["status"] != "open":
        reasons.append("session_closed")
        risk_score = max(risk_score, 0.9)

    # In block mode, require passport binding
    if mode == "block" and not session.get("passport_id"):
        reasons.append("passport_not_bound")
        risk_score = max(risk_score, 0.7)

    # ── 3. Intent inspection via mcp_inspector ─────────────────────────────────
    try:
        from modules.identity import mcp_inspector  # noqa: PLC0415

        mcp_inspector.init_db()
        insp = mcp_inspector.inspect_call(
            session_id=session_id,
            tenant_id=tenant_id,
            agent_id=agent_id,
            tool_name=tool_name,
            params=params,
        )
        inspector_used = True
        insp_score = float(insp.get("risk_score", 0.0))
        if insp_score > risk_score:
            risk_score = insp_score
        for v in insp.get("violations", []):
            reasons.append(f"inspector:{v}")
    except Exception as exc:
        log.debug("mcp_inspector unavailable or error: %s", exc)

    # ── 4. Anomaly detection ───────────────────────────────────────────────────
    anomaly = _check_and_update_anomaly(
        tenant_id=tenant_id,
        agent_id=agent_id,
        tool_name=tool_name,
        session_id=session_id,
        db_path=db_path,
    )
    if anomaly:
        risk_score = max(risk_score, min(1.0, anomaly["z_score"] / 10.0))
        reasons.append(
            f"anomaly:z={anomaly['z_score']:.2f} first_call={anomaly['first_call']}"
        )

    # ── 5. Apply enforcement mode ──────────────────────────────────────────────
    return _enforcement_result(
        session_id=session_id,
        tenant_id=tenant_id,
        agent_id=agent_id,
        server_id=server_id,
        tool_name=tool_name,
        params=params,
        risk_score=risk_score,
        reasons=reasons,
        mode=mode,
        inspector_used=inspector_used,
        db_path=db_path,
    )


def _enforcement_result(
    *,
    session_id: str,
    tenant_id: str,
    agent_id: str,
    server_id: str,
    tool_name: str,
    params: dict[str, Any],
    risk_score: float,
    reasons: list[str],
    mode: str,
    inspector_used: bool,
    db_path: str,
) -> dict[str, Any]:
    # Determine outcome based on mode + risk
    if mode == "audit":
        outcome = "allow"
    elif mode == "flag":
        outcome = "flag" if risk_score >= FLAG_RISK_THRESHOLD else "allow"
    else:  # block
        if risk_score >= BLOCK_RISK_THRESHOLD:
            outcome = "block"
        elif risk_score >= FLAG_RISK_THRESHOLD:
            outcome = "flag"
        else:
            outcome = "allow"

    enforcement_id = str(uuid.uuid4())
    now = _now()
    with _cursor(db_path) as cur:
        cur.execute(
            """
            INSERT INTO gw_enforcements
                (enforcement_id, session_id, tenant_id, agent_id, server_id,
                 tool_name, params_json, outcome, risk_score, reasons_json,
                 inspector_used, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                enforcement_id,
                session_id,
                tenant_id,
                agent_id,
                server_id,
                tool_name,
                json.dumps(params),
                outcome,
                risk_score,
                json.dumps(reasons),
                int(inspector_used),
                now,
            ),
        )
    return {
        "enforcement_id": enforcement_id,
        "session_id": session_id,
        "agent_id": agent_id,
        "server_id": server_id,
        "tool_name": tool_name,
        "outcome": outcome,
        "blocked": outcome == "block",
        "risk_score": risk_score,
        "reasons": reasons,
        "inspector_used": inspector_used,
        "created_at": now,
    }


def list_enforcements(
    tenant_id: str,
    *,
    session_id: str | None = None,
    outcome: str | None = None,
    limit: int = 100,
    db_path: str = _DB_PATH,
) -> list[dict[str, Any]]:
    init_db(db_path)
    sql = "SELECT * FROM gw_enforcements WHERE tenant_id = ?"
    params: list[Any] = [tenant_id]
    if session_id:
        sql += " AND session_id = ?"
        params.append(session_id)
    if outcome:
        sql += " AND outcome = ?"
        params.append(outcome)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with _cursor(db_path) as cur:
        rows = cur.execute(sql, params).fetchall()
    return [_row_to_enforcement(r) for r in rows]


def _row_to_enforcement(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "enforcement_id": row["enforcement_id"],
        "session_id": row["session_id"],
        "tenant_id": row["tenant_id"],
        "agent_id": row["agent_id"],
        "server_id": row["server_id"],
        "tool_name": row["tool_name"],
        "params": json.loads(row["params_json"] or "{}"),
        "outcome": row["outcome"],
        "blocked": row["outcome"] == "block",
        "risk_score": float(row["risk_score"]),
        "reasons": json.loads(row["reasons_json"] or "[]"),
        "inspector_used": bool(row["inspector_used"]),
        "created_at": row["created_at"],
    }


# ── Tool Fingerprinting ────────────────────────────────────────────────────────


def register_manifest(
    tenant_id: str,
    server_id: str,
    tools: list[dict[str, Any]],
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Register or update the tool manifest for a server.

    ``tools`` is a list of dicts, each describing one tool:
      - name (required)
      - description (optional)
      - input_schema (optional dict)

    Returns a summary of fingerprints registered and drift alerts raised.
    """
    init_db(db_path)
    now = _now()
    registered = []
    drift_alerts: list[dict[str, Any]] = []

    for tool in tools:
        tool_name = tool.get("name", "")
        if not tool_name:
            continue
        manifest_json = json.dumps(
            {
                "name": tool_name,
                "description": tool.get("description", ""),
                "input_schema": tool.get("input_schema") or {},
            },
            sort_keys=True,
        )
        fp_hash = hashlib.sha256(manifest_json.encode()).hexdigest()

        with _cursor(db_path) as cur:
            # Get the latest fingerprint for this tool
            existing = cur.execute(
                """
                SELECT * FROM gw_fingerprints
                 WHERE tenant_id = ? AND server_id = ? AND tool_name = ?
                 ORDER BY created_at DESC LIMIT 1
                """,
                (tenant_id, server_id, tool_name),
            ).fetchone()

            if existing is None:
                # First time we've seen this tool — register
                fp_id = str(uuid.uuid4())
                cur.execute(
                    """
                    INSERT OR IGNORE INTO gw_fingerprints
                        (fingerprint_id, tenant_id, server_id, tool_name,
                         manifest_json, hash, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (fp_id, tenant_id, server_id, tool_name, manifest_json, fp_hash, now),
                )
                registered.append({"tool_name": tool_name, "hash": fp_hash, "status": "new"})

            elif existing["hash"] != fp_hash:
                # Manifest changed — record the new version and raise a drift alert
                fp_id = str(uuid.uuid4())
                cur.execute(
                    """
                    INSERT OR IGNORE INTO gw_fingerprints
                        (fingerprint_id, tenant_id, server_id, tool_name,
                         manifest_json, hash, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (fp_id, tenant_id, server_id, tool_name, manifest_json, fp_hash, now),
                )
                alert_id = str(uuid.uuid4())
                cur.execute(
                    """
                    INSERT INTO gw_fp_alerts
                        (alert_id, tenant_id, server_id, tool_name,
                         old_hash, new_hash, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert_id,
                        tenant_id,
                        server_id,
                        tool_name,
                        existing["hash"],
                        fp_hash,
                        now,
                    ),
                )
                registered.append(
                    {"tool_name": tool_name, "hash": fp_hash, "status": "updated"}
                )
                drift_alerts.append(
                    {
                        "alert_id": alert_id,
                        "tool_name": tool_name,
                        "old_hash": existing["hash"],
                        "new_hash": fp_hash,
                    }
                )
            else:
                # Manifest unchanged
                registered.append(
                    {"tool_name": tool_name, "hash": fp_hash, "status": "unchanged"}
                )

    return {
        "server_id": server_id,
        "tenant_id": tenant_id,
        "tools_processed": len(registered),
        "drift_alerts_raised": len(drift_alerts),
        "registered": registered,
        "drift_alerts": drift_alerts,
    }


def get_fingerprint(
    tenant_id: str,
    server_id: str,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Return the current fingerprint snapshot for a server."""
    init_db(db_path)
    with _cursor(db_path) as cur:
        rows = cur.execute(
            """
            SELECT f1.*
              FROM gw_fingerprints f1
              JOIN (
                SELECT tool_name, MAX(created_at) AS latest
                  FROM gw_fingerprints
                 WHERE tenant_id = ? AND server_id = ?
                 GROUP BY tool_name
              ) f2 ON f1.tool_name = f2.tool_name
                   AND f1.created_at = f2.latest
                   AND f1.tenant_id = ?
                   AND f1.server_id = ?
            """,
            (tenant_id, server_id, tenant_id, server_id),
        ).fetchall()
    tools = [
        {
            "tool_name": r["tool_name"],
            "hash": r["hash"],
            "manifest": json.loads(r["manifest_json"]),
            "registered_at": r["created_at"],
        }
        for r in rows
    ]
    return {
        "server_id": server_id,
        "tenant_id": tenant_id,
        "tool_count": len(tools),
        "tools": tools,
    }


def list_fingerprint_alerts(
    tenant_id: str,
    *,
    server_id: str | None = None,
    resolved: bool = False,
    db_path: str = _DB_PATH,
) -> list[dict[str, Any]]:
    init_db(db_path)
    sql = "SELECT * FROM gw_fp_alerts WHERE tenant_id = ? AND resolved = ?"
    params: list[Any] = [tenant_id, int(resolved)]
    if server_id:
        sql += " AND server_id = ?"
        params.append(server_id)
    sql += " ORDER BY created_at DESC"
    with _cursor(db_path) as cur:
        rows = cur.execute(sql, params).fetchall()
    return [_row_to_fp_alert(r) for r in rows]


def resolve_fingerprint_alert(
    tenant_id: str,
    alert_id: str,
    resolved_by: str,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    init_db(db_path)
    now = _now()
    with _cursor(db_path) as cur:
        cur.execute(
            """
            UPDATE gw_fp_alerts
               SET resolved = 1, resolved_by = ?, resolved_at = ?
             WHERE alert_id = ? AND tenant_id = ? AND resolved = 0
            """,
            (resolved_by, now, alert_id, tenant_id),
        )
        row = cur.execute(
            "SELECT * FROM gw_fp_alerts WHERE alert_id = ? AND tenant_id = ?",
            (alert_id, tenant_id),
        ).fetchone()
    if row is None:
        raise KeyError(f"Fingerprint alert '{alert_id}' not found for tenant '{tenant_id}'")
    return _row_to_fp_alert(row)


def _row_to_fp_alert(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "alert_id": row["alert_id"],
        "tenant_id": row["tenant_id"],
        "server_id": row["server_id"],
        "tool_name": row["tool_name"],
        "old_hash": row["old_hash"],
        "new_hash": row["new_hash"],
        "created_at": row["created_at"],
        "resolved": bool(row["resolved"]),
        "resolved_by": row["resolved_by"],
        "resolved_at": row["resolved_at"],
    }


# ── Anomaly Detection ──────────────────────────────────────────────────────────


def _check_and_update_anomaly(
    *,
    tenant_id: str,
    agent_id: str,
    tool_name: str,
    session_id: str | None,
    db_path: str = _DB_PATH,
) -> dict[str, Any] | None:
    """Welford online algorithm — update baseline, check for anomaly.

    Returns an anomaly alert dict if a deviation was detected, else None.
    The alert is also persisted to gw_anomaly_alerts.
    """
    now = _now()

    with _cursor(db_path) as cur:
        row = cur.execute(
            """
            SELECT * FROM gw_anomaly_baselines
             WHERE tenant_id = ? AND agent_id = ? AND tool_name = ?
            """,
            (tenant_id, agent_id, tool_name),
        ).fetchone()

        if row is None:
            # First call — initialise baseline (count=1, mean=1.0, m2=0)
            baseline_id = str(uuid.uuid4())
            cur.execute(
                """
                INSERT INTO gw_anomaly_baselines
                    (baseline_id, tenant_id, agent_id, tool_name,
                     sample_count, mean, m2, last_updated)
                VALUES (?, ?, ?, ?, 1, 1.0, 0.0, ?)
                """,
                (baseline_id, tenant_id, agent_id, tool_name, now),
            )
            # First call — can't compute deviation yet, but flag as first_call
            alert = _record_anomaly_alert(
                cur=cur,
                tenant_id=tenant_id,
                agent_id=agent_id,
                tool_name=tool_name,
                session_id=session_id,
                expected_rate=0.0,
                actual_rate=1.0,
                z_score=0.0,
                first_call=True,
                now=now,
            )
            return alert
        else:
            # Welford update
            n = row["sample_count"] + 1
            old_mean = row["mean"]
            old_m2 = row["m2"]
            # Increment call count represents "one more call this observation"
            new_mean = old_mean + (1.0 - old_mean) / n
            new_m2 = old_m2 + (1.0 - old_mean) * (1.0 - new_mean)
            cur.execute(
                """
                UPDATE gw_anomaly_baselines
                   SET sample_count = ?, mean = ?, m2 = ?, last_updated = ?
                 WHERE tenant_id = ? AND agent_id = ? AND tool_name = ?
                """,
                (n, new_mean, new_m2, now, tenant_id, agent_id, tool_name),
            )

            # Need at least ANOMALY_MIN_SAMPLES to compute a useful z-score
            if n < ANOMALY_MIN_SAMPLES:
                return None

            variance = old_m2 / (n - 1) if n > 1 else 0.0
            stddev = math.sqrt(variance) if variance > 0 else 0.0
            if stddev == 0.0:
                return None  # All observations identical — no deviation possible

            # z-score: how many std devs is "1 call" from the mean?
            z = abs(1.0 - old_mean) / stddev

            if z < ANOMALY_Z_THRESHOLD:
                return None

            # Anomaly detected
            alert = _record_anomaly_alert(
                cur=cur,
                tenant_id=tenant_id,
                agent_id=agent_id,
                tool_name=tool_name,
                session_id=session_id,
                expected_rate=old_mean,
                actual_rate=1.0,
                z_score=z,
                first_call=False,
                now=now,
            )
            return alert


def _record_anomaly_alert(
    *,
    cur: sqlite3.Cursor,
    tenant_id: str,
    agent_id: str,
    tool_name: str,
    session_id: str | None,
    expected_rate: float,
    actual_rate: float,
    z_score: float,
    first_call: bool,
    now: str,
) -> dict[str, Any]:
    alert_id = str(uuid.uuid4())
    cur.execute(
        """
        INSERT INTO gw_anomaly_alerts
            (alert_id, tenant_id, agent_id, tool_name, session_id,
             expected_rate, actual_rate, z_score, first_call, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert_id,
            tenant_id,
            agent_id,
            tool_name,
            session_id,
            expected_rate,
            actual_rate,
            z_score,
            int(first_call),
            now,
        ),
    )
    return {
        "alert_id": alert_id,
        "agent_id": agent_id,
        "tool_name": tool_name,
        "expected_rate": expected_rate,
        "actual_rate": actual_rate,
        "z_score": z_score,
        "first_call": first_call,
    }


def get_anomaly_baseline(
    tenant_id: str,
    agent_id: str,
    *,
    db_path: str = _DB_PATH,
) -> list[dict[str, Any]]:
    """Return the learned baseline for all tools an agent has called."""
    init_db(db_path)
    with _cursor(db_path) as cur:
        rows = cur.execute(
            """
            SELECT * FROM gw_anomaly_baselines
             WHERE tenant_id = ? AND agent_id = ?
             ORDER BY tool_name
            """,
            (tenant_id, agent_id),
        ).fetchall()
    baselines = []
    for r in rows:
        n = r["sample_count"]
        variance = r["m2"] / (n - 1) if n > 1 else 0.0
        baselines.append(
            {
                "tool_name": r["tool_name"],
                "sample_count": n,
                "mean_call_rate": r["mean"],
                "stddev": math.sqrt(variance) if variance > 0 else 0.0,
                "last_updated": r["last_updated"],
            }
        )
    return baselines


def list_anomaly_alerts(
    tenant_id: str,
    *,
    acknowledged: bool = False,
    agent_id: str | None = None,
    db_path: str = _DB_PATH,
) -> list[dict[str, Any]]:
    init_db(db_path)
    sql = "SELECT * FROM gw_anomaly_alerts WHERE tenant_id = ? AND acknowledged = ?"
    params: list[Any] = [tenant_id, int(acknowledged)]
    if agent_id:
        sql += " AND agent_id = ?"
        params.append(agent_id)
    sql += " ORDER BY created_at DESC"
    with _cursor(db_path) as cur:
        rows = cur.execute(sql, params).fetchall()
    return [_row_to_anomaly_alert(r) for r in rows]


def acknowledge_anomaly_alert(
    tenant_id: str,
    alert_id: str,
    acknowledged_by: str,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    init_db(db_path)
    now = _now()
    with _cursor(db_path) as cur:
        cur.execute(
            """
            UPDATE gw_anomaly_alerts
               SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = ?
             WHERE alert_id = ? AND tenant_id = ?
            """,
            (acknowledged_by, now, alert_id, tenant_id),
        )
        row = cur.execute(
            "SELECT * FROM gw_anomaly_alerts WHERE alert_id = ? AND tenant_id = ?",
            (alert_id, tenant_id),
        ).fetchone()
    if row is None:
        raise KeyError(f"Anomaly alert '{alert_id}' not found for tenant '{tenant_id}'")
    return _row_to_anomaly_alert(row)


def _row_to_anomaly_alert(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "alert_id": row["alert_id"],
        "tenant_id": row["tenant_id"],
        "agent_id": row["agent_id"],
        "tool_name": row["tool_name"],
        "session_id": row["session_id"],
        "expected_rate": float(row["expected_rate"]),
        "actual_rate": float(row["actual_rate"]),
        "z_score": float(row["z_score"]),
        "first_call": bool(row["first_call"]),
        "created_at": row["created_at"],
        "acknowledged": bool(row["acknowledged"]),
        "acknowledged_by": row["acknowledged_by"],
        "acknowledged_at": row["acknowledged_at"],
    }


# ── Helpers ────────────────────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
