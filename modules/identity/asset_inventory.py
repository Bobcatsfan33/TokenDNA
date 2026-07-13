"""AI Workflow Scanner + Asset Inventory (Gap roadmap Epic 3.1 / Challenge C1).

Zscaler-style "AI Asset Management": ingest an agent workflow definition
(LangGraph / OpenAI-Agents / CrewAI / AutoGen) and/or MCP manifests, enumerate
the **Agents / Tools / MCP Servers / Vulnerabilities**, and track them over time
with scan history.

The scanner is format-tolerant: it detects the framework from the payload shape
(or an explicit ``framework`` field) and normalizes to one inventory model. The
vulnerability rules encode the NSA MCP advisory (unauthenticated MCP, missing
observability, unconstrained tools, self-modification, cascading-injection
surface).
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Optional

from modules.storage.ddl_runner import run_ddl
from modules.storage.pg_connection import AdaptedCursor, get_db_conn

_DB_PATH = os.getenv("DATA_DB_PATH", os.path.expanduser("~/.tokendna/tokendna.db"))
_lock = threading.Lock()
_initialized_paths: set[str] = set()

# Inventory item kinds.
AGENT = "agent"
TOOL = "tool"
MCP_SERVER = "mcp_server"
VULNERABILITY = "vulnerability"

_DDL = (
    """
    CREATE TABLE IF NOT EXISTS asset_scans (
        scan_id      TEXT PRIMARY KEY,
        tenant_id    TEXT NOT NULL,
        source       TEXT NOT NULL,
        framework    TEXT NOT NULL,
        scanned_at   TEXT NOT NULL,
        agents       INTEGER NOT NULL DEFAULT 0,
        tools        INTEGER NOT NULL DEFAULT 0,
        mcp_servers  INTEGER NOT NULL DEFAULT 0,
        vulnerabilities INTEGER NOT NULL DEFAULT 0
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_asset_scans_tenant ON asset_scans(tenant_id, scanned_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS asset_items (
        item_id    TEXT PRIMARY KEY,
        scan_id    TEXT NOT NULL,
        tenant_id  TEXT NOT NULL,
        kind       TEXT NOT NULL,
        name       TEXT NOT NULL,
        severity   TEXT,
        meta_json  TEXT NOT NULL DEFAULT '{}'
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_asset_items_scan ON asset_items(scan_id, kind)",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db(db_path: str = _DB_PATH) -> None:
    if db_path in _initialized_paths:
        return
    with _lock:
        if db_path in _initialized_paths:
            return
        run_ddl(_DDL, db_path)
        _initialized_paths.add(db_path)


@contextmanager
def _cursor(db_path: str = _DB_PATH):
    with get_db_conn(db_path=db_path) as conn:
        yield AdaptedCursor(conn.cursor())


# ── Framework detection + normalization ───────────────────────────────────────

def detect_framework(definition: dict[str, Any]) -> str:
    """Best-effort framework detection from the payload shape."""
    explicit = str(definition.get("framework", "")).strip().lower()
    if explicit:
        return explicit
    if "nodes" in definition and "edges" in definition:
        return "langgraph"
    if "crew" in definition or "tasks" in definition:
        return "crewai"
    if "agents" in definition and any("system_message" in a for a in definition.get("agents", []) if isinstance(a, dict)):
        return "autogen"
    if "agents" in definition:
        return "openai-agents"
    if "servers" in definition or "mcp_servers" in definition:
        return "mcp-manifest"
    return "unknown"


def _agent_entries(definition: dict[str, Any], framework: str) -> list[dict[str, Any]]:
    if framework == "langgraph":
        return [n for n in definition.get("nodes", []) if isinstance(n, dict)]
    return [a for a in definition.get("agents", []) if isinstance(a, dict)]


def _agent_name(entry: dict[str, Any]) -> str:
    return str(entry.get("name") or entry.get("id") or entry.get("role") or "unnamed-agent")


def _agent_tools(entry: dict[str, Any]) -> list[dict[str, Any]]:
    tools = entry.get("tools") or entry.get("functions") or []
    out = []
    for t in tools:
        if isinstance(t, str):
            out.append({"name": t})
        elif isinstance(t, dict):
            out.append(t)
    return out


def _tool_name(t: dict[str, Any]) -> str:
    return str(t.get("name") or t.get("function") or t.get("type") or "unnamed-tool")


def _mcp_entries(definition: dict[str, Any]) -> list[dict[str, Any]]:
    servers = definition.get("mcp_servers") or definition.get("servers") or []
    return [s for s in servers if isinstance(s, dict)]


def _mcp_name(s: dict[str, Any]) -> str:
    return str(s.get("name") or s.get("url") or s.get("id") or "unnamed-mcp")


# ── Vulnerability rules (NSA MCP advisory) ────────────────────────────────────

def _scan_vulns(agents: list[dict[str, Any]], tools: list[dict[str, Any]],
                mcp_servers: list[dict[str, Any]], definition: dict[str, Any]) -> list[dict[str, Any]]:
    vulns: list[dict[str, Any]] = []

    def add(rule, sev, target, detail):
        vulns.append({"name": rule, "severity": sev, "target": target, "detail": detail})

    # 1) Unauthenticated MCP server (advisory: MCP lacks required auth).
    for s in mcp_servers:
        auth = str(s.get("auth") or s.get("authentication") or "none").lower()
        if auth in ("none", "", "false", "anonymous"):
            add("unauthenticated_mcp_server", "high", _mcp_name(s),
                "MCP server exposes tools without authentication (NSA advisory: MCP lacks required auth)")

    # 2) Missing observability/audit (advisory: standardized audit logging).
    obs = definition.get("observability") or definition.get("logging") or definition.get("audit")
    if not obs:
        add("missing_observability", "medium", "workflow",
            "no audit/observability configured for tool invocations (NSA advisory: standardized audit logging)")

    # 3) Unconstrained tool (no input schema / wildcard scope).
    for t in tools:
        schema = t.get("input_schema") or t.get("parameters") or t.get("schema")
        scope = str(t.get("scope") or "").strip()
        if schema is None and scope in ("", "*", "all"):
            add("unconstrained_tool", "medium", _tool_name(t),
                "tool has no declared input schema or scope — broad attack surface")

    # 4) Self-modification risk (agent can change its own policy/permissions).
    for a in agents:
        names = " ".join(_tool_name(t).lower() for t in _agent_tools(a))
        if any(k in names for k in ("update_policy", "modify_policy", "set_permissions",
                                    "grant", "iam", "admin")):
            add("self_modification_risk", "high", _agent_name(a),
                "agent holds a tool that can alter policy/permissions (self-governance bypass)")

    # 5) Cascading-injection surface: >=2 agents sharing a tool/MCP (multi-agent
    #    pipeline where a poisoned output feeds the next agent).
    if len(agents) >= 2 and (tools or mcp_servers):
        add("cascading_injection_surface", "medium", "workflow",
            f"{len(agents)} chained agents share tools/MCP — cascading prompt-injection surface "
            "(NSA advisory: cascading injection across multi-agent pipelines)")

    return vulns


# ── Scan ──────────────────────────────────────────────────────────────────────

def scan_workflow(
    *,
    tenant_id: str,
    definition: dict[str, Any],
    source: str = "upload",
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Scan an agent-workflow definition → inventory + persisted scan record."""
    if not isinstance(definition, dict):
        raise ValueError("definition must be an object")
    init_db(db_path)
    framework = detect_framework(definition)

    agent_entries = _agent_entries(definition, framework)
    agents = [{"name": _agent_name(a), "tool_count": len(_agent_tools(a)),
               "framework": framework} for a in agent_entries]

    # De-dup tools by name across agents + a top-level tools list.
    tool_map: dict[str, dict[str, Any]] = {}
    for a in agent_entries:
        for t in _agent_tools(a):
            tool_map.setdefault(_tool_name(t), t)
    for t in definition.get("tools", []) or []:
        if isinstance(t, dict):
            tool_map.setdefault(_tool_name(t), t)
        elif isinstance(t, str):
            tool_map.setdefault(t, {"name": t})
    tools = [{"name": n, **({} if not isinstance(v, dict) else {k: v[k] for k in v if k != "name"})}
             for n, v in tool_map.items()]

    mcp_entries = _mcp_entries(definition)
    mcp_servers = [{"name": _mcp_name(s), "tool_count": len(s.get("tools", []) or [])}
                   for s in mcp_entries]

    vulns = _scan_vulns(agent_entries, list(tool_map.values()), mcp_entries, definition)

    scan_id = str(uuid.uuid4())
    now = _now()
    with _cursor(db_path) as cur:
        cur.execute(
            """
            INSERT INTO asset_scans
                (scan_id, tenant_id, source, framework, scanned_at,
                 agents, tools, mcp_servers, vulnerabilities)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (scan_id, tenant_id, source, framework, now,
             len(agents), len(tools), len(mcp_servers), len(vulns)),
        )
        for kind, items in ((AGENT, agents), (TOOL, tools), (MCP_SERVER, mcp_servers)):
            for it in items:
                cur.execute(
                    "INSERT INTO asset_items (item_id, scan_id, tenant_id, kind, name, severity, meta_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), scan_id, tenant_id, kind, it["name"], None, json.dumps(it)),
                )
        for v in vulns:
            cur.execute(
                "INSERT INTO asset_items (item_id, scan_id, tenant_id, kind, name, severity, meta_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), scan_id, tenant_id, VULNERABILITY, v["name"], v["severity"], json.dumps(v)),
            )

    return {
        "scan_id": scan_id,
        "tenant_id": tenant_id,
        "source": source,
        "framework": framework,
        "scanned_at": now,
        "counts": {"agents": len(agents), "tools": len(tools),
                   "mcp_servers": len(mcp_servers), "vulnerabilities": len(vulns)},
        "agents": agents,
        "tools": tools,
        "mcp_servers": mcp_servers,
        "vulnerabilities": vulns,
    }


def list_scans(*, tenant_id: str, limit: int = 50, db_path: str = _DB_PATH) -> list[dict[str, Any]]:
    init_db(db_path)
    with _cursor(db_path) as cur:
        rows = cur.execute(
            "SELECT scan_id, source, framework, scanned_at, agents, tools, mcp_servers, vulnerabilities "
            "FROM asset_scans WHERE tenant_id=? ORDER BY scanned_at DESC LIMIT ?",
            (tenant_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan(*, tenant_id: str, scan_id: str, kind: Optional[str] = None,
             db_path: str = _DB_PATH) -> dict[str, Any]:
    init_db(db_path)
    with _cursor(db_path) as cur:
        scan = cur.execute(
            "SELECT * FROM asset_scans WHERE tenant_id=? AND scan_id=?",
            (tenant_id, scan_id),
        ).fetchone()
        if not scan:
            raise KeyError(f"scan {scan_id} not found")
        q = "SELECT kind, name, severity, meta_json FROM asset_items WHERE scan_id=? AND tenant_id=?"
        args: list[Any] = [scan_id, tenant_id]
        if kind:
            q += " AND kind=?"
            args.append(kind)
        items = cur.execute(q, tuple(args)).fetchall()
    grouped: dict[str, list[dict[str, Any]]] = {AGENT: [], TOOL: [], MCP_SERVER: [], VULNERABILITY: []}
    for it in items:
        grouped.setdefault(it["kind"], []).append({
            "name": it["name"], "severity": it["severity"], **json.loads(it["meta_json"] or "{}"),
        })
    return {"scan": dict(scan), "items": grouped}
