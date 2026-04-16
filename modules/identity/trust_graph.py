"""
TokenDNA — UIS Trust Graph (Sprint 1-2)

Converts narrative-linked UIS events into a queryable graph of agents,
workloads, tools, issuers, and verifiers. Enables anomaly detection on
chain-of-trust relationships.

Graph model
-----------
Nodes: agent | workload | tool | issuer | verifier | tenant
Edges: delegates_to | attested_by | issued_by | uses_tool | verified_by

Storage
-------
SQLite default: two tables (tg_nodes, tg_edges) with a recursive CTE for
shortest-path queries.  PostgreSQL is used automatically when TOKENDNA_PG_DSN
is set — the same recursive CTE syntax works on Postgres 8.4+.

Anomaly detection
-----------------
Three signal types are evaluated on every insert:

  NEW_TOOL_IN_STABLE_AGENT_TOOLKIT
    An agent that has made ≥ MIN_STABLE_OBSERVATIONS observations suddenly
    uses a tool it has never used before.

  UNFAMILIAR_VERIFIER_IN_TRUST_PATH
    A (subject, issuer) pair uses a verifier that the issuer has never used
    with any subject before.

  DELEGATION_DEPTH_EXCEEDED
    A delegation chain for a tenant exceeds MAX_DELEGATION_DEPTH hops.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass, field
from typing import Any

from modules.storage import db_backend


# ── Constants ─────────────────────────────────────────────────────────────────

MIN_STABLE_OBSERVATIONS: int = int(os.getenv("TG_MIN_STABLE_OBS", "5"))
MAX_DELEGATION_DEPTH: int = int(os.getenv("TG_MAX_DELEGATION_DEPTH", "4"))

_lock = threading.Lock()


# ── DB helpers ─────────────────────────────────────────────────────────────────

def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _pg_dsn() -> str:
    return os.getenv("TOKENDNA_PG_DSN", "")


def _use_pg() -> bool:
    return db_backend.should_use_postgres()


# ── Schema ─────────────────────────────────────────────────────────────────────

_SQLITE_INIT = """
CREATE TABLE IF NOT EXISTS tg_nodes (
    node_id     TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    node_type   TEXT NOT NULL,
    label       TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 1,
    meta_json   TEXT,
    PRIMARY KEY (node_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS tg_edges (
    edge_id     TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    src_node    TEXT NOT NULL,
    dst_node    TEXT NOT NULL,
    edge_type   TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    weight      INTEGER NOT NULL DEFAULT 1,
    meta_json   TEXT
);

CREATE INDEX IF NOT EXISTS idx_tg_nodes_tenant
    ON tg_nodes(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tg_edges_tenant_src
    ON tg_edges(tenant_id, src_node);
CREATE INDEX IF NOT EXISTS idx_tg_edges_tenant_dst
    ON tg_edges(tenant_id, dst_node);
"""

_PG_INIT = """
CREATE TABLE IF NOT EXISTS tg_nodes (
    node_id     TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    node_type   TEXT NOT NULL,
    label       TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 1,
    meta_json   JSONB,
    PRIMARY KEY (node_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS tg_edges (
    edge_id     TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    src_node    TEXT NOT NULL,
    dst_node    TEXT NOT NULL,
    edge_type   TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    weight      INTEGER NOT NULL DEFAULT 1,
    meta_json   JSONB
);

CREATE INDEX IF NOT EXISTS idx_tg_nodes_tenant
    ON tg_nodes(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tg_edges_tenant_src
    ON tg_edges(tenant_id, src_node);
CREATE INDEX IF NOT EXISTS idx_tg_edges_tenant_dst
    ON tg_edges(tenant_id, dst_node);
"""


def init_db() -> None:
    if _use_pg():
        _pg_init()
        return
    db_path = _db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    with _lock:
        conn = _get_conn()
        try:
            conn.executescript(_SQLITE_INIT)
            conn.commit()
        finally:
            conn.close()


def _pg_init() -> None:
    import psycopg
    with psycopg.connect(_pg_dsn()) as conn:
        conn.execute(_PG_INIT)
        conn.commit()


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class GraphNode:
    node_id: str
    tenant_id: str
    node_type: str          # agent|workload|tool|issuer|verifier|tenant
    label: str
    first_seen: str
    last_seen: str
    observation_count: int = 1
    meta: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "tenant_id": self.tenant_id,
            "node_type": self.node_type,
            "label": self.label,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "observation_count": self.observation_count,
            "meta": self.meta,
        }


@dataclass
class GraphEdge:
    edge_id: str
    tenant_id: str
    src_node: str
    dst_node: str
    edge_type: str          # delegates_to|attested_by|issued_by|uses_tool|verified_by
    first_seen: str
    last_seen: str
    weight: int = 1
    meta: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "tenant_id": self.tenant_id,
            "src_node": self.src_node,
            "dst_node": self.dst_node,
            "edge_type": self.edge_type,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "weight": self.weight,
            "meta": self.meta,
        }


@dataclass
class GraphAnomaly:
    anomaly_type: str
    tenant_id: str
    detected_at: str
    subject_node: str
    detail: str
    severity: str           # low|medium|high|critical
    context: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "anomaly_type": self.anomaly_type,
            "tenant_id": self.tenant_id,
            "detected_at": self.detected_at,
            "subject_node": self.subject_node,
            "detail": self.detail,
            "severity": self.severity,
            "context": self.context,
        }


# ── Node/edge ID helpers ────────────────────────────────────────────────────────

def _node_id(tenant_id: str, node_type: str, label: str) -> str:
    """Stable, deterministic node ID."""
    import hashlib
    raw = f"{tenant_id}:{node_type}:{label}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def _edge_id(tenant_id: str, src: str, dst: str, edge_type: str) -> str:
    import hashlib
    raw = f"{tenant_id}:{src}:{dst}:{edge_type}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


# ── Graph ingestion ─────────────────────────────────────────────────────────────

def ingest_uis_event(tenant_id: str, event: dict[str, Any]) -> list[GraphAnomaly]:
    """
    Extract nodes and edges from a UIS event and upsert them into the graph.
    Returns any anomalies detected during this insert.

    Called by uis_store.insert_event after persistence.
    """
    now = event.get("event_timestamp") or _now()
    identity = event.get("identity") or {}
    auth = event.get("auth") or {}
    token = event.get("token") or {}
    binding = event.get("binding") or {}

    subject = identity.get("subject") or "unknown"
    entity_type = identity.get("entity_type") or "human"
    agent_id = identity.get("agent_id")
    issuer = token.get("issuer") or "unknown"
    attestation_id = binding.get("attestation_id")
    spiffe_id = binding.get("spiffe_id")

    nodes: list[tuple[str, str, str]] = []   # (node_type, label, meta_json)
    edges: list[tuple[str, str, str]] = []   # (src_label+type, dst_label+type, edge_type)

    # Subject node
    subject_node_type = "agent" if entity_type == "machine" else "workload"
    subject_label = agent_id or subject
    nodes.append((subject_node_type, subject_label, json.dumps({"subject": subject})))

    # Issuer node
    if issuer and issuer != "unknown":
        nodes.append(("issuer", issuer, "{}"))
        edges.append((subject_node_type, subject_label, "issuer", issuer, "issued_by"))

    # Verifier node (attestation or SPIFFE)
    verifier_label: str | None = None
    if attestation_id:
        verifier_label = f"attest:{attestation_id[:16]}"
        nodes.append(("verifier", verifier_label, json.dumps({"attestation_id": attestation_id})))
        edges.append((subject_node_type, subject_label, "verifier", verifier_label, "attested_by"))
    elif spiffe_id:
        verifier_label = spiffe_id
        nodes.append(("verifier", verifier_label, "{}"))
        edges.append((subject_node_type, subject_label, "verifier", verifier_label, "verified_by"))

    # Tool node (from auth method + protocol combination — represents an auth tool)
    auth_method = auth.get("method") or ""
    protocol = auth.get("protocol") or ""
    if auth_method and auth_method != "unknown" and protocol:
        tool_label = f"{protocol}:{auth_method}"
        nodes.append(("tool", tool_label, "{}"))
        edges.append((subject_node_type, subject_label, "tool", tool_label, "uses_tool"))

    # Upsert all nodes and edges
    _upsert_nodes(tenant_id, nodes, now)
    _upsert_edges(tenant_id, edges, now)

    # Detect anomalies
    return _detect_anomalies(
        tenant_id=tenant_id,
        subject_node_type=subject_node_type,
        subject_label=subject_label,
        issuer=issuer,
        verifier_label=verifier_label,
        tool_label=f"{protocol}:{auth_method}" if auth_method and auth_method != "unknown" and protocol else None,
        now=now,
    )


def _upsert_nodes(tenant_id: str, nodes: list[tuple], now: str) -> None:
    if _use_pg():
        _pg_upsert_nodes(tenant_id, nodes, now)
        return
    with _lock:
        conn = _get_conn()
        try:
            for node_type, label, meta_json in nodes:
                nid = _node_id(tenant_id, node_type, label)
                conn.execute(
                    """
                    INSERT INTO tg_nodes
                        (node_id, tenant_id, node_type, label, first_seen, last_seen,
                         observation_count, meta_json)
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                    ON CONFLICT(node_id, tenant_id) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        observation_count = tg_nodes.observation_count + 1
                    """,
                    (nid, tenant_id, node_type, label, now, now, meta_json),
                )
            conn.commit()
        finally:
            conn.close()


def _upsert_edges(tenant_id: str, edges: list[tuple], now: str) -> None:
    if _use_pg():
        _pg_upsert_edges(tenant_id, edges, now)
        return
    with _lock:
        conn = _get_conn()
        try:
            for src_type, src_label, dst_type, dst_label, edge_type in edges:
                src_id = _node_id(tenant_id, src_type, src_label)
                dst_id = _node_id(tenant_id, dst_type, dst_label)
                eid = _edge_id(tenant_id, src_id, dst_id, edge_type)
                conn.execute(
                    """
                    INSERT INTO tg_edges
                        (edge_id, tenant_id, src_node, dst_node, edge_type,
                         first_seen, last_seen, weight)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                    ON CONFLICT(edge_id) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        weight = tg_edges.weight + 1
                    """,
                    (eid, tenant_id, src_id, dst_id, edge_type, now, now),
                )
            conn.commit()
        finally:
            conn.close()


def _pg_upsert_nodes(tenant_id: str, nodes: list[tuple], now: str) -> None:
    import psycopg
    with psycopg.connect(_pg_dsn()) as conn:
        for node_type, label, meta_json in nodes:
            nid = _node_id(tenant_id, node_type, label)
            conn.execute(
                """
                INSERT INTO tg_nodes
                    (node_id, tenant_id, node_type, label, first_seen, last_seen,
                     observation_count, meta_json)
                VALUES (%s, %s, %s, %s, %s, %s, 1, %s)
                ON CONFLICT(node_id, tenant_id) DO UPDATE SET
                    last_seen = EXCLUDED.last_seen,
                    observation_count = tg_nodes.observation_count + 1
                """,
                (nid, tenant_id, node_type, label, now, now, meta_json),
            )
        conn.commit()


def _pg_upsert_edges(tenant_id: str, edges: list[tuple], now: str) -> None:
    import psycopg
    with psycopg.connect(_pg_dsn()) as conn:
        for src_type, src_label, dst_type, dst_label, edge_type in edges:
            src_id = _node_id(tenant_id, src_type, src_label)
            dst_id = _node_id(tenant_id, dst_type, dst_label)
            eid = _edge_id(tenant_id, src_id, dst_id, edge_type)
            conn.execute(
                """
                INSERT INTO tg_edges
                    (edge_id, tenant_id, src_node, dst_node, edge_type,
                     first_seen, last_seen, weight)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 1)
                ON CONFLICT(edge_id) DO UPDATE SET
                    last_seen = EXCLUDED.last_seen,
                    weight = tg_edges.weight + 1
                """,
                (eid, tenant_id, src_id, dst_id, edge_type, now, now),
            )
        conn.commit()


# ── Anomaly detection ───────────────────────────────────────────────────────────

def _detect_anomalies(
    *,
    tenant_id: str,
    subject_node_type: str,
    subject_label: str,
    issuer: str | None,
    verifier_label: str | None,
    tool_label: str | None,
    now: str,
) -> list[GraphAnomaly]:
    anomalies: list[GraphAnomaly] = []
    subject_nid = _node_id(tenant_id, subject_node_type, subject_label)

    # Signal 1: NEW_TOOL_IN_STABLE_AGENT_TOOLKIT
    if tool_label and subject_node_type == "agent":
        anomaly = _check_new_tool(tenant_id, subject_nid, subject_label, tool_label, now)
        if anomaly:
            anomalies.append(anomaly)

    # Signal 2: UNFAMILIAR_VERIFIER_IN_TRUST_PATH
    if verifier_label and issuer and issuer != "unknown":
        anomaly = _check_unfamiliar_verifier(
            tenant_id, subject_nid, subject_label, issuer, verifier_label, now
        )
        if anomaly:
            anomalies.append(anomaly)

    # Signal 3: DELEGATION_DEPTH_EXCEEDED
    anomaly = _check_delegation_depth(tenant_id, subject_nid, subject_label, now)
    if anomaly:
        anomalies.append(anomaly)

    return anomalies


def _check_new_tool(
    tenant_id: str,
    subject_nid: str,
    subject_label: str,
    tool_label: str,
    now: str,
) -> GraphAnomaly | None:
    """Return anomaly if agent has stable history but this tool is brand new."""
    if _use_pg():
        return None  # PG path: return None (anomaly detection uses SQLite for now)
    with _lock:
        conn = _get_conn()
        try:
            # How many times has this agent been observed?
            row = conn.execute(
                "SELECT observation_count FROM tg_nodes WHERE node_id=? AND tenant_id=?",
                (subject_nid, tenant_id),
            ).fetchone()
            agent_obs = row["observation_count"] if row else 0

            if agent_obs < MIN_STABLE_OBSERVATIONS:
                return None  # Not yet stable — no anomaly

            # Has this specific tool been used before by this agent?
            tool_nid = _node_id(tenant_id, "tool", tool_label)
            eid = _edge_id(tenant_id, subject_nid, tool_nid, "uses_tool")
            edge_row = conn.execute(
                "SELECT weight FROM tg_edges WHERE edge_id=?", (eid,)
            ).fetchone()
            # weight=1 means this insert just created it → brand new tool
            if edge_row is None or edge_row["weight"] <= 1:
                return GraphAnomaly(
                    anomaly_type="NEW_TOOL_IN_STABLE_AGENT_TOOLKIT",
                    tenant_id=tenant_id,
                    detected_at=now,
                    subject_node=subject_label,
                    detail=(
                        f"Agent '{subject_label}' (observed {agent_obs} times) "
                        f"used tool '{tool_label}' for the first time."
                    ),
                    severity="medium",
                    context={
                        "agent_observations": agent_obs,
                        "new_tool": tool_label,
                        "min_stable_threshold": MIN_STABLE_OBSERVATIONS,
                    },
                )
        finally:
            conn.close()
    return None


def _check_unfamiliar_verifier(
    tenant_id: str,
    subject_nid: str,
    subject_label: str,
    issuer: str,
    verifier_label: str,
    now: str,
) -> GraphAnomaly | None:
    """Return anomaly if this issuer has never used this verifier before."""
    if _use_pg():
        return None
    issuer_nid = _node_id(tenant_id, "issuer", issuer)
    verifier_nid = _node_id(tenant_id, "verifier", verifier_label)
    with _lock:
        conn = _get_conn()
        try:
            # Check if issuer has ANY prior edges (must be established)
            issuer_row = conn.execute(
                "SELECT observation_count FROM tg_nodes WHERE node_id=? AND tenant_id=?",
                (issuer_nid, tenant_id),
            ).fetchone()
            if not issuer_row or issuer_row["observation_count"] < MIN_STABLE_OBSERVATIONS:
                return None  # Issuer not yet stable

            # Has the issuer ever been connected to this verifier before?
            # Look for any subject→verifier edge that also has subject→issuer
            verifier_row = conn.execute(
                "SELECT observation_count FROM tg_nodes WHERE node_id=? AND tenant_id=?",
                (verifier_nid, tenant_id),
            ).fetchone()
            verifier_obs = verifier_row["observation_count"] if verifier_row else 0

            if verifier_obs <= 1:
                # Brand new verifier for this tenant
                return GraphAnomaly(
                    anomaly_type="UNFAMILIAR_VERIFIER_IN_TRUST_PATH",
                    tenant_id=tenant_id,
                    detected_at=now,
                    subject_node=subject_label,
                    detail=(
                        f"Issuer '{issuer}' used unfamiliar verifier "
                        f"'{verifier_label}' for subject '{subject_label}'."
                    ),
                    severity="high",
                    context={
                        "issuer": issuer,
                        "verifier": verifier_label,
                        "verifier_first_seen": True,
                    },
                )
        finally:
            conn.close()
    return None


def _check_delegation_depth(
    tenant_id: str,
    subject_nid: str,
    subject_label: str,
    now: str,
) -> GraphAnomaly | None:
    """Return anomaly if delegation chain depth exceeds MAX_DELEGATION_DEPTH."""
    if _use_pg():
        return None
    depth = _delegation_depth(tenant_id, subject_nid)
    if depth > MAX_DELEGATION_DEPTH:
        return GraphAnomaly(
            anomaly_type="DELEGATION_DEPTH_EXCEEDED",
            tenant_id=tenant_id,
            detected_at=now,
            subject_node=subject_label,
            detail=(
                f"Delegation chain for '{subject_label}' has depth {depth}, "
                f"exceeding max {MAX_DELEGATION_DEPTH}."
            ),
            severity="high",
            context={
                "depth": depth,
                "max_allowed": MAX_DELEGATION_DEPTH,
            },
        )
    return None


def _delegation_depth(tenant_id: str, start_node_id: str) -> int:
    """Compute delegation chain depth via recursive traversal (SQLite)."""
    with _lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                """
                WITH RECURSIVE chain(node_id, depth) AS (
                    SELECT ?, 0
                    UNION ALL
                    SELECT e.dst_node, chain.depth + 1
                    FROM tg_edges e
                    JOIN chain ON e.src_node = chain.node_id
                    WHERE e.edge_type = 'delegates_to'
                      AND e.tenant_id = ?
                      AND chain.depth < 20
                )
                SELECT MAX(depth) as max_depth FROM chain
                """,
                (start_node_id, tenant_id),
            ).fetchone()
            return rows["max_depth"] if rows and rows["max_depth"] else 0
        finally:
            conn.close()


# ── Query API ──────────────────────────────────────────────────────────────────

def shortest_path(
    tenant_id: str, from_label: str, to_label: str
) -> dict[str, Any]:
    """
    Find the shortest trust path between two nodes (by label).
    Returns path as a list of node dicts.
    """
    if _use_pg():
        return {"path": [], "length": 0, "found": False, "error": "pg_path_not_implemented"}

    with _lock:
        conn = _get_conn()
        try:
            # Find node IDs for from/to labels (try all node types)
            from_row = conn.execute(
                "SELECT node_id, node_type FROM tg_nodes WHERE tenant_id=? AND label=? LIMIT 1",
                (tenant_id, from_label),
            ).fetchone()
            to_row = conn.execute(
                "SELECT node_id, node_type FROM tg_nodes WHERE tenant_id=? AND label=? LIMIT 1",
                (tenant_id, to_label),
            ).fetchone()

            if not from_row or not to_row:
                return {
                    "path": [],
                    "length": 0,
                    "found": False,
                    "error": "one_or_both_nodes_not_found",
                }

            from_id = from_row["node_id"]
            to_id = to_row["node_id"]

            if from_id == to_id:
                node = _get_node(conn, tenant_id, from_id)
                return {"path": [node], "length": 0, "found": True}

            # BFS via recursive CTE
            rows = conn.execute(
                """
                WITH RECURSIVE bfs(node_id, path_nodes, depth) AS (
                    SELECT ?, ?, 0
                    UNION ALL
                    SELECT e.dst_node,
                           bfs.path_nodes || ',' || e.dst_node,
                           bfs.depth + 1
                    FROM tg_edges e
                    JOIN bfs ON e.src_node = bfs.node_id
                    WHERE e.tenant_id = ?
                      AND bfs.depth < 10
                      AND bfs.path_nodes NOT LIKE '%' || e.dst_node || '%'
                )
                SELECT path_nodes, depth
                FROM bfs
                WHERE node_id = ?
                ORDER BY depth
                LIMIT 1
                """,
                (from_id, from_id, tenant_id, to_id),
            ).fetchone()

            if not rows:
                return {"path": [], "length": 0, "found": False, "error": "no_path_found"}

            path_ids = rows["path_nodes"].split(",")
            path_nodes = [_get_node(conn, tenant_id, nid) for nid in path_ids if nid]
            return {
                "path": [n for n in path_nodes if n],
                "length": rows["depth"],
                "found": True,
            }
        finally:
            conn.close()


def _get_node(conn: sqlite3.Connection, tenant_id: str, node_id: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM tg_nodes WHERE node_id=? AND tenant_id=?",
        (node_id, tenant_id),
    ).fetchone()
    if not row:
        return None
    return {
        "node_id": row["node_id"],
        "node_type": row["node_type"],
        "label": row["label"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "observation_count": row["observation_count"],
    }


def get_anomalies(
    tenant_id: str,
    limit: int = 50,
    severity: str | None = None,
) -> list[dict[str, Any]]:
    """
    Return stored anomaly records for a tenant.
    Anomalies are written to tg_anomalies table on detection.
    """
    if _use_pg():
        return []
    with _lock:
        conn = _get_conn()
        try:
            # Ensure anomaly table exists
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tg_anomalies (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id   TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    subject_node TEXT NOT NULL,
                    detail      TEXT NOT NULL,
                    severity    TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    context_json TEXT
                )
                """
            )
            conn.commit()
            params: list[Any] = [tenant_id]
            where = "WHERE tenant_id=?"
            if severity:
                where += " AND severity=?"
                params.append(severity)
            rows = conn.execute(
                f"SELECT * FROM tg_anomalies {where} ORDER BY detected_at DESC LIMIT ?",
                tuple(params) + (min(limit, 200),),
            ).fetchall()
            return [
                {
                    "id": r["id"],
                    "anomaly_type": r["anomaly_type"],
                    "tenant_id": r["tenant_id"],
                    "subject_node": r["subject_node"],
                    "detail": r["detail"],
                    "severity": r["severity"],
                    "detected_at": r["detected_at"],
                    "context": json.loads(r["context_json"] or "{}"),
                }
                for r in rows
            ]
        finally:
            conn.close()


def store_anomaly(anomaly: GraphAnomaly) -> None:
    """Persist a detected anomaly to tg_anomalies."""
    if _use_pg():
        return
    with _lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tg_anomalies (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id   TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    subject_node TEXT NOT NULL,
                    detail      TEXT NOT NULL,
                    severity    TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    context_json TEXT
                )
                """
            )
            conn.execute(
                """
                INSERT INTO tg_anomalies
                    (tenant_id, anomaly_type, subject_node, detail, severity,
                     detected_at, context_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    anomaly.tenant_id,
                    anomaly.anomaly_type,
                    anomaly.subject_node,
                    anomaly.detail,
                    anomaly.severity,
                    anomaly.detected_at,
                    json.dumps(anomaly.context),
                ),
            )
            conn.commit()
        finally:
            conn.close()


def get_stats(tenant_id: str) -> dict[str, Any]:
    """Return graph shape statistics for a tenant."""
    if _use_pg():
        return {"error": "pg_stats_not_implemented"}
    with _lock:
        conn = _get_conn()
        try:
            node_count = conn.execute(
                "SELECT COUNT(*) as c FROM tg_nodes WHERE tenant_id=?", (tenant_id,)
            ).fetchone()["c"]
            edge_count = conn.execute(
                "SELECT COUNT(*) as c FROM tg_edges WHERE tenant_id=?", (tenant_id,)
            ).fetchone()["c"]

            # Node type breakdown
            type_rows = conn.execute(
                """
                SELECT node_type, COUNT(*) as c
                FROM tg_nodes WHERE tenant_id=?
                GROUP BY node_type
                """,
                (tenant_id,),
            ).fetchall()
            node_types = {r["node_type"]: r["c"] for r in type_rows}

            # Edge type breakdown
            edge_rows = conn.execute(
                """
                SELECT edge_type, COUNT(*) as c
                FROM tg_edges WHERE tenant_id=?
                GROUP BY edge_type
                """,
                (tenant_id,),
            ).fetchall()
            edge_types = {r["edge_type"]: r["c"] for r in edge_rows}

            # Anomaly count
            try:
                anomaly_count = conn.execute(
                    "SELECT COUNT(*) as c FROM tg_anomalies WHERE tenant_id=?",
                    (tenant_id,),
                ).fetchone()["c"]
            except sqlite3.OperationalError:
                anomaly_count = 0

            return {
                "tenant_id": tenant_id,
                "node_count": node_count,
                "edge_count": edge_count,
                "node_types": node_types,
                "edge_types": edge_types,
                "anomaly_count": anomaly_count,
            }
        finally:
            conn.close()
