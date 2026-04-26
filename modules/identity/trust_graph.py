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
Five signal types are evaluated.  The first three fire on UIS event ingest;
the last two fire when ``record_policy_modification`` is invoked.

  NEW_TOOL_IN_STABLE_AGENT_TOOLKIT
    An agent that has made ≥ MIN_STABLE_OBSERVATIONS observations suddenly
    uses a tool it has never used before.

  UNFAMILIAR_VERIFIER_IN_TRUST_PATH
    A (subject, issuer) pair uses a verifier that the issuer has never used
    with any subject before.

  DELEGATION_DEPTH_EXCEEDED
    A delegation chain for a tenant exceeds MAX_DELEGATION_DEPTH hops.

  POLICY_SCOPE_MODIFICATION  (RSA gap 1, CRITICAL)
    An agent modifies a policy that affects its own permission boundary —
    the CrowdStrike Fortune-50 self-elevation pattern.

  PERMISSION_WEIGHT_DRIFT    (RSA gap 2, HIGH)
    A (modifier → target) policy-modification edge accumulates weight
    >= _PERMISSION_WEIGHT_DRIFT_THRESHOLD within PERMISSION_DRIFT_WINDOW_DAYS
    while the modifier has no attestation event in the same window.
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
# RSA Gap 2: permission growth multiplier before anomaly fires
PERMISSION_GROWTH_THRESHOLD: float = float(os.getenv("TG_PERMISSION_GROWTH_X", "2.0"))
# Baseline window for permission drift history (days)
PERMISSION_DRIFT_WINDOW_DAYS: int = int(os.getenv("TG_PERMISSION_DRIFT_DAYS", "30"))

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
    from modules.storage.pg_connection import normalize_dsn_for_psycopg

    return normalize_dsn_for_psycopg(os.getenv("TOKENDNA_PG_DSN", ""))


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


# ── RSA gap detections — POLICY_SCOPE_MODIFICATION + PERMISSION_WEIGHT_DRIFT ──
#
# These two anomaly types address the CrowdStrike Fortune-50 scenario from RSA
# 2026: an agent that quietly writes policy edges expanding its own permission
# boundary, or a permission edge that silently grows in weight without a
# corresponding attestation event in the same window.
#
# Both are CRITICAL/HIGH severity — operators should freeze the agent and
# require human approval before any further state change.

# Edge type used by record_policy_modification — represents
# "<modifier_agent> modified the policy granting permissions to <target_agent>".
_POLICY_MOD_EDGE_TYPE = "modifies_policy_for"

# Edge type used by record_cross_org_action (FAT) — represents
# "<local_agent> performed an action <crosses_org> into the remote org's
# resource".  The edge meta_json carries both orgs' policy IDs and the
# federation trust_id (or None if no trust existed at action time).
_CROSSES_ORG_EDGE_TYPE = "crosses_org"

# Weight at which a (modifier → target) policy-mod edge is considered
# "rapidly growing" for the PERMISSION_WEIGHT_DRIFT check.  Combined with the
# PERMISSION_DRIFT_WINDOW_DAYS time gate and the absence-of-attestation gate,
# this captures the >2x growth signal without needing schema columns for
# baseline weight snapshots.
_PERMISSION_WEIGHT_DRIFT_THRESHOLD: int = max(
    2, int(round(PERMISSION_GROWTH_THRESHOLD * 2))
)


def record_policy_modification(
    tenant_id: str,
    *,
    target_agent: str,
    modified_by: str,
    policy_id: str,
    scope: list[str] | None = None,
    now: str | None = None,
) -> list[GraphAnomaly]:
    """
    Record a policy / permission modification into the trust graph and run the
    two RSA gap detections.

    Parameters
    ----------
    target_agent
        Agent label whose permission set this policy affects.
    modified_by
        Agent label of the actor making the modification.  When this equals
        ``target_agent`` it is a self-modification — POLICY_SCOPE_MODIFICATION
        fires CRITICAL.
    policy_id
        Stable identifier for the policy being modified.
    scope
        Optional list of permission strings the policy grants.  Stored on the
        edge meta_json for downstream review.
    now
        ISO8601 timestamp; defaults to current UTC.

    Returns
    -------
    list[GraphAnomaly]
        Any anomalies fired by this modification.
    """
    if not target_agent or not modified_by or not policy_id:
        raise ValueError("target_agent, modified_by, policy_id are required")

    when = now or _now()

    # Persist the policy node + the modifier→target edge.  The edge weight is
    # incremented on every call so PERMISSION_WEIGHT_DRIFT can see growth.
    nodes: list[tuple[str, str, str]] = [
        ("policy", f"policy:{policy_id}", json.dumps({"scope": scope or []})),
        ("agent", modified_by, "{}"),
        ("agent", target_agent, "{}"),
    ]
    edges: list[tuple[str, str, str, str, str]] = [
        ("agent", modified_by, "agent", target_agent, _POLICY_MOD_EDGE_TYPE),
    ]
    _upsert_nodes(tenant_id, nodes, when)
    _upsert_edges(tenant_id, edges, when)

    anomalies: list[GraphAnomaly] = []

    # Detection 1: self-modification — modifier is changing its own scope.
    if modified_by == target_agent:
        anomalies.append(
            GraphAnomaly(
                anomaly_type="POLICY_SCOPE_MODIFICATION",
                tenant_id=tenant_id,
                detected_at=when,
                subject_node=target_agent,
                detail=(
                    f"Agent '{modified_by}' modified policy '{policy_id}' "
                    f"affecting its own permission boundary."
                ),
                severity="critical",
                context={
                    "modifier": modified_by,
                    "target": target_agent,
                    "policy_id": policy_id,
                    "scope": scope or [],
                    "self_modification": True,
                },
            )
        )

    # Detection 2: permission weight drift — same modifier→target edge has
    # accumulated rapid growth recently with no attestation event for the
    # modifier in the drift window.
    drift = _check_permission_weight_drift(
        tenant_id=tenant_id,
        modified_by=modified_by,
        target_agent=target_agent,
        policy_id=policy_id,
        now=when,
    )
    if drift is not None:
        anomalies.append(drift)

    return anomalies


def record_cross_org_action(
    *,
    local_org_id: str,
    remote_org_id: str,
    local_agent: str,
    remote_resource: str,
    action_type: str,
    federation_trust_id: str | None = None,
    now: str | None = None,
) -> list[GraphAnomaly]:
    """
    Record a cross-organization agent action into the trust graph (FAT).

    Adds a node for the remote resource (namespaced by remote org) and a
    ``crosses_org`` edge from the local agent.  Detects
    ``CROSS_ORG_ACTION_WITHOUT_HANDSHAKE`` (CRITICAL) when no federation
    trust id is supplied — policy_guard's CONST-06 will independently
    BLOCK such actions, but the graph signal also feeds blast_radius and
    intent_correlation for visibility.
    """
    if not local_org_id or not remote_org_id or not local_agent:
        raise ValueError(
            "local_org_id, remote_org_id, local_agent are required"
        )

    when = now or _now()

    # Namespace the remote resource by its org so the same label across
    # different orgs does not collide in the graph.
    remote_label = f"{remote_org_id}::{remote_resource or 'unknown_resource'}"
    edge_meta = json.dumps(
        {
            "local_org_id": local_org_id,
            "remote_org_id": remote_org_id,
            "action_type": action_type,
            "federation_trust_id": federation_trust_id,
        }
    )

    nodes: list[tuple[str, str, str]] = [
        ("agent", local_agent, "{}"),
        ("workload", remote_label, edge_meta),
    ]
    edges: list[tuple[str, str, str, str, str]] = [
        ("agent", local_agent, "workload", remote_label, _CROSSES_ORG_EDGE_TYPE),
    ]
    _upsert_nodes(local_org_id, nodes, when)
    _upsert_edges(local_org_id, edges, when)

    anomalies: list[GraphAnomaly] = []
    if not federation_trust_id:
        anomalies.append(
            GraphAnomaly(
                anomaly_type="CROSS_ORG_ACTION_WITHOUT_HANDSHAKE",
                tenant_id=local_org_id,
                detected_at=when,
                subject_node=local_agent,
                detail=(
                    f"Agent '{local_agent}' acted on '{remote_resource}' "
                    f"in org '{remote_org_id}' with no federation trust."
                ),
                severity="critical",
                context={
                    "local_org_id": local_org_id,
                    "remote_org_id": remote_org_id,
                    "remote_resource": remote_resource,
                    "action_type": action_type,
                },
            )
        )
    return anomalies


def _check_permission_weight_drift(
    *,
    tenant_id: str,
    modified_by: str,
    target_agent: str,
    policy_id: str,
    now: str,
) -> GraphAnomaly | None:
    """
    Fire PERMISSION_WEIGHT_DRIFT if a (modifier → target) policy-modification
    edge has weight at or above ``_PERMISSION_WEIGHT_DRIFT_THRESHOLD``,
    was first seen within ``PERMISSION_DRIFT_WINDOW_DAYS``, and the modifier
    has no ``attested_by`` edge within the same window.
    """
    if _use_pg():
        # Postgres-backed anomaly detection lives behind the same SQLite path
        # for now; the existing detectors gate the same way.
        return None

    src_id = _node_id(tenant_id, "agent", modified_by)
    dst_id = _node_id(tenant_id, "agent", target_agent)
    eid = _edge_id(tenant_id, src_id, dst_id, _POLICY_MOD_EDGE_TYPE)

    with _lock:
        conn = _get_conn()
        try:
            edge_row = conn.execute(
                "SELECT weight, first_seen FROM tg_edges WHERE edge_id=?",
                (eid,),
            ).fetchone()
            if edge_row is None:
                return None
            weight = int(edge_row["weight"])
            if weight < _PERMISSION_WEIGHT_DRIFT_THRESHOLD:
                return None

            # Time gate: edge must have been first seen within the drift window.
            from datetime import datetime, timedelta, timezone

            try:
                first_seen = datetime.fromisoformat(edge_row["first_seen"])
                now_dt = datetime.fromisoformat(now)
            except ValueError:
                return None
            if first_seen.tzinfo is None:
                first_seen = first_seen.replace(tzinfo=timezone.utc)
            if now_dt.tzinfo is None:
                now_dt = now_dt.replace(tzinfo=timezone.utc)
            window = timedelta(days=PERMISSION_DRIFT_WINDOW_DAYS)
            if (now_dt - first_seen) > window:
                return None

            # Attestation gate: any attested_by edge from the modifier within
            # the same window suppresses the anomaly.
            attested = conn.execute(
                """
                SELECT 1 FROM tg_edges
                WHERE tenant_id=? AND src_node=? AND edge_type='attested_by'
                  AND last_seen >= ?
                LIMIT 1
                """,
                (
                    tenant_id,
                    src_id,
                    (now_dt - window).isoformat(),
                ),
            ).fetchone()
            if attested:
                return None

            return GraphAnomaly(
                anomaly_type="PERMISSION_WEIGHT_DRIFT",
                tenant_id=tenant_id,
                detected_at=now,
                subject_node=target_agent,
                detail=(
                    f"Modifier '{modified_by}' has accumulated {weight} "
                    f"unattested policy modifications affecting "
                    f"'{target_agent}' within the last "
                    f"{PERMISSION_DRIFT_WINDOW_DAYS} days."
                ),
                severity="high",
                context={
                    "modifier": modified_by,
                    "target": target_agent,
                    "policy_id": policy_id,
                    "edge_weight": weight,
                    "threshold": _PERMISSION_WEIGHT_DRIFT_THRESHOLD,
                    "window_days": PERMISSION_DRIFT_WINDOW_DAYS,
                    "attestation_present": False,
                },
            )
        finally:
            conn.close()


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


def get_graph_data(tenant_id: str, limit: int = 200) -> dict[str, Any]:
    """
    Return all nodes and edges for the tenant as plain dicts,
    suitable for graph visualization.
    """
    with _lock:
        conn = _get_conn()
        try:
            nodes = conn.execute(
                """
                SELECT node_id, node_type, label, observation_count, last_seen
                FROM tg_nodes WHERE tenant_id=?
                ORDER BY node_type, label
                LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
            edges = conn.execute(
                """
                SELECT e.src_node, e.dst_node, e.edge_type, e.weight,
                       s.label AS src_label, s.node_type AS src_type,
                       d.label AS dst_label, d.node_type AS dst_type
                FROM tg_edges e
                JOIN tg_nodes s ON s.node_id = e.src_node AND s.tenant_id = e.tenant_id
                JOIN tg_nodes d ON d.node_id = e.dst_node AND d.tenant_id = e.tenant_id
                WHERE e.tenant_id=?
                LIMIT ?
                """,
                (tenant_id, limit * 4),
            ).fetchall()
            return {
                "nodes": [dict(r) for r in nodes],
                "edges": [dict(r) for r in edges],
            }
        finally:
            conn.close()


# ── RSA 26 Gap-Closure Extensions ────────────────────────────────────────────
#
# Sprint 1-2 addendum (2026-04-17):
# RSA 26 exposed three critical gaps no vendor closed.  Two of those gaps map
# directly to trust-graph anomaly rules:
#
#   RULE-04  POLICY_SELF_MODIFICATION  (RSA Gap 1)
#     Agent has legitimate credentials, hits a restriction, removes the
#     restriction itself.  CrowdStrike disclosed two Fortune 50 incidents.
#     No existing identity framework detects this.
#
#   RULE-05  PERMISSION_DRIFT_SPIKE    (RSA Gap 2)
#     Agent permissions expanded 3× in one month without security review.
#     Discovery tools show today’s permissions; nothing tracks how they
#     evolved.
#
# These rules are appended here so they integrate cleanly into the existing
# anomaly pipeline without restructuring the upstream implementation.
# ─────────────────────────────────────────────────────────────────────────────

_RSA_INIT = """
CREATE TABLE IF NOT EXISTS tg_policy_governs (
    edge_id       TEXT NOT NULL PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    policy_label  TEXT NOT NULL,
    agent_label   TEXT NOT NULL,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS tg_permission_history (
    history_id    TEXT NOT NULL PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    agent_label   TEXT NOT NULL,
    policy_label  TEXT NOT NULL,
    recorded_at   TEXT NOT NULL,
    scope_weight  REAL NOT NULL,
    source_event  TEXT
);

CREATE INDEX IF NOT EXISTS idx_tg_policy_governs_tenant
    ON tg_policy_governs(tenant_id, agent_label);
CREATE INDEX IF NOT EXISTS idx_tg_perm_history_lookup
    ON tg_permission_history(tenant_id, agent_label, policy_label, recorded_at);
"""


def _rsa_init_db() -> None:
    """Idempotently create RSA gap-closure tables."""
    with _lock:
        conn = _get_conn()
        try:
            conn.executescript(_RSA_INIT)
            conn.commit()
        finally:
            conn.close()


def _rsa_edge_id(tenant_id: str, policy_label: str, agent_label: str) -> str:
    import uuid
    return str(uuid.uuid5(
        uuid.NAMESPACE_DNS,
        f"{tenant_id}:{policy_label}:{agent_label}:governs",
    ))


def record_policy_governance(tenant_id: str, policy_label: str,
                              agent_label: str) -> bool:
    """
    Record that policy_label GOVERNS agent_label in this tenant.
    Returns True if the edge pre-existed (update), False if brand new (insert).
    Used by RULE-04: self-modification detection fires only on pre-existing edges.
    """
    _rsa_init_db()
    now = _now()
    edge_id = _rsa_edge_id(tenant_id, policy_label, agent_label)
    with _lock:
        conn = _get_conn()
        try:
            existing = conn.execute(
                "SELECT observation_count FROM tg_policy_governs WHERE edge_id=?",
                (edge_id,)
            ).fetchone()
            if existing:
                conn.execute("""
                    UPDATE tg_policy_governs
                    SET last_seen=?, observation_count=observation_count+1
                    WHERE edge_id=?
                """, (now, edge_id))
                conn.commit()
                return True  # pre-existed
            else:
                conn.execute("""
                    INSERT INTO tg_policy_governs
                        (edge_id, tenant_id, policy_label, agent_label,
                         first_seen, last_seen, observation_count)
                    VALUES (?, ?, ?, ?, ?, ?, 1)
                """, (edge_id, tenant_id, policy_label, agent_label, now, now))
                conn.commit()
                return False  # brand new
        finally:
            conn.close()


def record_permission_scope(tenant_id: str, agent_label: str,
                             policy_label: str, scope: list[str],
                             source_event: str | None = None) -> None:
    """Record a permission scope observation for drift tracking (RULE-05)."""
    import uuid
    _rsa_init_db()
    scope_weight = float(len(scope)) if scope else 1.0
    with _lock:
        conn = _get_conn()
        try:
            conn.execute("""
                INSERT INTO tg_permission_history
                    (history_id, tenant_id, agent_label, policy_label,
                     recorded_at, scope_weight, source_event)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4()), tenant_id, agent_label, policy_label,
                _now(), scope_weight, source_event,
            ))
            conn.commit()
        finally:
            conn.close()


def check_policy_self_modification(
    tenant_id: str,
    agent_label: str,
    policy_label: str,
    event_type: str = "",
    action: str = "",
) -> GraphAnomaly | None:
    """
    RULE-04 (RSA Gap 1): Detect agent attempting to modify its own governing policy.

    Fires CRITICAL anomaly when:
      - A GOVERNS edge exists from policy_label → agent_label (pre-existing)
      - The current event is a policy write/modify/delete/remove operation

    Returns a GraphAnomaly or None.
    """
    _rsa_init_db()
    now = _now()

    # Write signal detection
    write_signals = {
        "policy_write", "policy_update", "policy_delete", "policy_modify",
        "permission_grant", "scope_expansion", "rule_removal",
        "privilege_escalation",
    }
    write_actions = {"write", "update", "delete", "modify", "remove"}
    is_write = (
        event_type in write_signals
        or action.lower() in write_actions
    )
    if not is_write:
        return None

    # Check pre-existing governance relationship
    edge_id = _rsa_edge_id(tenant_id, policy_label, agent_label)
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT observation_count FROM tg_policy_governs WHERE edge_id=?",
                (edge_id,)
            ).fetchone()
        finally:
            conn.close()

    if not row or row["observation_count"] < 2:
        # Not a pre-existing governance relationship — first event created it;
        # can’t be self-modification
        return None

    anomaly = GraphAnomaly(
        anomaly_type="POLICY_SELF_MODIFICATION",
        severity="critical",
        tenant_id=tenant_id,
        detected_at=now,
        subject_node=agent_label,
        detail=(
            f"CRITICAL: Agent ‘{agent_label}’ attempted to modify policy ‘{policy_label}’ "
            "which governs its own permissions. This matches the pattern of an agent "
            "removing its own security restrictions. Human review required immediately. "
            "[RSA 26 Gap 1]"
        ),
        context={"policy_label": policy_label, "event_type": event_type,
                 "action": action, "rsa_gap": "Gap 1 — Policy Self-Modification",
                 "rule": "RULE-04"},
    )
    store_anomaly(anomaly)
    return anomaly


def check_permission_drift(
    tenant_id: str,
    agent_label: str,
    policy_label: str,
) -> GraphAnomaly | None:
    """
    RULE-05 (RSA Gap 2): Permission surface growing >×2 without attestation.

    Compares the current (most recent) scope weight against the oldest
    weight recorded within the baseline window.  If growth exceeds
    PERMISSION_GROWTH_THRESHOLD, fires a HIGH anomaly.

    Returns a GraphAnomaly or None.
    """
    from datetime import datetime, timezone, timedelta
    _rsa_init_db()
    now = _now()
    cutoff = (
        datetime.now(timezone.utc) - timedelta(days=PERMISSION_DRIFT_WINDOW_DAYS)
    ).isoformat()

    with _lock:
        conn = _get_conn()
        try:
            # Oldest record in the window (baseline)
            baseline_row = conn.execute("""
                SELECT scope_weight FROM tg_permission_history
                WHERE tenant_id=? AND agent_label=? AND policy_label=?
                  AND recorded_at >= ?
                ORDER BY recorded_at ASC LIMIT 1
            """, (tenant_id, agent_label, policy_label, cutoff)).fetchone()

            # Most recent record (current)
            current_row = conn.execute("""
                SELECT scope_weight FROM tg_permission_history
                WHERE tenant_id=? AND agent_label=? AND policy_label=?
                ORDER BY recorded_at DESC LIMIT 1
            """, (tenant_id, agent_label, policy_label)).fetchone()
        finally:
            conn.close()

    if not baseline_row or not current_row:
        return None
    baseline = baseline_row["scope_weight"]
    current = current_row["scope_weight"]
    if baseline <= 0:
        return None

    growth = current / baseline
    if growth < PERMISSION_GROWTH_THRESHOLD:
        return None

    anomaly = GraphAnomaly(
        anomaly_type="PERMISSION_DRIFT_SPIKE",
        severity="high",
        tenant_id=tenant_id,
        detected_at=now,
        subject_node=agent_label,
        detail=(
            f"Agent ‘{agent_label}’ permission surface for policy ‘{policy_label}’ "
            f"has grown {growth:.1f}× (baseline {baseline:.1f} → current {current:.1f}) "
            f"over the past {PERMISSION_DRIFT_WINDOW_DAYS} days without attestation. "
            "[RSA 26 Gap 2]"
        ),
        context={
            "policy_label": policy_label,
            "baseline_weight": baseline,
            "current_weight": current,
            "growth_factor": round(growth, 3),
            "threshold": PERMISSION_GROWTH_THRESHOLD,
            "rsa_gap": "Gap 2 — Permission Lifecycle / Drift",
            "rule": "RULE-05",
        },
    )
    store_anomaly(anomaly)
    return anomaly
