"""
TokenDNA — Agent Permission Blast Radius Simulator (Sprint 2-1)

Pre-execution query: "if agent X is compromised at time T, what nodes does
it reach, what actions does it enable, and what is the overall impact score?"

Consumes the UIS Trust Graph (Sprint 1-2) to compute the reachability set of
a given agent node under a simulated compromise scenario.

Impact scoring
--------------
Each reached node contributes to an impact score based on its type:

  verifier    +40   (compromise of a verifier = trust infrastructure damage)
  issuer      +30   (compromise of an issuer = credential issuance risk)
  agent       +20   (lateral movement to another agent)
  workload    +15   (access to a workload = data / compute risk)
  tool        +10   (tool access enables further pivoting)
  tenant      +50   (top-level tenant compromise = complete control)

Score is capped at 100. Risk tiers map as:
  0–20    → low
  21–50   → medium
  51–80   → high
  81–100  → critical
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass, field
from typing import Any

from modules.storage import db_backend


# ── Impact scoring weights ────────────────────────────────────────────────────

NODE_TYPE_IMPACT: dict[str, int] = {
    "tenant":   50,
    "verifier": 40,
    "issuer":   30,
    "agent":    20,
    "workload": 15,
    "tool":     10,
}

MAX_IMPACT_SCORE = 100


def _risk_tier(score: int) -> str:
    if score <= 20:
        return "low"
    if score <= 50:
        return "medium"
    if score <= 80:
        return "high"
    return "critical"


# ── DB helpers ─────────────────────────────────────────────────────────────────

_lock = threading.Lock()


def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _use_pg() -> bool:
    return db_backend.should_use_postgres()


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class ReachableNode:
    node_id: str
    node_type: str
    label: str
    hop_distance: int
    path_edge_types: list[str]
    impact_contribution: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "label": self.label,
            "hop_distance": self.hop_distance,
            "path_edge_types": self.path_edge_types,
            "impact_contribution": self.impact_contribution,
        }


@dataclass
class BlastRadiusResult:
    agent_label: str
    tenant_id: str
    simulated_at: str
    reachable_nodes: list[ReachableNode] = field(default_factory=list)
    total_nodes_reached: int = 0
    impact_score: int = 0
    risk_tier: str = "low"
    policies_containing_blast: list[str] = field(default_factory=list)
    # Sprint B enrichment — surface Trust Graph anomalies and recent MCP
    # chain-pattern matches that touch nodes inside the blast radius.  These
    # turn the simulation from "what could happen" into "what IS happening,
    # right now, against this agent" — the live demo wedge.
    recent_anomalies_in_blast: list[dict[str, Any]] = field(default_factory=list)
    recent_mcp_violations_in_blast: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent_label": self.agent_label,
            "tenant_id": self.tenant_id,
            "simulated_at": self.simulated_at,
            "total_nodes_reached": self.total_nodes_reached,
            "impact_score": self.impact_score,
            "risk_tier": self.risk_tier,
            "reachable_nodes": [n.as_dict() for n in self.reachable_nodes],
            "policies_containing_blast": self.policies_containing_blast,
            "recent_anomalies_in_blast": self.recent_anomalies_in_blast,
            "recent_mcp_violations_in_blast": self.recent_mcp_violations_in_blast,
            "error": self.error,
        }


# ── Simulation ─────────────────────────────────────────────────────────────────

def simulate_blast_radius(
    tenant_id: str,
    agent_label: str,
    max_hops: int = 6,
) -> BlastRadiusResult:
    """
    Compute the blast radius if agent `agent_label` is compromised.

    Returns a BlastRadiusResult with:
    - All reachable nodes within max_hops hops
    - Impact score (0–100) based on node type weights
    - Risk tier (low/medium/high/critical)
    - List of policy bundle IDs whose scope overlaps the blast radius

    The traversal follows ALL edge types — a compromised agent can pivot
    along any trust relationship it holds.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()

    if _use_pg():
        return BlastRadiusResult(
            agent_label=agent_label,
            tenant_id=tenant_id,
            simulated_at=now,
            error="pg_blast_radius_not_implemented",
        )

    from modules.identity.trust_graph import _node_id  # noqa: PLC0415

    # Resolve agent node
    agent_node_id: str | None = None
    for node_type in ("agent", "workload"):
        candidate = _node_id(tenant_id, node_type, agent_label)
        if _node_exists(tenant_id, candidate):
            agent_node_id = candidate
            break

    if not agent_node_id:
        return BlastRadiusResult(
            agent_label=agent_label,
            tenant_id=tenant_id,
            simulated_at=now,
            error=f"agent_not_found:{agent_label}",
        )

    # BFS reachability traversal
    reachable = _bfs_reachability(tenant_id, agent_node_id, max_hops)

    # Compute impact score
    raw_score = sum(
        NODE_TYPE_IMPACT.get(n.node_type, 5) for n in reachable
    )
    impact_score = min(raw_score, MAX_IMPACT_SCORE)

    # Find overlapping policy bundles
    blast_labels = [n.label for n in reachable] + [agent_label]
    policy_ids = _policies_in_blast(tenant_id, blast_labels)

    # Sprint B — surface the live signals that touch this blast radius.
    anomalies = _recent_anomalies_in_blast(tenant_id, blast_labels)
    mcp_violations = _recent_mcp_violations_in_blast(tenant_id, blast_labels)

    return BlastRadiusResult(
        agent_label=agent_label,
        tenant_id=tenant_id,
        simulated_at=now,
        reachable_nodes=reachable,
        total_nodes_reached=len(reachable),
        impact_score=impact_score,
        risk_tier=_risk_tier(impact_score),
        policies_containing_blast=policy_ids,
        recent_anomalies_in_blast=anomalies,
        recent_mcp_violations_in_blast=mcp_violations,
    )


def _recent_anomalies_in_blast(
    tenant_id: str,
    blast_labels: list[str],
    *,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """
    Pull recent Trust Graph anomalies whose subject_node is inside the blast
    radius.  Best-effort: missing tables (e.g. on a fresh test DB without
    anomaly history) return an empty list rather than raising.
    """
    if not blast_labels:
        return []
    label_set = set(blast_labels)
    with _lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                """
                SELECT anomaly_type, severity, subject_node, detected_at, detail
                FROM tg_anomalies
                WHERE tenant_id = ?
                ORDER BY detected_at DESC
                LIMIT ?
                """,
                (tenant_id, limit * 4),
            ).fetchall()
            return [
                {
                    "anomaly_type": r["anomaly_type"],
                    "severity": r["severity"],
                    "subject_node": r["subject_node"],
                    "detected_at": r["detected_at"],
                    "detail": r["detail"],
                }
                for r in rows
                if r["subject_node"] in label_set
            ][:limit]
        except sqlite3.OperationalError:
            return []
        finally:
            conn.close()


def _recent_mcp_violations_in_blast(
    tenant_id: str,
    blast_labels: list[str],
    *,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """
    Pull recent MCP violations whose agent_id is inside the blast radius.
    Best-effort: returns empty if the mcp_violations table doesn't exist.
    """
    if not blast_labels:
        return []
    label_set = set(blast_labels)
    with _lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                """
                SELECT violation_id, agent_id, tool_name, violation_type,
                       detail, risk_score, created_at
                FROM mcp_violations
                WHERE tenant_id = ? AND resolved = 0
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (tenant_id, limit * 4),
            ).fetchall()
            return [
                {
                    "violation_id": r["violation_id"],
                    "agent_id": r["agent_id"],
                    "tool_name": r["tool_name"],
                    "violation_type": r["violation_type"],
                    "detail": r["detail"],
                    "risk_score": r["risk_score"],
                    "created_at": r["created_at"],
                }
                for r in rows
                if r["agent_id"] and r["agent_id"] in label_set
            ][:limit]
        except sqlite3.OperationalError:
            return []
        finally:
            conn.close()


def _node_exists(tenant_id: str, node_id: str) -> bool:
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT 1 FROM tg_nodes WHERE node_id=? AND tenant_id=?",
                (node_id, tenant_id),
            ).fetchone()
            return row is not None
        except sqlite3.OperationalError:
            return False
        finally:
            conn.close()


def _bfs_reachability(
    tenant_id: str,
    start_node_id: str,
    max_hops: int,
) -> list[ReachableNode]:
    """
    BFS over the trust graph starting from start_node_id.
    Returns all reachable nodes (excluding the start node itself).
    """
    with _lock:
        conn = _get_conn()
        try:
            # Bidirectional BFS in Python: compromise propagates BOTH along
            # outgoing edges (agent trusts X) AND reverse edges (other agents
            # that share the same issuer/verifier as the compromised agent).
            # Pre-load all edges for the tenant for efficiency.
            all_edges = conn.execute(
                "SELECT src_node, dst_node, edge_type FROM tg_edges WHERE tenant_id=?",
                (tenant_id,),
            ).fetchall()
            # Build adjacency: forward and reverse
            fwd: dict[str, list[tuple[str, str]]] = {}  # src -> [(dst, etype)]
            rev: dict[str, list[tuple[str, str]]] = {}  # dst -> [(src, etype)]
            for e in all_edges:
                fwd.setdefault(e["src_node"], []).append((e["dst_node"], e["edge_type"]))
                rev.setdefault(e["dst_node"], []).append((e["src_node"], e["edge_type"]))
            # Load node metadata
            node_rows = conn.execute(
                "SELECT node_id, node_type, label FROM tg_nodes WHERE tenant_id=?",
                (tenant_id,),
            ).fetchall()
            node_meta: dict[str, dict] = {r["node_id"]: dict(r) for r in node_rows}

            # BFS
            from collections import deque
            queue: deque = deque()
            queue.append((start_node_id, 0, []))
            visited: dict[str, int] = {start_node_id: 0}  # node_id -> first hop seen
            result_map: dict[str, ReachableNode] = {}

            while queue:
                cur_id, hop, path_edges = queue.popleft()
                if hop >= max_hops:
                    continue
                neighbors = list(fwd.get(cur_id, [])) + list(rev.get(cur_id, []))
                for (nbr_id, etype) in neighbors:
                    if nbr_id not in visited:
                        visited[nbr_id] = hop + 1
                        new_path = path_edges + [etype]
                        if nbr_id in node_meta:
                            m = node_meta[nbr_id]
                            result_map[nbr_id] = ReachableNode(
                                node_id=nbr_id,
                                node_type=m["node_type"],
                                label=m["label"],
                                hop_distance=hop + 1,
                                path_edge_types=new_path,
                                impact_contribution=NODE_TYPE_IMPACT.get(m["node_type"], 5),
                            )
                        queue.append((nbr_id, hop + 1, new_path))

            result = sorted(result_map.values(), key=lambda n: n.hop_distance)
            return result
        except sqlite3.OperationalError:
            return []
        finally:
            conn.close()


def _policies_in_blast(tenant_id: str, node_labels: list[str]) -> list[str]:
    """
    Return policy bundle IDs whose subject or scope overlaps any node label
    in the blast radius.
    """
    if not node_labels:
        return []
    try:
        from modules.identity import policy_bundles  # noqa: PLC0415
        bundles = policy_bundles.list_bundles(tenant_id=tenant_id)
        matching: list[str] = []
        for bundle in bundles:
            raw = bundle.get("policy_json") or bundle.get("rules_json") or ""
            if isinstance(raw, str):
                raw_lower = raw.lower()
            else:
                raw_lower = json.dumps(raw).lower()
            for label in node_labels:
                if label.lower() in raw_lower:
                    bid = bundle.get("bundle_id") or bundle.get("id", "")
                    if bid and bid not in matching:
                        matching.append(bid)
                    break
        return matching
    except Exception:  # noqa: BLE001
        return []


# ── Simulation history ─────────────────────────────────────────────────────────

def store_simulation(result: BlastRadiusResult) -> None:
    """Persist a simulation result for audit and trending."""
    if _use_pg():
        return
    with _lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS blast_radius_simulations (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id       TEXT NOT NULL,
                    agent_label     TEXT NOT NULL,
                    simulated_at    TEXT NOT NULL,
                    impact_score    INTEGER NOT NULL,
                    risk_tier       TEXT NOT NULL,
                    nodes_reached   INTEGER NOT NULL,
                    result_json     TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                INSERT INTO blast_radius_simulations
                    (tenant_id, agent_label, simulated_at, impact_score,
                     risk_tier, nodes_reached, result_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.tenant_id,
                    result.agent_label,
                    result.simulated_at,
                    result.impact_score,
                    result.risk_tier,
                    result.total_nodes_reached,
                    json.dumps(result.as_dict()),
                ),
            )
            conn.commit()
        finally:
            conn.close()


def list_simulations(
    tenant_id: str,
    agent_label: str | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Return recent blast radius simulation history for a tenant."""
    if _use_pg():
        return []
    with _lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS blast_radius_simulations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL, agent_label TEXT NOT NULL,
                    simulated_at TEXT NOT NULL, impact_score INTEGER NOT NULL,
                    risk_tier TEXT NOT NULL, nodes_reached INTEGER NOT NULL,
                    result_json TEXT NOT NULL
                )
                """
            )
            params: list[Any] = [tenant_id]
            where = "WHERE tenant_id=?"
            if agent_label:
                where += " AND agent_label=?"
                params.append(agent_label)
            rows = conn.execute(
                f"""SELECT id, agent_label, simulated_at, impact_score, risk_tier,
                           nodes_reached
                    FROM blast_radius_simulations
                    {where}
                    ORDER BY simulated_at DESC
                    LIMIT ?""",
                tuple(params) + (min(limit, 100),),
            ).fetchall()
            return [dict(r) for r in rows]
        except sqlite3.OperationalError:
            return []
        finally:
            conn.close()
