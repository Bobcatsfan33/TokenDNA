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
    policy_ids = _policies_in_blast(tenant_id, [n.label for n in reachable])

    return BlastRadiusResult(
        agent_label=agent_label,
        tenant_id=tenant_id,
        simulated_at=now,
        reachable_nodes=reachable,
        total_nodes_reached=len(reachable),
        impact_score=impact_score,
        risk_tier=_risk_tier(impact_score),
        policies_containing_blast=policy_ids,
    )


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
            # BFS using SQLite recursive CTE — follows all edge types
            rows = conn.execute(
                f"""
                WITH RECURSIVE reach(node_id, hop, edge_path) AS (
                    SELECT ?, 0, ''
                    UNION ALL
                    SELECT e.dst_node,
                           reach.hop + 1,
                           reach.edge_path || ',' || e.edge_type
                    FROM tg_edges e
                    JOIN reach ON e.src_node = reach.node_id
                    WHERE e.tenant_id = ?
                      AND reach.hop < ?
                      AND (',' || reach.edge_path || ',') NOT LIKE
                          ('%,' || e.dst_node || ',%')
                )
                SELECT n.node_id, n.node_type, n.label,
                       r.hop, r.edge_path
                FROM reach r
                JOIN tg_nodes n ON n.node_id = r.node_id AND n.tenant_id = ?
                WHERE r.node_id != ?
                ORDER BY r.hop
                """,
                (start_node_id, tenant_id, max_hops, tenant_id, start_node_id),
            ).fetchall()

            seen: set[str] = set()
            result: list[ReachableNode] = []
            for row in rows:
                nid = row["node_id"]
                if nid in seen:
                    continue
                seen.add(nid)
                edge_path = [e for e in row["edge_path"].split(",") if e]
                result.append(ReachableNode(
                    node_id=nid,
                    node_type=row["node_type"],
                    label=row["label"],
                    hop_distance=row["hop"],
                    path_edge_types=edge_path,
                    impact_contribution=NODE_TYPE_IMPACT.get(row["node_type"], 5),
                ))
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
