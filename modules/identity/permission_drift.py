"""
TokenDNA — Permission Drift Tracker (Sprint 5-2)

Closes RSA'26 Gap 2: "Agent permissions expanded 3× in one month without
security review. Discovery tools show today's state; nothing tracks how
permissions evolved."

This module provides the full operator-facing product for permission drift
detection — not just the trust_graph-level signal, but a complete tracking,
alerting, and approval workflow:

  1. Scope observation recording
     Every permission change (grant, revoke, scope update) is recorded with
     full provenance: who changed it, when, what changed, and whether an
     attestation event accompanied the change.

  2. Drift detection
     Computes growth factor over a configurable baseline window. Fires a
     DriftAlert when any agent's permission surface grows beyond the threshold
     without an accompanying attestation event.

  3. Drift report
     Per-agent timeline of permission changes — the "permission history" that
     no existing tool provides. Shows baseline → current delta with growth
     factor and approval status.

  4. Human approval workflow
     Unreviewed drift events can be approved (with justification) or flagged
     for remediation. Approved drift records the approver and timestamp.

  5. Blast Radius comparison
     compare_blast_radius() returns current blast radius score vs. the score
     at the baseline date, making permission drift viscerally clear to
     operators: "your agent's blast radius increased 2.4× this month."

API
───
GET  /api/drift/alerts                  List open drift alerts (all agents)
GET  /api/drift/report/{agent_id}       Full permission timeline for one agent
POST /api/drift/record                  Record a permission scope observation
POST /api/drift/approve/{drift_id}      Human approval of a drift event
GET  /api/drift/summary                 Tenant-level drift summary stats
GET  /api/drift/blast-comparison/{agent_id}  Current vs. baseline blast radius delta
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

from modules.security.audit_log import AuditEventType, AuditOutcome, log_event
from modules.storage.ddl_runner import run_ddl
from modules.storage.pg_connection import AdaptedCursor, get_db_conn
from typing import Any

logger = logging.getLogger(__name__)


def _emit_audit(
    event_type: AuditEventType,
    outcome: AuditOutcome,
    *,
    tenant_id: str,
    subject: str,
    resource: str,
    detail: dict[str, Any],
) -> None:
    """Best-effort audit emission — never block the caller on logging failure."""
    try:
        log_event(
            event_type,
            outcome,
            tenant_id=tenant_id,
            subject=subject,
            resource=resource,
            detail=detail,
        )
    except Exception:
        logger.exception("audit log emit failed for %s", event_type)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_DB_PATH = os.getenv("DATA_DB_PATH", "/data/tokendna.db")
_lock = threading.Lock()

DRIFT_THRESHOLD_MULTIPLIER = float(os.getenv("DRIFT_THRESHOLD_X", "2.0"))
DRIFT_BASELINE_DAYS = int(os.getenv("DRIFT_BASELINE_DAYS", "30"))
DRIFT_STABLE_MIN_OBSERVATIONS = int(os.getenv("DRIFT_STABLE_MIN_OBS", "3"))


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

@dataclass
class ScopeObservation:
    """A single recorded permission scope state for an agent."""
    observation_id: str
    tenant_id: str
    agent_id: str
    policy_id: str
    scope: list[str]
    scope_weight: float           # len(scope) — permission surface proxy
    recorded_at: str
    source_event: str | None      # UIS event ID or system reference
    has_attestation: bool         # was this change accompanied by an attestation?
    changed_by: str | None        # actor that made the change (if known)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DriftAlert:
    """An open drift event requiring operator review."""
    drift_id: str
    tenant_id: str
    agent_id: str
    policy_id: str
    baseline_weight: float
    current_weight: float
    growth_factor: float
    baseline_date: str
    detected_at: str
    status: str                   # "open" | "approved" | "remediated"
    approved_by: str | None
    approved_at: str | None
    approval_note: str | None
    observations_in_window: int
    unattested_changes: int       # changes without accompanying attestation
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentDriftReport:
    """Full permission history timeline for one agent."""
    agent_id: str
    tenant_id: str
    policy_id: str
    observations: list[ScopeObservation]
    baseline_weight: float
    current_weight: float
    growth_factor: float
    open_alerts: int
    unattested_changes: int
    report_generated_at: str


@dataclass
class DriftSummary:
    """Tenant-level drift summary."""
    tenant_id: str
    agents_tracked: int
    agents_with_open_alerts: int
    total_open_alerts: int
    total_approved: int
    highest_growth_factor: float
    highest_growth_agent: str | None
    computed_at: str


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def _cursor():
    """Yield a backend-portable AdaptedCursor (SQLite or Postgres)."""
    with _lock:
        with get_db_conn(db_path=_DB_PATH) as conn:
            yield AdaptedCursor(conn.cursor())


_DDL_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS drift_observations (
        observation_id      TEXT NOT NULL PRIMARY KEY,
        tenant_id           TEXT NOT NULL,
        agent_id            TEXT NOT NULL,
        policy_id           TEXT NOT NULL,
        scope               TEXT NOT NULL DEFAULT '[]',
        scope_weight        REAL NOT NULL,
        recorded_at         TEXT NOT NULL,
        source_event        TEXT,
        has_attestation     INTEGER NOT NULL DEFAULT 0,
        changed_by          TEXT,
        metadata            TEXT NOT NULL DEFAULT '{}'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS drift_alerts (
        drift_id            TEXT NOT NULL PRIMARY KEY,
        tenant_id           TEXT NOT NULL,
        agent_id            TEXT NOT NULL,
        policy_id           TEXT NOT NULL,
        baseline_weight     REAL NOT NULL,
        current_weight      REAL NOT NULL,
        growth_factor       REAL NOT NULL,
        baseline_date       TEXT NOT NULL,
        detected_at         TEXT NOT NULL,
        status              TEXT NOT NULL DEFAULT 'open',
        approved_by         TEXT,
        approved_at         TEXT,
        approval_note       TEXT,
        observations_count  INTEGER NOT NULL DEFAULT 0,
        unattested_changes  INTEGER NOT NULL DEFAULT 0,
        metadata            TEXT NOT NULL DEFAULT '{}'
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_do_tenant_agent ON drift_observations(tenant_id, agent_id, policy_id, recorded_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_da_tenant_status ON drift_alerts(tenant_id, status, detected_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_da_agent ON drift_alerts(tenant_id, agent_id, policy_id)",
)


def init_db() -> None:
    """Idempotently create permission drift tables on SQLite or Postgres."""
    run_ddl(_DDL_STATEMENTS, _DB_PATH)


# ---------------------------------------------------------------------------
# Scope observation recording
# ---------------------------------------------------------------------------

def record_observation(
    *,
    tenant_id: str,
    agent_id: str,
    policy_id: str,
    scope: list[str],
    source_event: str | None = None,
    has_attestation: bool = False,
    changed_by: str | None = None,
    metadata: dict | None = None,
) -> ScopeObservation:
    """
    Record a permission scope observation and run drift detection.
    Returns the ScopeObservation; may also create a DriftAlert as a side effect.
    """
    init_db()
    obs_id = str(uuid.uuid4())
    now = _utc_now()
    scope_weight = float(len(scope)) if scope else 0.0

    with _cursor() as cur:
        cur.execute("""
            INSERT INTO drift_observations
                (observation_id, tenant_id, agent_id, policy_id, scope,
                 scope_weight, recorded_at, source_event, has_attestation,
                 changed_by, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            obs_id, tenant_id, agent_id, policy_id,
            json.dumps(scope), scope_weight, now,
            source_event, int(has_attestation),
            changed_by, json.dumps(metadata or {}),
        ))

    obs = ScopeObservation(
        observation_id=obs_id,
        tenant_id=tenant_id,
        agent_id=agent_id,
        policy_id=policy_id,
        scope=scope,
        scope_weight=scope_weight,
        recorded_at=now,
        source_event=source_event,
        has_attestation=has_attestation,
        changed_by=changed_by,
        metadata=metadata or {},
    )

    _emit_audit(
        AuditEventType.PERMISSION_DRIFT_OBSERVED,
        AuditOutcome.SUCCESS,
        tenant_id=tenant_id,
        subject=changed_by or agent_id,
        resource=policy_id,
        detail={
            "observation_id": obs_id,
            "agent_id": agent_id,
            "scope_size": len(scope),
            "has_attestation": has_attestation,
            "source_event": source_event,
        },
    )

    # Run drift detection after recording
    alert = _detect_drift(tenant_id=tenant_id, agent_id=agent_id, policy_id=policy_id)
    if alert is not None:
        _emit_audit(
            AuditEventType.PERMISSION_DRIFT_DETECTED,
            AuditOutcome.FAILURE,
            tenant_id=tenant_id,
            subject=agent_id,
            resource=policy_id,
            detail={
                "drift_id": alert.drift_id,
                "growth_factor": alert.growth_factor,
                "baseline_weight": alert.baseline_weight,
                "current_weight": alert.current_weight,
                "unattested_changes": alert.unattested_changes,
                "observations_in_window": alert.observations_in_window,
            },
        )

    return obs


def _detect_drift(tenant_id: str, agent_id: str, policy_id: str) -> DriftAlert | None:
    """
    Compute drift for (tenant, agent, policy) and create/update a DriftAlert
    if growth exceeds the threshold.
    """
    baseline_cutoff = (
        datetime.now(timezone.utc) - timedelta(days=DRIFT_BASELINE_DAYS)
    ).isoformat()
    now = _utc_now()

    with _cursor() as cur:
        # All observations in the baseline window
        cur.execute("""
            SELECT observation_id, scope_weight, recorded_at, has_attestation
            FROM drift_observations
            WHERE tenant_id=? AND agent_id=? AND policy_id=?
              AND recorded_at >= ?
            ORDER BY recorded_at ASC
        """, (tenant_id, agent_id, policy_id, baseline_cutoff))
        window_rows = cur.fetchall()

    if len(window_rows) < DRIFT_STABLE_MIN_OBSERVATIONS:
        return None  # not enough history to detect drift

    baseline_weight = window_rows[0]["scope_weight"]
    current_weight = window_rows[-1]["scope_weight"]

    if baseline_weight <= 0:
        return None

    growth_factor = current_weight / baseline_weight
    if growth_factor < DRIFT_THRESHOLD_MULTIPLIER:
        return None  # within acceptable bounds

    # Count unattested changes
    unattested = sum(1 for r in window_rows if not r["has_attestation"])

    # Check for an existing open alert for this (agent, policy) pair
    with _cursor() as cur:
        cur.execute("""
            SELECT drift_id FROM drift_alerts
            WHERE tenant_id=? AND agent_id=? AND policy_id=? AND status='open'
            ORDER BY detected_at DESC LIMIT 1
        """, (tenant_id, agent_id, policy_id))
        existing = cur.fetchone()

    if existing:
        # Update the existing alert with fresh numbers
        with _cursor() as cur:
            cur.execute("""
                UPDATE drift_alerts
                SET current_weight=?, growth_factor=?,
                    observations_count=?, unattested_changes=?
                WHERE drift_id=?
            """, (current_weight, round(growth_factor, 3),
                  len(window_rows), unattested,
                  existing["drift_id"]))
        return get_alert(existing["drift_id"], tenant_id)

    # Create a new alert
    drift_id = str(uuid.uuid4())
    with _cursor() as cur:
        cur.execute("""
            INSERT INTO drift_alerts
                (drift_id, tenant_id, agent_id, policy_id,
                 baseline_weight, current_weight, growth_factor,
                 baseline_date, detected_at, status,
                 observations_count, unattested_changes, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, '{}')
        """, (
            drift_id, tenant_id, agent_id, policy_id,
            baseline_weight, current_weight, round(growth_factor, 3),
            window_rows[0]["recorded_at"], now,
            len(window_rows), unattested,
        ))

    logger.warning(
        "DriftAlert: agent=%s policy=%s growth=%.1fx unattested=%d tenant=%s",
        agent_id, policy_id, growth_factor, unattested, tenant_id,
    )
    return get_alert(drift_id, tenant_id)


# ---------------------------------------------------------------------------
# Alert queries
# ---------------------------------------------------------------------------

def _row_to_alert(row: sqlite3.Row) -> DriftAlert:
    return DriftAlert(
        drift_id=row["drift_id"],
        tenant_id=row["tenant_id"],
        agent_id=row["agent_id"],
        policy_id=row["policy_id"],
        baseline_weight=row["baseline_weight"],
        current_weight=row["current_weight"],
        growth_factor=row["growth_factor"],
        baseline_date=row["baseline_date"],
        detected_at=row["detected_at"],
        status=row["status"],
        approved_by=row["approved_by"],
        approved_at=row["approved_at"],
        approval_note=row["approval_note"],
        observations_in_window=row["observations_count"],
        unattested_changes=row["unattested_changes"],
        metadata=json.loads(row["metadata"]),
    )


def get_alert(drift_id: str, tenant_id: str) -> DriftAlert | None:
    with _cursor() as cur:
        cur.execute(
            "SELECT * FROM drift_alerts WHERE drift_id=? AND tenant_id=?",
            (drift_id, tenant_id),
        )
        row = cur.fetchone()
    return _row_to_alert(row) if row else None


def list_alerts(
    tenant_id: str,
    status: str | None = "open",
    agent_id: str | None = None,
    limit: int = 50,
) -> list[DriftAlert]:
    """List drift alerts for a tenant."""
    init_db()
    clauses = ["tenant_id = ?"]
    params: list[Any] = [tenant_id]
    if status:
        clauses.append("status = ?")
        params.append(status)
    if agent_id:
        clauses.append("agent_id = ?")
        params.append(agent_id)
    where = " AND ".join(clauses)
    params.append(min(limit, 200))
    with _cursor() as cur:
        cur.execute(
            f"SELECT * FROM drift_alerts WHERE {where} "
            f"ORDER BY growth_factor DESC, detected_at DESC LIMIT ?",
            params,
        )
        rows = cur.fetchall()
    return [_row_to_alert(r) for r in rows]


def approve_drift(
    drift_id: str,
    tenant_id: str,
    approved_by: str,
    note: str = "",
) -> DriftAlert | None:
    """Human operator approves a drift event (accepts the growth as intentional)."""
    init_db()
    now = _utc_now()
    with _cursor() as cur:
        cur.execute("""
            UPDATE drift_alerts
            SET status='approved', approved_by=?, approved_at=?, approval_note=?
            WHERE drift_id=? AND tenant_id=? AND status='open'
        """, (approved_by, now, note, drift_id, tenant_id))
        if cur.rowcount == 0:
            return None
    final = get_alert(drift_id, tenant_id)
    _emit_audit(
        AuditEventType.PERMISSION_DRIFT_APPROVED,
        AuditOutcome.SUCCESS,
        tenant_id=tenant_id,
        subject=approved_by,
        resource=final.policy_id if final else drift_id,
        detail={
            "drift_id": drift_id,
            "agent_id": final.agent_id if final else None,
            "growth_factor": final.growth_factor if final else None,
            "note": note,
        },
    )
    return final


def mark_remediated(drift_id: str, tenant_id: str, note: str = "") -> DriftAlert | None:
    """Mark a drift event as remediated (permissions have been reduced)."""
    init_db()
    now = _utc_now()
    with _cursor() as cur:
        cur.execute("""
            UPDATE drift_alerts
            SET status='remediated', approved_at=?, approval_note=?
            WHERE drift_id=? AND tenant_id=? AND status='open'
        """, (now, note, drift_id, tenant_id))
        if cur.rowcount == 0:
            return None
    return get_alert(drift_id, tenant_id)


# ---------------------------------------------------------------------------
# Per-agent drift report
# ---------------------------------------------------------------------------

def agent_drift_report(
    tenant_id: str,
    agent_id: str,
    policy_id: str,
    days: int = 30,
) -> AgentDriftReport:
    """Full permission history timeline for one agent on one policy."""
    init_db()
    cutoff = (
        datetime.now(timezone.utc) - timedelta(days=min(days, 365))
    ).isoformat()

    with _cursor() as cur:
        cur.execute("""
            SELECT * FROM drift_observations
            WHERE tenant_id=? AND agent_id=? AND policy_id=?
              AND recorded_at >= ?
            ORDER BY recorded_at ASC
        """, (tenant_id, agent_id, policy_id, cutoff))
        obs_rows = cur.fetchall()

        cur.execute("""
            SELECT COUNT(*) as n FROM drift_alerts
            WHERE tenant_id=? AND agent_id=? AND policy_id=? AND status='open'
        """, (tenant_id, agent_id, policy_id))
        open_alerts = cur.fetchone()["n"]

    observations = [
        ScopeObservation(
            observation_id=r["observation_id"],
            tenant_id=r["tenant_id"],
            agent_id=r["agent_id"],
            policy_id=r["policy_id"],
            scope=json.loads(r["scope"]),
            scope_weight=r["scope_weight"],
            recorded_at=r["recorded_at"],
            source_event=r["source_event"],
            has_attestation=bool(r["has_attestation"]),
            changed_by=r["changed_by"],
            metadata=json.loads(r["metadata"]),
        )
        for r in obs_rows
    ]

    baseline_weight = observations[0].scope_weight if observations else 0.0
    current_weight = observations[-1].scope_weight if observations else 0.0
    growth_factor = (current_weight / baseline_weight) if baseline_weight > 0 else 1.0
    unattested = sum(1 for o in observations if not o.has_attestation)

    return AgentDriftReport(
        agent_id=agent_id,
        tenant_id=tenant_id,
        policy_id=policy_id,
        observations=observations,
        baseline_weight=baseline_weight,
        current_weight=current_weight,
        growth_factor=round(growth_factor, 3),
        open_alerts=open_alerts,
        unattested_changes=unattested,
        report_generated_at=_utc_now(),
    )


# ---------------------------------------------------------------------------
# Edge-cache snapshot
# ---------------------------------------------------------------------------

def edge_drift_snapshot(limit: int = 10_000) -> list[dict[str, Any]]:
    """
    Cross-tenant per-agent drift snapshot for the Cloudflare Worker KV
    cache.  Returns the highest-growth-factor open alert per agent, mapped
    to a coarse tier the worker can compare against without re-running the
    detector:

      growth_factor >= 3.0  → tier=BLOCK   score=min(1.0, growth_factor/5)
      growth_factor >= 2.0  → tier=STEP_UP score=growth_factor/4
      otherwise             → tier=ALLOW   score=growth_factor/4

    Agents with no open alert are omitted from the snapshot so the worker
    does not block them at the edge.
    """
    init_db()
    with _cursor() as cur:
        cur.execute(
            """
            SELECT agent_id, MAX(growth_factor) AS gf, MIN(detected_at) AS first_seen
            FROM drift_alerts
            WHERE status = 'open'
            GROUP BY agent_id
            ORDER BY gf DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        gf = float(r["gf"] or 0.0)
        if gf >= 3.0:
            tier, score = "BLOCK", min(1.0, gf / 5.0)
        elif gf >= 2.0:
            tier, score = "STEP_UP", min(0.99, gf / 4.0)
        else:
            tier, score = "ALLOW", min(0.5, gf / 4.0)
        out.append({
            "agent_id": r["agent_id"],
            "score": round(score, 3),
            "tier": tier,
            "reason": f"growth_factor={gf:.2f}",
        })
    return out


# ---------------------------------------------------------------------------
# Tenant-level summary
# ---------------------------------------------------------------------------

def drift_summary(tenant_id: str) -> DriftSummary:
    """Compute tenant-level drift summary statistics."""
    init_db()
    with _cursor() as cur:
        cur.execute("""
            SELECT COUNT(DISTINCT agent_id) as agents_tracked
            FROM drift_observations WHERE tenant_id=?
        """, (tenant_id,))
        agents_tracked = cur.fetchone()["agents_tracked"]

        cur.execute("""
            SELECT COUNT(DISTINCT agent_id) as agents_with_alerts
            FROM drift_alerts WHERE tenant_id=? AND status='open'
        """, (tenant_id,))
        agents_with_alerts = cur.fetchone()["agents_with_alerts"]

        cur.execute("""
            SELECT COUNT(*) as total FROM drift_alerts
            WHERE tenant_id=? AND status='open'
        """, (tenant_id,))
        total_open = cur.fetchone()["total"]

        cur.execute("""
            SELECT COUNT(*) as total FROM drift_alerts
            WHERE tenant_id=? AND status='approved'
        """, (tenant_id,))
        total_approved = cur.fetchone()["total"]

        cur.execute("""
            SELECT agent_id, growth_factor FROM drift_alerts
            WHERE tenant_id=?
            ORDER BY growth_factor DESC LIMIT 1
        """, (tenant_id,))
        top_row = cur.fetchone()

    return DriftSummary(
        tenant_id=tenant_id,
        agents_tracked=agents_tracked,
        agents_with_open_alerts=agents_with_alerts,
        total_open_alerts=total_open,
        total_approved=total_approved,
        highest_growth_factor=top_row["growth_factor"] if top_row else 0.0,
        highest_growth_agent=top_row["agent_id"] if top_row else None,
        computed_at=_utc_now(),
    )


# ---------------------------------------------------------------------------
# Blast Radius comparison
# ---------------------------------------------------------------------------

def blast_radius_comparison(
    tenant_id: str,
    agent_id: str,
    policy_id: str,
    baseline_days: int = 30,
) -> dict[str, Any]:
    """
    Compare current permission weight vs. baseline weight and surface the
    delta as a blast-radius growth estimate.

    Returns a dict with:
      baseline_weight, current_weight, growth_factor,
      blast_radius_growth_estimate (qualitative: low/medium/high/critical),
      baseline_date, notes
    """
    init_db()
    cutoff = (
        datetime.now(timezone.utc) - timedelta(days=baseline_days)
    ).isoformat()

    with _cursor() as cur:
        cur.execute("""
            SELECT scope_weight, recorded_at FROM drift_observations
            WHERE tenant_id=? AND agent_id=? AND policy_id=?
              AND recorded_at >= ?
            ORDER BY recorded_at ASC LIMIT 1
        """, (tenant_id, agent_id, policy_id, cutoff))
        baseline_row = cur.fetchone()

        cur.execute("""
            SELECT scope_weight, recorded_at FROM drift_observations
            WHERE tenant_id=? AND agent_id=? AND policy_id=?
            ORDER BY recorded_at DESC LIMIT 1
        """, (tenant_id, agent_id, policy_id))
        current_row = cur.fetchone()

    if not baseline_row or not current_row:
        return {
            "agent_id": agent_id,
            "policy_id": policy_id,
            "found": False,
            "notes": "Insufficient history for comparison",
        }

    baseline_weight = baseline_row["scope_weight"]
    current_weight = current_row["scope_weight"]
    growth = (current_weight / baseline_weight) if baseline_weight > 0 else 1.0

    if growth < 1.5:
        tier = "low"
    elif growth < 2.0:
        tier = "medium"
    elif growth < 3.0:
        tier = "high"
    else:
        tier = "critical"

    return {
        "agent_id": agent_id,
        "policy_id": policy_id,
        "found": True,
        "baseline_weight": baseline_weight,
        "baseline_date": baseline_row["recorded_at"],
        "current_weight": current_weight,
        "current_date": current_row["recorded_at"],
        "growth_factor": round(growth, 3),
        "blast_radius_growth_estimate": tier,
        "notes": (
            f"Agent '{agent_id}' permission surface has grown {growth:.1f}× "
            f"over the past {baseline_days} days. "
            f"Blast radius growth estimate: {tier.upper()}."
        ),
    }
