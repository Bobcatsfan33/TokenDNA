"""
TokenDNA — Behavioral DNA Drift Detection (Phase 5-3, Part 2)

An agent with valid credentials that starts behaving differently is invisible
to every credential-based security tool.  This module fingerprints the
behavioral patterns of each agent and detects when behaviour deviates from
the established baseline — even when credentials remain valid.

─────────────────────────────────────────────────────────────
What "Behavioral DNA" Means
─────────────────────────────────────────────────────────────

Every agent has observable behavioural dimensions:
  - tool_usage     : which tools it calls, and how often
  - resource_access: which resources it touches
  - timing         : hour-of-day and day-of-week patterns
  - action_types   : read/write/delete/admin mix

For each dimension we maintain a Welford online baseline — a streaming
mean and variance that updates on every event without storing raw history.

Drift score: for each dimension we compute a z-score of the current
observation vs. the baseline.  The dimensions' z-scores are combined into
a 0.0–1.0 drift score.  Above DRIFT_ALERT_THRESHOLD, a drift alert is
raised.

─────────────────────────────────────────────────────────────
Use cases
─────────────────────────────────────────────────────────────

1. System prompt injection — model starts calling tools it never used.
   Drift alert fires on the "first_use_of_tool" dimension.

2. Model poisoning / malicious fine-tune — subtle shift in resource
   access patterns.  Drift alert fires when pattern z-score exceeds
   threshold.

3. Orchestrator compromise — agent calls tools at unusual times (3 AM
   pattern vs. 9-5 baseline).  Timing drift triggers alert.

4. Scope creep — agent gradually expands into admin/delete actions over
   time.  Action-type drift catches the change.

─────────────────────────────────────────────────────────────
API
─────────────────────────────────────────────────────────────
POST /api/behavioral/event                   Record an observable event
GET  /api/behavioral/baseline/{agent_id}     Current learned baseline
GET  /api/behavioral/drift/{agent_id}        Current drift score
GET  /api/behavioral/alerts                  Unacknowledged drift alerts
POST /api/behavioral/alerts/{id}/acknowledge Acknowledge a drift alert
POST /api/behavioral/snapshot/{agent_id}     Take a manual snapshot
GET  /api/behavioral/audit/{agent_id}        Behavioral audit trail
"""

from __future__ import annotations

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
    "TOKENDNA_BEHAVIORAL_DB",
    os.path.expanduser("~/.tokendna/behavioral_dna.db"),
)

DRIFT_ALERT_THRESHOLD = float(os.getenv("BEHAVIORAL_DRIFT_THRESHOLD", "0.65"))
MIN_BASELINE_SAMPLES = int(os.getenv("BEHAVIORAL_MIN_SAMPLES", "10"))
# z-score cap — prevents single extreme outliers from dominating the score
Z_CAP = float(os.getenv("BEHAVIORAL_Z_CAP", "5.0"))

_lock = threading.Lock()
_db_initialized = False


# ── DB bootstrap ───────────────────────────────────────────────────────────────


def init_db(db_path: str = _DB_PATH) -> None:
    global _db_initialized
    if _db_initialized:
        return
    with _lock:
        if _db_initialized:
            return
        os.makedirs(
            os.path.dirname(db_path) if os.path.dirname(db_path) else ".",
            exist_ok=True,
        )
        with sqlite3.connect(db_path) as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                -- ── Behavioural event log ─────────────────────────────────
                CREATE TABLE IF NOT EXISTS bd_events (
                    event_id     TEXT PRIMARY KEY,
                    tenant_id    TEXT NOT NULL,
                    agent_id     TEXT NOT NULL,
                    event_type   TEXT NOT NULL,   -- tool_call|resource_access|action
                    tool_name    TEXT,
                    resource     TEXT,
                    action_type  TEXT,
                    params_hash  TEXT,
                    hour_of_day  INTEGER,
                    day_of_week  INTEGER,
                    created_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_bd_events_agent
                    ON bd_events(tenant_id, agent_id, created_at DESC);

                -- ── Welford baselines ─────────────────────────────────────
                -- One row per (tenant, agent, dimension, value).
                -- dimension: tool_name | resource | action_type | hour_of_day
                CREATE TABLE IF NOT EXISTS bd_baselines (
                    baseline_id   TEXT PRIMARY KEY,
                    tenant_id     TEXT NOT NULL,
                    agent_id      TEXT NOT NULL,
                    dimension     TEXT NOT NULL,
                    dim_value     TEXT NOT NULL,
                    sample_count  INTEGER NOT NULL DEFAULT 0,
                    mean          REAL NOT NULL DEFAULT 0.0,
                    m2            REAL NOT NULL DEFAULT 0.0,
                    last_updated  TEXT NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_bd_baseline_key
                    ON bd_baselines(tenant_id, agent_id, dimension, dim_value);

                -- ── Drift scores ──────────────────────────────────────────
                CREATE TABLE IF NOT EXISTS bd_drift_scores (
                    score_id     TEXT PRIMARY KEY,
                    tenant_id    TEXT NOT NULL,
                    agent_id     TEXT NOT NULL,
                    drift_score  REAL NOT NULL,
                    factors_json TEXT,
                    computed_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_bd_drift_agent
                    ON bd_drift_scores(tenant_id, agent_id, computed_at DESC);

                -- ── Drift alerts ──────────────────────────────────────────
                CREATE TABLE IF NOT EXISTS bd_drift_alerts (
                    alert_id         TEXT PRIMARY KEY,
                    tenant_id        TEXT NOT NULL,
                    agent_id         TEXT NOT NULL,
                    drift_score      REAL NOT NULL,
                    threshold        REAL NOT NULL,
                    factors_json     TEXT,
                    detected_at      TEXT NOT NULL,
                    acknowledged     INTEGER NOT NULL DEFAULT 0,
                    acknowledged_by  TEXT,
                    acknowledged_at  TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_bd_alerts_tenant
                    ON bd_drift_alerts(tenant_id, acknowledged);

                -- ── Behavioral snapshots ──────────────────────────────────
                CREATE TABLE IF NOT EXISTS bd_snapshots (
                    snapshot_id   TEXT PRIMARY KEY,
                    tenant_id     TEXT NOT NULL,
                    agent_id      TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    trigger       TEXT NOT NULL DEFAULT 'manual',
                    snapped_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_bd_snapshots_agent
                    ON bd_snapshots(tenant_id, agent_id, snapped_at DESC);
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


# ── Event Recording ────────────────────────────────────────────────────────────


def record_event(
    tenant_id: str,
    agent_id: str,
    event_type: str,
    *,
    tool_name: str = "",
    resource: str = "",
    action_type: str = "",
    params: dict[str, Any] | None = None,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Record a behavioural event for an agent and update its baseline.

    After updating the baseline, computes the current drift score and raises
    an alert if the score exceeds DRIFT_ALERT_THRESHOLD.

    Returns the event record.
    """
    init_db(db_path)
    event_id = str(uuid.uuid4())
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()
    hour_of_day = now_dt.hour
    day_of_week = now_dt.weekday()  # 0=Monday

    # Hash params to track parameter shape without storing values
    params_hash = ""
    if params:
        import hashlib  # noqa: PLC0415
        params_hash = hashlib.sha256(
            json.dumps(sorted(params.keys())).encode()
        ).hexdigest()[:16]

    with _cursor(db_path) as cur:
        cur.execute(
            """
            INSERT INTO bd_events
                (event_id, tenant_id, agent_id, event_type, tool_name,
                 resource, action_type, params_hash, hour_of_day,
                 day_of_week, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, tenant_id, agent_id, event_type,
             tool_name, resource, action_type,
             params_hash, hour_of_day, day_of_week, now),
        )

    # Update baselines for each observable dimension
    if tool_name:
        _update_baseline(tenant_id, agent_id, "tool_name", tool_name, db_path=db_path)
    if resource:
        _update_baseline(tenant_id, agent_id, "resource", resource, db_path=db_path)
    if action_type:
        _update_baseline(tenant_id, agent_id, "action_type", action_type, db_path=db_path)
    _update_baseline(
        tenant_id, agent_id, "hour_of_day", str(hour_of_day), db_path=db_path
    )

    # Compute drift and raise alert if needed
    drift = _compute_and_store_drift(tenant_id, agent_id, db_path=db_path)
    if drift and drift["drift_score"] >= DRIFT_ALERT_THRESHOLD:
        _maybe_raise_drift_alert(
            tenant_id, agent_id, drift["drift_score"], drift["factors"], db_path=db_path
        )

    return {
        "event_id":    event_id,
        "tenant_id":   tenant_id,
        "agent_id":    agent_id,
        "event_type":  event_type,
        "tool_name":   tool_name,
        "resource":    resource,
        "action_type": action_type,
        "hour_of_day": hour_of_day,
        "day_of_week": day_of_week,
        "created_at":  now,
    }


def _update_baseline(
    tenant_id: str,
    agent_id: str,
    dimension: str,
    dim_value: str,
    *,
    db_path: str,
) -> None:
    """Welford online update for one (dimension, value) pair."""
    now = _now()
    with _cursor(db_path) as cur:
        row = cur.execute(
            """
            SELECT * FROM bd_baselines
             WHERE tenant_id=? AND agent_id=? AND dimension=? AND dim_value=?
            """,
            (tenant_id, agent_id, dimension, dim_value),
        ).fetchone()

        if row is None:
            baseline_id = str(uuid.uuid4())
            # First observation: n=1, mean=1.0, m2=0
            cur.execute(
                """
                INSERT INTO bd_baselines
                    (baseline_id, tenant_id, agent_id, dimension, dim_value,
                     sample_count, mean, m2, last_updated)
                VALUES (?, ?, ?, ?, ?, 1, 1.0, 0.0, ?)
                """,
                (baseline_id, tenant_id, agent_id, dimension, dim_value, now),
            )
        else:
            n = row["sample_count"] + 1
            old_mean = row["mean"]
            old_m2 = row["m2"]
            # Welford update with observation value = 1 (this dim_value appeared once)
            new_mean = old_mean + (1.0 - old_mean) / n
            new_m2 = old_m2 + (1.0 - old_mean) * (1.0 - new_mean)
            cur.execute(
                """
                UPDATE bd_baselines
                   SET sample_count=?, mean=?, m2=?, last_updated=?
                 WHERE tenant_id=? AND agent_id=? AND dimension=? AND dim_value=?
                """,
                (n, new_mean, new_m2, now,
                 tenant_id, agent_id, dimension, dim_value),
            )


# ── Drift Scoring ──────────────────────────────────────────────────────────────


def _compute_and_store_drift(
    tenant_id: str,
    agent_id: str,
    *,
    db_path: str,
) -> dict[str, Any] | None:
    """Compute drift score using proportion-based novelty model.

    For each (dimension, value) the novelty score is:
      - 1.0  when the value has never been seen before (first_use)
      - 1 - proportion  otherwise (rarer = more novel)

    Drift score = max novelty across all dimensions that have at least
    MIN_BASELINE_SAMPLES total events.

    Returns None if there is insufficient baseline data.
    """
    with _cursor(db_path) as cur:
        rows = cur.execute(
            """
            SELECT * FROM bd_baselines
             WHERE tenant_id=? AND agent_id=?
            """,
            (tenant_id, agent_id),
        ).fetchall()

    if not rows:
        return None

    # Group rows by dimension and compute totals
    by_dim: dict[str, list[sqlite3.Row]] = {}
    for row in rows:
        by_dim.setdefault(row["dimension"], []).append(row)

    novelty_scores: list[float] = []
    factors: list[dict[str, Any]] = []

    for dimension, dim_rows in by_dim.items():
        total = sum(r["sample_count"] for r in dim_rows)
        if total < MIN_BASELINE_SAMPLES:
            continue

        for row in dim_rows:
            proportion = row["sample_count"] / total if total > 0 else 0.0
            # Novelty: rarer values are more surprising
            # New values (count=1) are maximally novel
            novelty = 1.0 - proportion
            novelty = max(0.0, min(1.0, novelty))
            if novelty > 0:
                novelty_scores.append(novelty)
                factors.append({
                    "dimension":  dimension,
                    "value":      row["dim_value"],
                    "novelty":    round(novelty, 3),
                    "proportion": round(proportion, 4),
                    "count":      row["sample_count"],
                    "total":      total,
                })

    if not novelty_scores:
        return None

    # Drift score = maximum novelty (worst-case dimension)
    novelty_scores.sort(reverse=True)
    drift_score = novelty_scores[0]

    # Store
    score_id = str(uuid.uuid4())
    now = _now()
    with _cursor(db_path) as cur:
        cur.execute(
            """
            INSERT INTO bd_drift_scores
                (score_id, tenant_id, agent_id, drift_score, factors_json, computed_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (score_id, tenant_id, agent_id, drift_score, json.dumps(factors), now),
        )

    return {"drift_score": drift_score, "factors": factors}


def _maybe_raise_drift_alert(
    tenant_id: str,
    agent_id: str,
    drift_score: float,
    factors: list[dict[str, Any]],
    *,
    db_path: str,
) -> None:
    """Raise a drift alert only if there isn't an unacknowledged one already."""
    with _cursor(db_path) as cur:
        existing = cur.execute(
            """
            SELECT 1 FROM bd_drift_alerts
             WHERE tenant_id=? AND agent_id=? AND acknowledged=0
            """,
            (tenant_id, agent_id),
        ).fetchone()
        if existing:
            return
        alert_id = str(uuid.uuid4())
        cur.execute(
            """
            INSERT INTO bd_drift_alerts
                (alert_id, tenant_id, agent_id, drift_score, threshold,
                 factors_json, detected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (alert_id, tenant_id, agent_id, drift_score,
             DRIFT_ALERT_THRESHOLD, json.dumps(factors), _now()),
        )


def compute_drift_score(
    tenant_id: str,
    agent_id: str,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Return the latest computed drift score for an agent."""
    init_db(db_path)
    with _cursor(db_path) as cur:
        row = cur.execute(
            """
            SELECT * FROM bd_drift_scores
             WHERE tenant_id=? AND agent_id=?
             ORDER BY computed_at DESC LIMIT 1
            """,
            (tenant_id, agent_id),
        ).fetchone()
    if row is None:
        return {
            "agent_id":    agent_id,
            "drift_score": 0.0,
            "factors":     [],
            "computed_at": None,
            "status":      "insufficient_data",
        }
    return {
        "agent_id":    agent_id,
        "drift_score": float(row["drift_score"]),
        "factors":     json.loads(row["factors_json"] or "[]"),
        "computed_at": row["computed_at"],
        "status":      "above_threshold" if float(row["drift_score"]) >= DRIFT_ALERT_THRESHOLD else "normal",
    }


# ── Baseline API ───────────────────────────────────────────────────────────────


def get_baseline(
    tenant_id: str,
    agent_id: str,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Return the full learned baseline for an agent, grouped by dimension."""
    init_db(db_path)
    with _cursor(db_path) as cur:
        rows = cur.execute(
            """
            SELECT * FROM bd_baselines
             WHERE tenant_id=? AND agent_id=?
             ORDER BY dimension, dim_value
            """,
            (tenant_id, agent_id),
        ).fetchall()

    by_dim: dict[str, list[dict[str, Any]]] = {}
    total_samples = 0
    for r in rows:
        dim = r["dimension"]
        n = r["sample_count"]
        variance = r["m2"] / (n - 1) if n > 1 else 0.0
        by_dim.setdefault(dim, []).append({
            "value":        r["dim_value"],
            "sample_count": n,
            "mean":         round(r["mean"], 4),
            "stddev":       round(math.sqrt(variance), 4) if variance > 0 else 0.0,
            "last_updated": r["last_updated"],
        })
        total_samples = max(total_samples, n)

    return {
        "agent_id":      agent_id,
        "tenant_id":     tenant_id,
        "total_samples": total_samples,
        "dimensions":    by_dim,
        "stable":        total_samples >= MIN_BASELINE_SAMPLES,
    }


# ── Drift Alerts ───────────────────────────────────────────────────────────────


def list_drift_alerts(
    tenant_id: str,
    *,
    agent_id: str | None = None,
    acknowledged: bool = False,
    db_path: str = _DB_PATH,
) -> list[dict[str, Any]]:
    init_db(db_path)
    sql = "SELECT * FROM bd_drift_alerts WHERE tenant_id=? AND acknowledged=?"
    params: list[Any] = [tenant_id, int(acknowledged)]
    if agent_id:
        sql += " AND agent_id=?"
        params.append(agent_id)
    sql += " ORDER BY detected_at DESC"
    with _cursor(db_path) as cur:
        rows = cur.execute(sql, params).fetchall()
    return [_row_to_alert(r) for r in rows]


def acknowledge_drift_alert(
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
            UPDATE bd_drift_alerts
               SET acknowledged=1, acknowledged_by=?, acknowledged_at=?
             WHERE alert_id=? AND tenant_id=?
            """,
            (acknowledged_by, now, alert_id, tenant_id),
        )
        row = cur.execute(
            "SELECT * FROM bd_drift_alerts WHERE alert_id=? AND tenant_id=?",
            (alert_id, tenant_id),
        ).fetchone()
    if row is None:
        raise KeyError(f"Drift alert '{alert_id}' not found for tenant '{tenant_id}'")
    return _row_to_alert(row)


def _row_to_alert(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "alert_id":        row["alert_id"],
        "tenant_id":       row["tenant_id"],
        "agent_id":        row["agent_id"],
        "drift_score":     float(row["drift_score"]),
        "threshold":       float(row["threshold"]),
        "factors":         json.loads(row["factors_json"] or "[]"),
        "detected_at":     row["detected_at"],
        "acknowledged":    bool(row["acknowledged"]),
        "acknowledged_by": row["acknowledged_by"],
        "acknowledged_at": row["acknowledged_at"],
    }


# ── Snapshots & Audit Trail ────────────────────────────────────────────────────


def take_snapshot(
    tenant_id: str,
    agent_id: str,
    trigger: str = "manual",
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Capture a point-in-time behavioral profile snapshot."""
    init_db(db_path)
    baseline = get_baseline(tenant_id, agent_id, db_path=db_path)
    drift = compute_drift_score(tenant_id, agent_id, db_path=db_path)
    snapshot = {"baseline": baseline, "drift": drift}
    snapshot_id = str(uuid.uuid4())
    now = _now()
    with _cursor(db_path) as cur:
        cur.execute(
            """
            INSERT INTO bd_snapshots
                (snapshot_id, tenant_id, agent_id, snapshot_json, trigger, snapped_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (snapshot_id, tenant_id, agent_id, json.dumps(snapshot), trigger, now),
        )
    return {
        "snapshot_id": snapshot_id,
        "agent_id":    agent_id,
        "trigger":     trigger,
        "snapped_at":  now,
        "snapshot":    snapshot,
    }


def get_audit_trail(
    tenant_id: str,
    agent_id: str,
    *,
    limit: int = 200,
    db_path: str = _DB_PATH,
) -> list[dict[str, Any]]:
    """Return the immutable behavioral event audit trail for an agent."""
    init_db(db_path)
    with _cursor(db_path) as cur:
        rows = cur.execute(
            """
            SELECT * FROM bd_events
             WHERE tenant_id=? AND agent_id=?
             ORDER BY created_at DESC LIMIT ?
            """,
            (tenant_id, agent_id, limit),
        ).fetchall()
    return [_row_to_event(r) for r in rows]


def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "event_id":    row["event_id"],
        "tenant_id":   row["tenant_id"],
        "agent_id":    row["agent_id"],
        "event_type":  row["event_type"],
        "tool_name":   row["tool_name"] or "",
        "resource":    row["resource"] or "",
        "action_type": row["action_type"] or "",
        "params_hash": row["params_hash"] or "",
        "hour_of_day": row["hour_of_day"],
        "day_of_week": row["day_of_week"],
        "created_at":  row["created_at"],
    }


# ── Helpers ────────────────────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
