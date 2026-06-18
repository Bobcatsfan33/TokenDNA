"""Cross-session/agent/model campaign correlation (Gap roadmap Epic 4.1 / A1).

The damaging multi-session attack is decomposed across many individually-harmless
prompts, sessions, agents, and even models — "harm only exists in the
reassembly." Single-prompt guardrails never see it. This module reassembles it:
it takes security signals (intent matches, trust-graph anomalies, MCP
violations, denied retrievals) and stitches related ones into a **campaign** —
a connected cluster that shares a linking dimension (agent / session / model /
target / technique) within a time window.

A campaign that spans more than one session, agent, or model is the direct
answer to the multi-session attack thesis, and is flagged as such.
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

# Default correlation window: signals farther apart than this never link.
DEFAULT_WINDOW_SECONDS = 24 * 3600
# Dimensions that, when shared, link two signals into the same campaign.
_LINK_DIMS = ("agent_id", "session_id", "model_id", "target", "technique")
_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

_DDL = (
    """
    CREATE TABLE IF NOT EXISTS campaigns (
        campaign_id    TEXT PRIMARY KEY,
        tenant_id      TEXT NOT NULL,
        severity       TEXT NOT NULL,
        signal_count   INTEGER NOT NULL,
        sessions       INTEGER NOT NULL DEFAULT 0,
        agents         INTEGER NOT NULL DEFAULT 0,
        models         INTEGER NOT NULL DEFAULT 0,
        spans_sessions INTEGER NOT NULL DEFAULT 0,
        spans_agents   INTEGER NOT NULL DEFAULT 0,
        spans_models   INTEGER NOT NULL DEFAULT 0,
        first_seen     TEXT NOT NULL,
        last_seen      TEXT NOT NULL,
        detail_json    TEXT NOT NULL DEFAULT '{}',
        created_at     TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_campaigns_tenant ON campaigns(tenant_id, created_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS campaign_signals (
        row_id       TEXT PRIMARY KEY,
        campaign_id  TEXT NOT NULL,
        tenant_id    TEXT NOT NULL,
        signal_json  TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_campaign_signals ON campaign_signals(campaign_id)",
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


# ── Signal normalization ──────────────────────────────────────────────────────

def _ts(signal: dict[str, Any]) -> float:
    """Epoch seconds for a signal; accepts 'ts' (float) or ISO 'timestamp'."""
    if isinstance(signal.get("ts"), (int, float)):
        return float(signal["ts"])
    raw = signal.get("timestamp") or signal.get("detected_at")
    if raw:
        try:
            return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    return 0.0


def signals_from_intent_matches(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert intent_correlation matches into campaign signals.

    Pulls linking dimensions out of the match subject + context.
    """
    out = []
    for m in matches:
        ctx = m.get("context") or {}
        out.append({
            "signal_id": m.get("match_id") or str(uuid.uuid4()),
            "source": "intent_match",
            "severity": m.get("severity", "medium"),
            "timestamp": m.get("detected_at"),
            "agent_id": ctx.get("agent_id") or m.get("subject"),
            "session_id": ctx.get("session_id"),
            "model_id": ctx.get("model_id") or ctx.get("model"),
            "target": ctx.get("target") or ctx.get("target_policy_id"),
            "technique": m.get("playbook_name") or ctx.get("technique"),
            "detail": m.get("detail", ""),
        })
    return out


# ── Clustering (connected components over linking dimensions) ──────────────────

def _linked(a: dict[str, Any], b: dict[str, Any], window: float) -> bool:
    if abs(_ts(a) - _ts(b)) > window:
        return False
    for dim in _LINK_DIMS:
        va, vb = a.get(dim), b.get(dim)
        if va and vb and va == vb:
            return True
    return False


def _cluster(signals: list[dict[str, Any]], window: float) -> list[list[dict[str, Any]]]:
    n = len(signals)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        parent[find(x)] = find(y)

    for i in range(n):
        for j in range(i + 1, n):
            if _linked(signals[i], signals[j], window):
                union(i, j)

    groups: dict[int, list[dict[str, Any]]] = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(signals[i])
    return list(groups.values())


def _distinct(signals: list[dict[str, Any]], dim: str) -> set[str]:
    return {str(s[dim]) for s in signals if s.get(dim)}


def build_campaigns(
    *,
    tenant_id: str,
    signals: list[dict[str, Any]],
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
    min_signals: int = 2,
    persist: bool = True,
    db_path: str = _DB_PATH,
) -> list[dict[str, Any]]:
    """Stitch signals into campaigns. Only clusters with >= min_signals qualify.

    Returns campaign dicts; persists them when persist=True. Emits a
    CAMPAIGN_DETECTED audit per multi-dimension campaign.
    """
    init_db(db_path)
    clusters = [c for c in _cluster(signals, window_seconds) if len(c) >= min_signals]
    campaigns: list[dict[str, Any]] = []
    for cluster in clusters:
        sessions = _distinct(cluster, "session_id")
        agents = _distinct(cluster, "agent_id")
        models = _distinct(cluster, "model_id")
        techniques = sorted(_distinct(cluster, "technique"))
        severity = max((s.get("severity", "low") for s in cluster),
                       key=lambda x: _SEV_RANK.get(x, 0))
        times = sorted(_ts(s) for s in cluster)
        first_iso = datetime.fromtimestamp(times[0], tz=timezone.utc).isoformat() if times[0] else _now()
        last_iso = datetime.fromtimestamp(times[-1], tz=timezone.utc).isoformat() if times[-1] else _now()
        cid = str(uuid.uuid4())
        campaign = {
            "campaign_id": cid,
            "tenant_id": tenant_id,
            "severity": severity,
            "signal_count": len(cluster),
            "sessions": len(sessions),
            "agents": len(agents),
            "models": len(models),
            "spans_sessions": len(sessions) > 1,
            "spans_agents": len(agents) > 1,
            "spans_models": len(models) > 1,
            "techniques": techniques,
            "first_seen": first_iso,
            "last_seen": last_iso,
            "signals": cluster,
        }
        campaigns.append(campaign)

    # Highest-severity / widest-spanning first.
    campaigns.sort(key=lambda c: (_SEV_RANK.get(c["severity"], 0),
                                  c["spans_models"], c["spans_agents"], c["spans_sessions"],
                                  c["signal_count"]), reverse=True)

    if persist:
        for c in campaigns:
            _persist(c, db_path=db_path)
            if c["spans_sessions"] or c["spans_agents"] or c["spans_models"]:
                _emit_campaign(c)
    return campaigns


def _persist(campaign: dict[str, Any], *, db_path: str) -> None:
    detail = {"techniques": campaign["techniques"]}
    with _cursor(db_path) as cur:
        cur.execute(
            """
            INSERT INTO campaigns
                (campaign_id, tenant_id, severity, signal_count, sessions, agents, models,
                 spans_sessions, spans_agents, spans_models, first_seen, last_seen, detail_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (campaign["campaign_id"], campaign["tenant_id"], campaign["severity"],
             campaign["signal_count"], campaign["sessions"], campaign["agents"], campaign["models"],
             int(campaign["spans_sessions"]), int(campaign["spans_agents"]), int(campaign["spans_models"]),
             campaign["first_seen"], campaign["last_seen"], json.dumps(detail), _now()),
        )
        for s in campaign["signals"]:
            cur.execute(
                "INSERT INTO campaign_signals (row_id, campaign_id, tenant_id, signal_json) VALUES (?, ?, ?, ?)",
                (str(uuid.uuid4()), campaign["campaign_id"], campaign["tenant_id"], json.dumps(s)),
            )


def _emit_campaign(campaign: dict[str, Any]) -> None:
    try:
        from modules.security.audit_log import AuditEventType, AuditOutcome, log_event
        log_event(
            AuditEventType.CAMPAIGN_DETECTED, AuditOutcome.SUCCESS,
            tenant_id=campaign["tenant_id"], subject="campaign-correlator",
            resource=f"campaign/{campaign['campaign_id']}",
            detail={k: campaign[k] for k in
                    ("severity", "signal_count", "sessions", "agents", "models",
                     "spans_sessions", "spans_agents", "spans_models", "techniques")},
        )
    except Exception:  # noqa: BLE001
        pass


def list_campaigns(*, tenant_id: str, limit: int = 50, db_path: str = _DB_PATH) -> list[dict[str, Any]]:
    init_db(db_path)
    with _cursor(db_path) as cur:
        rows = cur.execute(
            "SELECT * FROM campaigns WHERE tenant_id=? ORDER BY created_at DESC LIMIT ?",
            (tenant_id, limit),
        ).fetchall()
    return [_row(r) for r in rows]


def get_campaign(*, tenant_id: str, campaign_id: str, db_path: str = _DB_PATH) -> dict[str, Any]:
    init_db(db_path)
    with _cursor(db_path) as cur:
        row = cur.execute("SELECT * FROM campaigns WHERE tenant_id=? AND campaign_id=?",
                          (tenant_id, campaign_id)).fetchone()
        if not row:
            raise KeyError(f"campaign {campaign_id} not found")
        sigs = cur.execute("SELECT signal_json FROM campaign_signals WHERE campaign_id=?",
                           (campaign_id,)).fetchall()
    out = _row(row)
    out["signals"] = [json.loads(s["signal_json"]) for s in sigs]
    return out


def _row(r: Any) -> dict[str, Any]:
    d = dict(r)
    for k in ("spans_sessions", "spans_agents", "spans_models"):
        d[k] = bool(d.get(k))
    d["techniques"] = json.loads(d.pop("detail_json", "{}") or "{}").get("techniques", [])
    return d
