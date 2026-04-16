"""
TokenDNA -- Behavioral DNA fingerprinting for machine/agent identity.

Computes a versioned behavioral fingerprint from an agent's recent UIS events.
Unlike token_dna.py (human session signals: IP, UA, browser), this module works
on *protocol-level behavioral patterns*: which auth methods does this agent use,
what protocols, what risk baseline, which countries, which issuers?

Deviation scoring tells the normalize pipeline how anomalous a single incoming
event is relative to that established baseline.

Public API
──────────
  compute_agent_dna(agent_id, events)           → dna dict
  compute_deviation_score(baseline_dna, event)  → float 0.0-1.0
  build_agent_dna_store()                        → None
  get_agent_dna(tenant_id, agent_id)            → dict | None
  store_agent_dna(tenant_id, dna)               → None
  refresh_agent_dna(tenant_id, agent_id)        → dict
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import threading
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

_lock = threading.Lock()

DNA_VERSION = 1


# ── DB path (shared with trust_graph / uis_store) ────────────────────────────

def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


@contextmanager
def _cursor():
    with _lock:
        db_path = _db_path()
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            cur = conn.cursor()
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


# ── Store initialisation ──────────────────────────────────────────────────────

def build_agent_dna_store() -> None:
    """Create the agent_dna table if it does not already exist."""
    with _cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_dna (
                tenant_id    TEXT NOT NULL,
                agent_id     TEXT NOT NULL,
                dna_json     TEXT NOT NULL,
                computed_at  TEXT NOT NULL,
                event_count  INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, agent_id)
            )
            """
        )


# ── Fingerprint computation ───────────────────────────────────────────────────

def _safe_get(obj: dict, *keys: str, default: Any = None) -> Any:
    """Safely traverse nested dict keys."""
    for key in keys:
        if not isinstance(obj, dict):
            return default
        obj = obj.get(key, default)  # type: ignore[assignment]
    return obj


def compute_agent_dna(agent_id: str, events: list[dict], n: int = 100) -> dict:
    """Compute a behavioral fingerprint for *agent_id* from its recent *events*.

    Uses the last *n* events (default 100).  Returns a valid DNA dict even if
    *events* is empty — all distributions will be empty / zero.

    Args:
        agent_id: Stable identifier for the agent (e.g. "agt-orchestrator").
        events:   List of UIS-normalised event dicts.
        n:        Maximum number of most-recent events to consider.

    Returns:
        DNA dict (see module docstring for schema).
    """
    # Use only the last N events (assume already newest-first from the store).
    sample = events[:n]
    count = len(sample)

    if count == 0:
        fingerprint_hash = _compute_fingerprint_hash(
            agent_id=agent_id,
            protocol_distribution={},
            auth_method_distribution={},
            typical_countries=[],
            typical_issuers=[],
        )
        return {
            "version": DNA_VERSION,
            "agent_id": agent_id,
            "computed_at": datetime.now(timezone.utc).isoformat(),
            "protocol_distribution": {},
            "auth_method_distribution": {},
            "risk_score_baseline": {"mean": 0.0, "std_dev": 0.0, "p95": 0.0},
            "mfa_rate": 0.0,
            "dpop_rate": 0.0,
            "typical_countries": [],
            "typical_issuers": [],
            "event_count": 0,
            "fingerprint_hash": fingerprint_hash,
        }

    # ── Protocol distribution ─────────────────────────────────────────────────
    proto_counter: Counter[str] = Counter()
    auth_method_counter: Counter[str] = Counter()
    country_counter: Counter[str] = Counter()
    issuer_counter: Counter[str] = Counter()
    risk_scores: list[float] = []
    mfa_count = 0
    dpop_count = 0

    for ev in sample:
        proto = _safe_get(ev, "auth", "protocol", default="unknown") or "unknown"
        proto_counter[str(proto)] += 1

        method = _safe_get(ev, "auth", "method", default="unknown") or "unknown"
        auth_method_counter[str(method)] += 1

        country = _safe_get(ev, "session", "country", default="") or ""
        if country:
            country_counter[str(country)] += 1

        issuer = _safe_get(ev, "token", "issuer", default="") or ""
        if issuer:
            issuer_counter[str(issuer)] += 1

        risk_score = _safe_get(ev, "threat", "risk_score", default=0)
        try:
            risk_scores.append(float(risk_score))
        except (TypeError, ValueError):
            risk_scores.append(0.0)

        if _safe_get(ev, "auth", "mfa_asserted", default=False):
            mfa_count += 1

        dpop_bound = _safe_get(ev, "token", "dpop_bound", default=False) or _safe_get(
            ev, "binding", "dpop_bound", default=False
        )
        if dpop_bound:
            dpop_count += 1

    # ── Distributions (fractions) ─────────────────────────────────────────────
    protocol_distribution = {k: v / count for k, v in proto_counter.items()}
    auth_method_distribution = {k: v / count for k, v in auth_method_counter.items()}

    # Typical = seen in >10% of events
    threshold = 0.10
    typical_countries = sorted(
        k for k, v in country_counter.items() if v / count > threshold
    )
    typical_issuers = sorted(
        k for k, v in issuer_counter.items() if v / count > threshold
    )

    # ── Risk score baseline ───────────────────────────────────────────────────
    mean_risk = sum(risk_scores) / count
    variance = sum((x - mean_risk) ** 2 for x in risk_scores) / count
    std_dev = math.sqrt(variance)
    sorted_scores = sorted(risk_scores)
    p95_idx = min(int(math.ceil(0.95 * count)) - 1, count - 1)
    p95 = sorted_scores[p95_idx]

    risk_baseline = {"mean": round(mean_risk, 4), "std_dev": round(std_dev, 4), "p95": round(p95, 4)}

    # ── Fingerprint hash (deterministic, stable) ──────────────────────────────
    fingerprint_hash = _compute_fingerprint_hash(
        agent_id=agent_id,
        protocol_distribution=protocol_distribution,
        auth_method_distribution=auth_method_distribution,
        typical_countries=typical_countries,
        typical_issuers=typical_issuers,
    )

    return {
        "version": DNA_VERSION,
        "agent_id": agent_id,
        "computed_at": datetime.now(timezone.utc).isoformat(),
        "protocol_distribution": protocol_distribution,
        "auth_method_distribution": auth_method_distribution,
        "risk_score_baseline": risk_baseline,
        "mfa_rate": round(mfa_count / count, 4),
        "dpop_rate": round(dpop_count / count, 4),
        "typical_countries": typical_countries,
        "typical_issuers": typical_issuers,
        "event_count": count,
        "fingerprint_hash": fingerprint_hash,
    }


def _compute_fingerprint_hash(
    *,
    agent_id: str,
    protocol_distribution: dict,
    auth_method_distribution: dict,
    typical_countries: list,
    typical_issuers: list,
) -> str:
    """SHA-256 of a canonical representation of the stable DNA fields."""
    canonical = {
        "agent_id": agent_id,
        "auth_method_distribution": dict(sorted(auth_method_distribution.items())),
        "protocol_distribution": dict(sorted(protocol_distribution.items())),
        "typical_countries": sorted(typical_countries),
        "typical_issuers": sorted(typical_issuers),
    }
    serialised = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialised.encode("utf-8")).hexdigest()


# ── Deviation scoring ─────────────────────────────────────────────────────────

def compute_deviation_score(baseline_dna: dict, event: dict) -> float:
    """Score how anomalous *event* is relative to *baseline_dna*.

    Returns a float in [0.0, 1.0].  Each signal contributes an additive
    penalty; the total is clamped to 1.0.

    Scoring rubric
    ──────────────
    New protocol (not in baseline):           +0.30
    New auth method (not in baseline):        +0.20
    Risk score > mean + 2 * std_dev:          +0.20
    New country (not in typical_countries):   +0.15
    New issuer (not in typical_issuers):      +0.15
    """
    score = 0.0

    proto = _safe_get(event, "auth", "protocol", default="") or ""
    proto_dist: dict = baseline_dna.get("protocol_distribution") or {}
    if proto_dist and proto not in proto_dist:
        score += 0.30

    method = _safe_get(event, "auth", "method", default="") or ""
    auth_dist: dict = baseline_dna.get("auth_method_distribution") or {}
    if auth_dist and method not in auth_dist:
        score += 0.20

    risk_baseline: dict = baseline_dna.get("risk_score_baseline") or {}
    mean_r = float(risk_baseline.get("mean", 0.0))
    std_r = float(risk_baseline.get("std_dev", 0.0))
    try:
        event_risk = float(_safe_get(event, "threat", "risk_score", default=0) or 0)
    except (TypeError, ValueError):
        event_risk = 0.0
    if event_risk > mean_r + 2 * std_r:
        score += 0.20

    country = _safe_get(event, "session", "country", default="") or ""
    typical_countries: list = baseline_dna.get("typical_countries") or []
    if typical_countries and country not in typical_countries:
        score += 0.15

    issuer = _safe_get(event, "token", "issuer", default="") or ""
    typical_issuers: list = baseline_dna.get("typical_issuers") or []
    if typical_issuers and issuer not in typical_issuers:
        score += 0.15

    return min(score, 1.0)


# ── Persistence ───────────────────────────────────────────────────────────────

def get_agent_dna(tenant_id: str, agent_id: str) -> dict | None:
    """Return the stored DNA for (tenant_id, agent_id), or None if not found."""
    try:
        with _cursor() as cur:
            row = cur.execute(
                "SELECT dna_json FROM agent_dna WHERE tenant_id = ? AND agent_id = ?",
                (tenant_id, agent_id),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["dna_json"])
    except Exception:  # noqa: BLE001
        return None


def store_agent_dna(tenant_id: str, dna: dict) -> None:
    """Upsert (tenant_id, agent_id) DNA record."""
    agent_id = dna.get("agent_id", "")
    computed_at = dna.get("computed_at", "")
    event_count = int(dna.get("event_count", 0))
    build_agent_dna_store()
    with _cursor() as cur:
        cur.execute(
            """
            INSERT OR REPLACE INTO agent_dna
                (tenant_id, agent_id, dna_json, computed_at, event_count)
            VALUES (?, ?, ?, ?, ?)
            """,
            (tenant_id, agent_id, json.dumps(dna), computed_at, event_count),
        )


# ── Refresh ───────────────────────────────────────────────────────────────────

def refresh_agent_dna(tenant_id: str, agent_id: str) -> dict:
    """Re-compute DNA for *agent_id* from its most recent 100 events, store and return it."""
    from modules.identity import uis_store  # noqa: PLC0415 (lazy, avoid circular)

    events = uis_store.list_events_by_agent_id(tenant_id=tenant_id, agent_id=agent_id, limit=100)
    dna = compute_agent_dna(agent_id=agent_id, events=events)
    store_agent_dna(tenant_id=tenant_id, dna=dna)
    return dna
