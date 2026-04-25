"""
TokenDNA — Threat Sharing Network Flywheel

Extends ``threat_sharing`` with the four loops that turn the catalog into a
network-effect product rather than a feature:

  1. Hit recording      — every match in a recipient tenant logs back to the
                          shared catalog (anonymized via SHA-256 tenant hash).
  2. Confirmation       — operators flag hits as confirmed-true-positive.
  3. Catalog scoring    — confidence = f(confirmed hits, distinct tenants,
                          age). Updated lazily on read.
  4. Industry clustering + auto-subscribe — tenants tagged with an industry
                          vertical see digests of confirmed attacks against
                          peers, and (opt-in) auto-pull high-confidence
                          network playbooks during sync.

Tables added
------------
``network_playbook_hits``    one row per (tenant_hash, network_playbook_id, match_id)
``tenant_industry``          (tenant_id, industry, updated_at)
``tenant_subscription``      (tenant_id, auto_subscribe, min_confidence, updated_at)

Schema migrations are non-destructive — ``init_db`` is idempotent and never
ALTERs an existing column.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from modules.product import threat_sharing
from modules.storage import db_backend

logger = logging.getLogger(__name__)
_lock = threading.Lock()


# ── Constants ─────────────────────────────────────────────────────────────────

# Default minimum confidence for auto-subscribe pulls.
DEFAULT_AUTO_SUBSCRIBE_THRESHOLD = float(
    os.getenv("FLYWHEEL_AUTO_SUBSCRIBE_THRESHOLD", "0.7")
)
# Confidence decays linearly to zero over this many days for hits without
# refresh. Keeps stale playbooks from squatting on the top of the catalog.
CONFIDENCE_HALF_LIFE_DAYS = int(os.getenv("FLYWHEEL_HALF_LIFE_DAYS", "180"))

# Number of distinct tenants needed to *saturate* the breadth contribution.
# Beyond this, more tenants stop pushing the score up — protects against a
# single attacker spamming hits from many sock-puppet tenants from inflating
# scores. (The opt-in registry already gates that, but defense-in-depth.)
BREADTH_SATURATION_TENANTS = int(os.getenv("FLYWHEEL_BREADTH_SAT", "20"))


# ── DB helpers (mirror threat_sharing for consistency) ────────────────────────

def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _use_pg() -> bool:
    return db_backend.should_use_postgres()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse_iso(s: str) -> datetime:
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def _hash_tenant(tenant_id: str) -> str:
    """Same hash scheme as threat_sharing — never reversed."""
    return hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()[:32]


# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS network_playbook_hits (
    hit_id              TEXT PRIMARY KEY,
    network_playbook_id TEXT NOT NULL,
    tenant_hash         TEXT NOT NULL,
    match_id            TEXT,
    industry            TEXT,
    detected_at         TEXT NOT NULL,
    confirmed           INTEGER NOT NULL DEFAULT 0,
    confirmed_at        TEXT,
    confirmed_by        TEXT
);

CREATE INDEX IF NOT EXISTS idx_npb_hits_pb
    ON network_playbook_hits(network_playbook_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_npb_hits_industry
    ON network_playbook_hits(industry, detected_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_npb_hit_match
    ON network_playbook_hits(network_playbook_id, tenant_hash, match_id);

CREATE TABLE IF NOT EXISTS tenant_industry (
    tenant_id   TEXT PRIMARY KEY,
    industry    TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_subscription (
    tenant_id        TEXT PRIMARY KEY,
    auto_subscribe   INTEGER NOT NULL DEFAULT 0,
    min_confidence   REAL NOT NULL DEFAULT 0.7,
    updated_at       TEXT NOT NULL
);
"""


def init_db() -> None:
    if _use_pg():
        return
    threat_sharing.init_db()  # ensure base tables exist
    db_path = _db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    with _lock:
        conn = _get_conn()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class NetworkHit:
    hit_id: str
    network_playbook_id: str
    tenant_hash: str
    match_id: str | None
    industry: str | None
    detected_at: str
    confirmed: bool
    confirmed_at: str | None
    confirmed_by: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "hit_id": self.hit_id,
            "network_playbook_id": self.network_playbook_id,
            # tenant_hash intentionally exposed (not the raw tenant_id)
            "tenant_hash": self.tenant_hash,
            "match_id": self.match_id,
            "industry": self.industry,
            "detected_at": self.detected_at,
            "confirmed": self.confirmed,
            "confirmed_at": self.confirmed_at,
            "confirmed_by": self.confirmed_by,
        }


# ── Hit recording ─────────────────────────────────────────────────────────────

def record_network_hit(
    tenant_id: str,
    network_playbook_id: str,
    match_id: str | None = None,
) -> dict[str, Any] | None:
    """
    Log that a network-sourced playbook fired in this tenant. Idempotent on
    (network_playbook_id, tenant_hash, match_id). Returns the new hit row, or
    ``None`` if the hit was already recorded.
    """
    if _use_pg():
        return None
    industry = get_tenant_industry(tenant_id)
    th = _hash_tenant(tenant_id)
    now = _iso(_now())
    hit_id = f"nhit:{uuid.uuid4().hex[:24]}"
    with _lock:
        conn = _get_conn()
        try:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO network_playbook_hits
                    (hit_id, network_playbook_id, tenant_hash, match_id,
                     industry, detected_at, confirmed)
                VALUES (?, ?, ?, ?, ?, ?, 0)
                """,
                (hit_id, network_playbook_id, th, match_id or "", industry, now),
            )
            conn.commit()
            if cur.rowcount == 0:
                return None
            return {
                "hit_id": hit_id,
                "network_playbook_id": network_playbook_id,
                "tenant_hash": th,
                "match_id": match_id,
                "industry": industry,
                "detected_at": now,
                "confirmed": False,
            }
        finally:
            conn.close()


def confirm_hit(hit_id: str, confirmed_by: str) -> bool:
    """Mark a hit as a confirmed-true-positive. Returns True iff a row was
    updated. Idempotent — second call on an already-confirmed hit returns
    False."""
    if _use_pg():
        return False
    now = _iso(_now())
    with _lock:
        conn = _get_conn()
        try:
            cur = conn.execute(
                """
                UPDATE network_playbook_hits
                SET confirmed = 1, confirmed_at = ?, confirmed_by = ?
                WHERE hit_id = ? AND confirmed = 0
                """,
                (now, confirmed_by, hit_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


def get_hits(
    network_playbook_id: str,
    confirmed_only: bool = False,
    limit: int = 200,
) -> list[NetworkHit]:
    if _use_pg():
        return []
    with _lock:
        conn = _get_conn()
        try:
            sql = "SELECT * FROM network_playbook_hits WHERE network_playbook_id=?"
            params: list[Any] = [network_playbook_id]
            if confirmed_only:
                sql += " AND confirmed=1"
            sql += " ORDER BY detected_at DESC LIMIT ?"
            params.append(min(int(limit), 500))
            rows = conn.execute(sql, tuple(params)).fetchall()
            return [
                NetworkHit(
                    hit_id=r["hit_id"],
                    network_playbook_id=r["network_playbook_id"],
                    tenant_hash=r["tenant_hash"],
                    match_id=r["match_id"] or None,
                    industry=r["industry"],
                    detected_at=r["detected_at"],
                    confirmed=bool(r["confirmed"]),
                    confirmed_at=r["confirmed_at"],
                    confirmed_by=r["confirmed_by"],
                )
                for r in rows
            ]
        finally:
            conn.close()


# ── Catalog scoring ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PlaybookScore:
    network_playbook_id: str
    confidence: float       # 0..1
    confirmed_hits: int
    total_hits: int
    distinct_tenants: int
    last_hit_at: str | None
    age_decay: float        # 0..1 — multiplier applied for staleness

    def as_dict(self) -> dict[str, Any]:
        return {
            "network_playbook_id": self.network_playbook_id,
            "confidence": self.confidence,
            "confirmed_hits": self.confirmed_hits,
            "total_hits": self.total_hits,
            "distinct_tenants": self.distinct_tenants,
            "last_hit_at": self.last_hit_at,
            "age_decay": self.age_decay,
        }


def score_network_playbook(network_playbook_id: str) -> PlaybookScore:
    """
    Confidence is a function of:
      - confirmed hit volume (saturating curve)
      - distinct tenant breadth (saturating at BREADTH_SATURATION_TENANTS)
      - age decay (linear ramp to zero at CONFIDENCE_HALF_LIFE_DAYS * 2 if no
        new hits)

    Pure function of the hit table — re-derived on each call so the score
    always reflects current ground truth.
    """
    if _use_pg():
        return PlaybookScore(network_playbook_id, 0.0, 0, 0, 0, None, 0.0)
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN confirmed = 1 THEN 1 ELSE 0 END) AS confirmed,
                    COUNT(DISTINCT tenant_hash) AS tenants,
                    MAX(detected_at) AS last_hit
                FROM network_playbook_hits
                WHERE network_playbook_id = ?
                """,
                (network_playbook_id,),
            ).fetchone()
        finally:
            conn.close()

    if not row or row["total"] == 0:
        return PlaybookScore(network_playbook_id, 0.0, 0, 0, 0, None, 1.0)

    total = int(row["total"])
    confirmed = int(row["confirmed"] or 0)
    tenants = int(row["tenants"])
    last_hit = row["last_hit"]

    # Confirmed-hits component: 1 - 1/(1 + confirmed/3) — fast ramp, saturates.
    hit_component = 1.0 - (1.0 / (1.0 + (confirmed / 3.0))) if confirmed else 0.0
    # Breadth component: distinct tenants normalized to saturation.
    breadth_component = min(tenants, BREADTH_SATURATION_TENANTS) / float(
        BREADTH_SATURATION_TENANTS
    )
    # Combine: weighted geometric mean leans on confirmation but rewards breadth.
    raw = (0.7 * hit_component) + (0.3 * breadth_component)

    # Age decay.
    decay = 1.0
    if last_hit:
        try:
            delta = _now() - _parse_iso(last_hit)
            days = max(0.0, delta.total_seconds() / 86400.0)
            window = CONFIDENCE_HALF_LIFE_DAYS * 2.0
            decay = max(0.0, 1.0 - (days / window))
        except (ValueError, TypeError):
            decay = 1.0

    confidence = round(raw * decay, 4)
    return PlaybookScore(
        network_playbook_id=network_playbook_id,
        confidence=confidence,
        confirmed_hits=confirmed,
        total_hits=total,
        distinct_tenants=tenants,
        last_hit_at=last_hit,
        age_decay=round(decay, 4),
    )


def list_scored_catalog(
    limit: int = 100,
    min_confidence: float = 0.0,
) -> list[dict[str, Any]]:
    """Browse the full catalog with derived confidence scores attached.
    Sorted by confidence desc."""
    pbs = threat_sharing.list_network_playbooks(limit=limit)
    out: list[dict[str, Any]] = []
    for pb in pbs:
        score = score_network_playbook(pb["network_playbook_id"])
        if score.confidence < min_confidence:
            continue
        out.append({**pb, "score": score.as_dict()})
    out.sort(key=lambda r: r["score"]["confidence"], reverse=True)
    return out


# ── Industry tagging ──────────────────────────────────────────────────────────

VALID_INDUSTRIES: frozenset[str] = frozenset({
    "finance", "healthcare", "saas", "retail", "manufacturing",
    "government", "education", "energy", "media", "technology", "other",
})


def set_tenant_industry(tenant_id: str, industry: str) -> dict[str, Any]:
    industry = (industry or "").strip().lower()
    if industry not in VALID_INDUSTRIES:
        raise ValueError(f"unknown_industry:{industry}")
    if _use_pg():
        return {"tenant_id": tenant_id, "industry": industry}
    now = _iso(_now())
    with _lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                INSERT INTO tenant_industry (tenant_id, industry, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    industry = excluded.industry,
                    updated_at = excluded.updated_at
                """,
                (tenant_id, industry, now),
            )
            conn.commit()
        finally:
            conn.close()
    return {"tenant_id": tenant_id, "industry": industry, "updated_at": now}


def get_tenant_industry(tenant_id: str) -> str | None:
    if _use_pg():
        return None
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT industry FROM tenant_industry WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
            return row["industry"] if row else None
        finally:
            conn.close()


# ── Industry digest ───────────────────────────────────────────────────────────

def get_industry_digest(
    tenant_id: str,
    days: int = 7,
    limit: int = 25,
) -> dict[str, Any]:
    """
    Return a 'this attack hit N peers in your vertical' digest. Tenants
    without an industry tag get an empty digest. Tenants in the same
    industry are counted via tenant_hash so no raw IDs leak.
    """
    industry = get_tenant_industry(tenant_id)
    if not industry:
        return {
            "tenant_id": tenant_id,
            "industry": None,
            "since": None,
            "items": [],
            "message": "no_industry_tag",
        }
    if _use_pg():
        return {"tenant_id": tenant_id, "industry": industry, "items": []}

    since_dt = _now() - timedelta(days=max(1, int(days)))
    since = _iso(since_dt)
    own_hash = _hash_tenant(tenant_id)
    with _lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                """
                SELECT
                    h.network_playbook_id,
                    COUNT(DISTINCT h.tenant_hash) AS peer_tenants,
                    SUM(CASE WHEN h.confirmed = 1 THEN 1 ELSE 0 END) AS confirmed,
                    COUNT(*) AS total_hits,
                    MAX(h.detected_at) AS last_hit_at,
                    np.name AS playbook_name,
                    np.severity AS severity
                FROM network_playbook_hits h
                JOIN network_playbooks np
                  ON np.network_playbook_id = h.network_playbook_id
                WHERE h.industry = ?
                  AND h.detected_at >= ?
                  AND h.tenant_hash <> ?     -- exclude requesting tenant
                  AND np.revoked = 0
                GROUP BY h.network_playbook_id
                ORDER BY confirmed DESC, peer_tenants DESC, last_hit_at DESC
                LIMIT ?
                """,
                (industry, since, own_hash, min(int(limit), 100)),
            ).fetchall()
        finally:
            conn.close()
    items = [
        {
            "network_playbook_id": r["network_playbook_id"],
            "playbook_name": r["playbook_name"],
            "severity": r["severity"],
            "peer_tenants": int(r["peer_tenants"]),
            "confirmed_hits": int(r["confirmed"] or 0),
            "total_hits": int(r["total_hits"]),
            "last_hit_at": r["last_hit_at"],
        }
        for r in rows
    ]
    return {
        "tenant_id": tenant_id,
        "industry": industry,
        "since": since,
        "items": items,
        "count": len(items),
    }


# ── Auto-subscribe ────────────────────────────────────────────────────────────

def set_auto_subscribe(
    tenant_id: str,
    enabled: bool,
    min_confidence: float | None = None,
) -> dict[str, Any]:
    if _use_pg():
        return {"tenant_id": tenant_id, "auto_subscribe": enabled}
    if min_confidence is None:
        min_confidence = DEFAULT_AUTO_SUBSCRIBE_THRESHOLD
    min_confidence = max(0.0, min(1.0, float(min_confidence)))
    now = _iso(_now())
    with _lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                INSERT INTO tenant_subscription
                    (tenant_id, auto_subscribe, min_confidence, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    auto_subscribe = excluded.auto_subscribe,
                    min_confidence = excluded.min_confidence,
                    updated_at = excluded.updated_at
                """,
                (tenant_id, 1 if enabled else 0, min_confidence, now),
            )
            conn.commit()
        finally:
            conn.close()
    return {
        "tenant_id": tenant_id,
        "auto_subscribe": bool(enabled),
        "min_confidence": min_confidence,
        "updated_at": now,
    }


def get_subscription(tenant_id: str) -> dict[str, Any]:
    if _use_pg():
        return {
            "tenant_id": tenant_id,
            "auto_subscribe": False,
            "min_confidence": DEFAULT_AUTO_SUBSCRIBE_THRESHOLD,
        }
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM tenant_subscription WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
        finally:
            conn.close()
    if not row:
        return {
            "tenant_id": tenant_id,
            "auto_subscribe": False,
            "min_confidence": DEFAULT_AUTO_SUBSCRIBE_THRESHOLD,
            "updated_at": None,
        }
    return {
        "tenant_id": row["tenant_id"],
        "auto_subscribe": bool(row["auto_subscribe"]),
        "min_confidence": float(row["min_confidence"]),
        "updated_at": row["updated_at"],
    }


def auto_sync_subscribed(tenant_id: str) -> dict[str, Any]:
    """
    Honour the tenant's auto-subscribe preference. Pulls every network
    playbook whose derived confidence ≥ min_confidence and is not already
    propagated. Returns ``{added: int, candidates_evaluated: int}``.

    Falls back to a vanilla ``threat_sharing.sync_network_playbooks`` if the
    tenant has not enabled auto-subscribe — keeps the behaviour predictable
    and the surface backwards-compatible.
    """
    sub = get_subscription(tenant_id)
    if not sub["auto_subscribe"]:
        return {
            "tenant_id": tenant_id,
            "auto_subscribe": False,
            "added": threat_sharing.sync_network_playbooks(tenant_id),
            "candidates_evaluated": 0,
        }
    if not threat_sharing.is_opted_in(tenant_id):
        return {
            "tenant_id": tenant_id,
            "auto_subscribe": True,
            "added": 0,
            "candidates_evaluated": 0,
        }

    catalog = threat_sharing.list_network_playbooks(limit=500)
    threshold = float(sub["min_confidence"])
    candidates = 0
    added = 0
    for pb in catalog:
        score = score_network_playbook(pb["network_playbook_id"])
        if score.confidence < threshold:
            continue
        candidates += 1
        result = threat_sharing.propagate_to_tenant(
            tenant_id, pb["network_playbook_id"]
        )
        if result and not result.get("deduplicated"):
            added += 1
    return {
        "tenant_id": tenant_id,
        "auto_subscribe": True,
        "min_confidence": threshold,
        "added": added,
        "candidates_evaluated": candidates,
    }
