"""
TokenDNA -- Cross-tenant anonymized identity threat intelligence feed.

Records high-risk indicators in anonymized form and exposes aggregate feed
signals that can be used to increase runtime risk scoring.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any


_lock = threading.Lock()


def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _salt() -> str:
    return os.getenv("NETWORK_INTEL_HASH_SALT", "tokendna-network-intel-salt")


def _hash_signal(raw_value: str) -> str:
    material = f"{_salt()}:{raw_value}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _signal_key(signal_type: str, raw_value: str) -> str:
    return f"{signal_type}:{_hash_signal(raw_value)}"


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def _cursor():
    with _lock:
        conn = _get_conn()
        try:
            cur = conn.cursor()
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def _severity_rank(severity: str) -> int:
    mapping = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return mapping.get((severity or "medium").lower(), 2)


def init_db() -> None:
    db_path = _db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    with _cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS network_intel_signals (
                signal_key            TEXT PRIMARY KEY,
                signal_type           TEXT NOT NULL,
                signal_hash           TEXT NOT NULL,
                severity              TEXT NOT NULL,
                confidence            REAL NOT NULL,
                first_seen            TEXT NOT NULL,
                last_seen             TEXT NOT NULL,
                observation_count     INTEGER NOT NULL,
                tenant_count          INTEGER NOT NULL,
                metadata_json         TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS network_intel_observations (
                signal_key            TEXT NOT NULL,
                tenant_id             TEXT NOT NULL,
                first_seen            TEXT NOT NULL,
                last_seen             TEXT NOT NULL,
                PRIMARY KEY (signal_key, tenant_id)
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_network_intel_type_last_seen ON network_intel_signals(signal_type, last_seen DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_network_intel_tenant_obs ON network_intel_observations(tenant_id, last_seen DESC)"
        )


def record_signal(
    *,
    tenant_id: str,
    signal_type: str,
    raw_value: str,
    severity: str = "medium",
    confidence: float = 0.5,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    now = _iso_now()
    signal_hash = _hash_signal(raw_value)
    signal_key = f"{signal_type}:{signal_hash}"
    metadata_json = json.dumps(metadata or {}, sort_keys=True)

    with _cursor() as cur:
        cur.execute(
            """
            INSERT INTO network_intel_observations(signal_key, tenant_id, first_seen, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(signal_key, tenant_id)
            DO UPDATE SET last_seen = excluded.last_seen
            """,
            (signal_key, tenant_id, now, now),
        )

        existing = cur.execute(
            """
            SELECT severity, confidence, observation_count
            FROM network_intel_signals
            WHERE signal_key = ?
            """,
            (signal_key,),
        ).fetchone()

        tenant_count = int(
            cur.execute(
                "SELECT COUNT(*) AS cnt FROM network_intel_observations WHERE signal_key = ?",
                (signal_key,),
            ).fetchone()["cnt"]
        )

        if existing:
            current_severity = existing["severity"]
            selected_severity = severity if _severity_rank(severity) >= _severity_rank(current_severity) else current_severity
            selected_confidence = max(float(existing["confidence"]), float(confidence))
            observation_count = int(existing["observation_count"]) + 1
            cur.execute(
                """
                UPDATE network_intel_signals
                SET severity = ?, confidence = ?, last_seen = ?, observation_count = ?, tenant_count = ?, metadata_json = ?
                WHERE signal_key = ?
                """,
                (
                    selected_severity,
                    selected_confidence,
                    now,
                    observation_count,
                    tenant_count,
                    metadata_json,
                    signal_key,
                ),
            )
        else:
            cur.execute(
                """
                INSERT INTO network_intel_signals(
                    signal_key, signal_type, signal_hash, severity, confidence,
                    first_seen, last_seen, observation_count, tenant_count, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    signal_key,
                    signal_type,
                    signal_hash,
                    severity,
                    float(confidence),
                    now,
                    now,
                    1,
                    tenant_count,
                    metadata_json,
                ),
            )

    return {
        "signal_key": signal_key,
        "signal_type": signal_type,
        "signal_hash": signal_hash,
        "severity": severity,
        "confidence": float(confidence),
        "tenant_count": tenant_count,
    }


def get_feed(
    *,
    limit: int = 100,
    min_tenant_count: int = 2,
    min_confidence: float = 0.6,
) -> list[dict[str, Any]]:
    with _cursor() as cur:
        rows = cur.execute(
            """
            SELECT signal_key, signal_type, signal_hash, severity, confidence,
                   first_seen, last_seen, observation_count, tenant_count, metadata_json
            FROM network_intel_signals
            WHERE tenant_count >= ? AND confidence >= ?
            ORDER BY tenant_count DESC, confidence DESC, last_seen DESC
            LIMIT ?
            """,
            (min_tenant_count, float(min_confidence), limit),
        ).fetchall()
    return [
        {
            "signal_key": row["signal_key"],
            "signal_type": row["signal_type"],
            "signal_hash": row["signal_hash"],
            "severity": row["severity"],
            "confidence": float(row["confidence"]),
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "observation_count": int(row["observation_count"]),
            "tenant_count": int(row["tenant_count"]),
            "metadata": json.loads(row["metadata_json"]),
        }
        for row in rows
    ]


def assess_runtime_penalty(candidates: list[dict[str, str]]) -> dict[str, Any]:
    """
    Estimate extra risk penalty from cross-tenant anonymized intelligence.

    candidates: list of {"signal_type": "...", "raw_value": "..."}
    """
    if not candidates:
        return {"penalty": 0, "reasons": [], "hits": []}

    penalty = 0
    reasons: list[str] = []
    hits: list[dict[str, Any]] = []

    with _cursor() as cur:
        for candidate in candidates:
            signal_type = candidate.get("signal_type", "")
            raw_value = candidate.get("raw_value", "")
            if not signal_type or not raw_value:
                continue
            key = _signal_key(signal_type, raw_value)
            row = cur.execute(
                """
                SELECT severity, confidence, tenant_count, observation_count
                FROM network_intel_signals
                WHERE signal_key = ?
                """,
                (key,),
            ).fetchone()
            if not row:
                continue

            tenant_count = int(row["tenant_count"])
            confidence = float(row["confidence"])
            severity = str(row["severity"])
            if tenant_count < 2 or confidence < 0.5:
                continue

            if severity == "critical":
                p = 30
            elif severity == "high":
                p = 20
            elif severity == "medium":
                p = 10
            else:
                p = 5
            penalty += p
            reasons.append(f"network_intel:{signal_type}:{severity}:t{tenant_count}")
            hits.append(
                {
                    "signal_type": signal_type,
                    "severity": severity,
                    "confidence": confidence,
                    "tenant_count": tenant_count,
                    "penalty": p,
                }
            )

    return {"penalty": min(penalty, 40), "reasons": reasons, "hits": hits}
