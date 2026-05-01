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
from datetime import datetime, timedelta, timezone
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


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso8601(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def _confidence_cap_from_metadata(metadata: dict[str, Any]) -> float:
    source = str((metadata or {}).get("source", "")).lower()
    if source in {"secure_runtime", "secure"}:
        return 1.0
    if source in {"manual_review", "analyst"}:
        return 0.95
    return 0.9


def _is_confidence_suspicious(
    severity: str,
    confidence: float,
    metadata: dict[str, Any],
    *,
    existing_signal: bool = False,
) -> bool:
    source = str((metadata or {}).get("source", "")).lower()
    trust_tier = str((metadata or {}).get("trust_tier", "")).lower()
    untrusted = source in {"unknown", "runtime", "untrusted", ""} or trust_tier in {"untrusted", "unknown"}
    if (
        untrusted
        and not existing_signal
        and severity.lower() in {"critical", "high"}
        and confidence >= 0.9
    ):
        return True
    if severity.lower() in {"critical", "high"} and confidence < 0.2:
        return True
    return False


def _rule_key(signal_type: str, signal_hash: str, mode: str) -> str:
    return f"{mode}:{signal_type}:{signal_hash}"


def _is_rule_active(expires_at: str | None) -> bool:
    parsed = _parse_iso8601(expires_at)
    if parsed is None:
        return True
    return parsed >= _utc_now()


def _lookup_rule(cur: sqlite3.Cursor, signal_type: str, signal_hash: str, mode: str) -> dict[str, Any] | None:
    row = cur.execute(
        """
        SELECT rule_key, signal_type, signal_hash, mode, reason, created_at, expires_at
        FROM network_intel_rules
        WHERE rule_key = ?
        """,
        (_rule_key(signal_type, signal_hash, mode),),
    ).fetchone()
    if not row:
        return None
    if not _is_rule_active(row["expires_at"]):
        return None
    return {
        "rule_key": row["rule_key"],
        "signal_type": row["signal_type"],
        "signal_hash": row["signal_hash"],
        "mode": row["mode"],
        "reason": row["reason"] or "",
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
    }


def _effective_confidence(*, confidence: float, tenant_count: int, last_seen: str) -> float:
    conf = max(0.0, min(float(confidence), 1.0))
    tenant_boost = min(0.2, 0.05 * max(tenant_count - 1, 0))
    age_days = 0.0
    parsed = _parse_iso8601(last_seen)
    if parsed is not None:
        age_days = max(0.0, (_utc_now() - parsed).total_seconds() / 86400.0)
    decay_rate = max(0.01, float(os.getenv("NETWORK_INTEL_DECAY_RATE_PER_DAY", "0.05")))
    decayed = conf * max(0.0, 1.0 - (decay_rate * age_days))
    return round(max(0.0, min(1.0, decayed + tenant_boost)), 4)


def _min_observation_count() -> int:
    try:
        return max(1, int(os.getenv("NETWORK_INTEL_MIN_OBSERVATIONS", "2")))
    except Exception:
        return 2


def _decay_days() -> int:
    try:
        return max(1, int(os.getenv("NETWORK_INTEL_DECAY_DAYS", "30")))
    except Exception:
        return 30


def _anti_poisoning_tenant_threshold() -> int:
    try:
        return max(1, int(os.getenv("NETWORK_INTEL_ANTI_POISONING_MIN_TENANTS", "2")))
    except Exception:
        return 2


def _anti_poisoning_threshold() -> float:
    try:
        return max(0.0, min(1.0, float(os.getenv("NETWORK_INTEL_ANTI_POISONING_CONFIDENCE_THRESHOLD", "0.7"))))
    except Exception:
        return 0.7


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
            """
            CREATE TABLE IF NOT EXISTS network_intel_rules (
                rule_key              TEXT PRIMARY KEY,
                signal_type           TEXT NOT NULL,
                signal_hash           TEXT NOT NULL,
                mode                  TEXT NOT NULL,
                reason                TEXT,
                created_at            TEXT NOT NULL,
                expires_at            TEXT
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_network_intel_type_last_seen ON network_intel_signals(signal_type, last_seen DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_network_intel_tenant_obs ON network_intel_observations(tenant_id, last_seen DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_network_intel_rules_type_hash ON network_intel_rules(signal_type, signal_hash, mode)"
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
    metadata_obj = dict(metadata or {})
    metadata_json = json.dumps(metadata_obj, sort_keys=True)
    source = str(metadata_obj.get("source", "")).lower()
    normalized_confidence = max(0.0, min(float(confidence), _confidence_cap_from_metadata(metadata_obj)))
    if _is_confidence_suspicious(severity, normalized_confidence, metadata_obj, existing_signal=False):
        return {
            "signal_key": signal_key,
            "signal_type": signal_type,
            "signal_hash": signal_hash,
            "severity": severity,
            "confidence": normalized_confidence,
            "tenant_count": 0,
            "suppressed": True,
            "suppression_reason": "anti_poisoning_confidence_gate",
        }

    with _cursor() as cur:
        suppression_rule = _lookup_rule(cur, signal_type, signal_hash, "suppress")
        allowlist_rule = _lookup_rule(cur, signal_type, signal_hash, "allow")
        if suppression_rule and not allowlist_rule:
            return {
                "signal_key": signal_key,
                "signal_type": signal_type,
                "signal_hash": signal_hash,
                "severity": severity,
                "confidence": normalized_confidence,
                "tenant_count": 0,
                "suppressed": True,
                "suppression_reason": f"rule:{suppression_rule.get('reason', 'suppressed')}",
            }
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
        if existing and _is_confidence_suspicious(
            severity,
            normalized_confidence,
            metadata_obj,
            existing_signal=True,
        ):
            return {
                "signal_key": signal_key,
                "signal_type": signal_type,
                "signal_hash": signal_hash,
                "severity": severity,
                "confidence": normalized_confidence,
                "tenant_count": int(
                    cur.execute(
                        "SELECT COUNT(*) AS cnt FROM network_intel_observations WHERE signal_key = ?",
                        (signal_key,),
                    ).fetchone()["cnt"]
                ),
                "suppressed": True,
                "suppression_reason": "anti_poisoning_confidence_gate",
            }

        tenant_count = int(
            cur.execute(
                "SELECT COUNT(*) AS cnt FROM network_intel_observations WHERE signal_key = ?",
                (signal_key,),
            ).fetchone()["cnt"]
        )

        min_obs = _min_observation_count()

        if existing:
            current_severity = existing["severity"]
            selected_severity = severity if _severity_rank(severity) >= _severity_rank(current_severity) else current_severity
            selected_confidence = max(float(existing["confidence"]), normalized_confidence)
            observation_count = int(existing["observation_count"]) + 1
            if observation_count < min_obs and not allowlist_rule:
                selected_confidence = min(selected_confidence, _anti_poisoning_threshold())
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
            initial_confidence = normalized_confidence
            if min_obs > 1 and not allowlist_rule:
                initial_confidence = min(initial_confidence, _anti_poisoning_threshold())
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
                    initial_confidence,
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
        "confidence": normalized_confidence,
        "tenant_count": tenant_count,
        "suppressed": False,
    }


def get_feed(
    *,
    limit: int = 100,
    offset: int = 0,
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
            LIMIT ? OFFSET ?
            """,
            (min_tenant_count, float(min_confidence), limit, max(int(offset), 0)),
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
            signal_hash = _hash_signal(raw_value)
            suppress_rule = _lookup_rule(cur, signal_type, signal_hash, "suppress")
            allow_rule = _lookup_rule(cur, signal_type, signal_hash, "allow")
            if suppress_rule and not allow_rule:
                continue

            tenant_count = int(row["tenant_count"])
            confidence = _effective_confidence(
                confidence=float(row["confidence"]),
                tenant_count=tenant_count,
                last_seen=str(cur.execute(
                    "SELECT last_seen FROM network_intel_signals WHERE signal_key = ?",
                    (key,),
                ).fetchone()["last_seen"]),
            )
            severity = str(row["severity"])
            if tenant_count < _anti_poisoning_tenant_threshold() or confidence < 0.5:
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


def upsert_suppression_rule(
    *,
    signal_type: str,
    raw_value: str,
    mode: str,
    reason: str = "",
    expires_at: str | None = None,
) -> dict[str, Any]:
    mode_normalized = mode.lower().strip()
    if mode_normalized not in {"suppress", "allow"}:
        raise ValueError("mode must be 'suppress' or 'allow'")
    signal_hash = _hash_signal(raw_value)
    rule_key = _rule_key(signal_type, signal_hash, mode_normalized)
    payload = {
        "rule_key": rule_key,
        "signal_type": signal_type,
        "signal_hash": signal_hash,
        "mode": mode_normalized,
        "reason": reason,
        "created_at": _iso_now(),
        "expires_at": expires_at,
    }
    with _cursor() as cur:
        cur.execute(
            """
            INSERT OR REPLACE INTO network_intel_rules(
                rule_key, signal_type, signal_hash, mode, reason, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload["rule_key"],
                payload["signal_type"],
                payload["signal_hash"],
                payload["mode"],
                payload["reason"],
                payload["created_at"],
                payload["expires_at"],
            ),
        )
    return payload


def list_suppression_rules(mode: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    with _cursor() as cur:
        if mode:
            rows = cur.execute(
                """
                SELECT rule_key, signal_type, signal_hash, mode, reason, created_at, expires_at
                FROM network_intel_rules
                WHERE mode = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (mode, limit),
            ).fetchall()
        else:
            rows = cur.execute(
                """
                SELECT rule_key, signal_type, signal_hash, mode, reason, created_at, expires_at
                FROM network_intel_rules
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
    return [
        {
            "rule_key": row["rule_key"],
            "signal_type": row["signal_type"],
            "signal_hash": row["signal_hash"],
            "mode": row["mode"],
            "reason": row["reason"] or "",
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "active": _is_rule_active(row["expires_at"]),
        }
        for row in rows
    ]


def is_suppressed(signal_type: str, raw_value: str) -> dict[str, Any]:
    signal_hash = _hash_signal(raw_value)
    with _cursor() as cur:
        suppress = _lookup_rule(cur, signal_type, signal_hash, "suppress")
        allow = _lookup_rule(cur, signal_type, signal_hash, "allow")
    return {
        "suppressed": bool(suppress and not allow),
        "suppress_rule": suppress,
        "allow_rule": allow,
    }


def apply_decay(*, older_than_days: int | None = None) -> dict[str, Any]:
    days = older_than_days if older_than_days is not None else _decay_days()
    cutoff = (_utc_now() - timedelta(days=max(days, 1))).isoformat()
    decayed = 0
    removed = 0
    with _cursor() as cur:
        rows = cur.execute(
            """
            SELECT signal_key, confidence, tenant_count, last_seen
            FROM network_intel_signals
            """
        ).fetchall()
        for row in rows:
            if str(row["last_seen"]) >= cutoff:
                continue
            new_conf = _effective_confidence(
                confidence=float(row["confidence"]),
                tenant_count=int(row["tenant_count"]),
                last_seen=str(row["last_seen"]),
            )
            if new_conf < 0.1:
                cur.execute("DELETE FROM network_intel_signals WHERE signal_key = ?", (row["signal_key"],))
                cur.execute("DELETE FROM network_intel_observations WHERE signal_key = ?", (row["signal_key"],))
                removed += 1
            else:
                cur.execute(
                    "UPDATE network_intel_signals SET confidence = ? WHERE signal_key = ?",
                    (new_conf, row["signal_key"]),
                )
                decayed += 1
    return {"decayed": decayed, "removed": removed, "cutoff": cutoff}


def status() -> dict[str, Any]:
    with _cursor() as cur:
        signal_count = int(cur.execute("SELECT COUNT(*) AS cnt FROM network_intel_signals").fetchone()["cnt"])
        observation_count = int(cur.execute("SELECT COUNT(*) AS cnt FROM network_intel_observations").fetchone()["cnt"])
        rule_count = int(cur.execute("SELECT COUNT(*) AS cnt FROM network_intel_rules").fetchone()["cnt"])
        active_rule_count = int(
            cur.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM network_intel_rules
                WHERE expires_at IS NULL OR expires_at >= ?
                """,
                (_iso_now(),),
            ).fetchone()["cnt"]
        )
        latest_signal_row = cur.execute(
            """
            SELECT last_seen
            FROM network_intel_signals
            ORDER BY last_seen DESC
            LIMIT 1
            """
        ).fetchone()
    return {
        "signals": signal_count,
        "observations": observation_count,
        "rules": rule_count,
        "active_rules": active_rule_count,
        "latest_signal_at": latest_signal_row["last_seen"] if latest_signal_row else None,
        "decay_days": _decay_days(),
        "anti_poisoning": {
            "min_observations": _min_observation_count(),
            "min_tenants": _anti_poisoning_tenant_threshold(),
            "confidence_threshold": _anti_poisoning_threshold(),
        },
    }


def upsert_suppression_rule(
    *,
    signal_type: str,
    raw_value: str,
    mode: str,
    reason: str = "",
    expires_at: str | None = None,
) -> dict[str, Any]:
    mode_normalized = mode.lower().strip()
    if mode_normalized not in {"suppress", "allow"}:
        raise ValueError("mode must be 'suppress' or 'allow'")
    signal_hash = _hash_signal(raw_value)
    rule_key = _rule_key(signal_type, signal_hash, mode_normalized)
    payload = {
        "rule_key": rule_key,
        "signal_type": signal_type,
        "signal_hash": signal_hash,
        "mode": mode_normalized,
        "reason": reason,
        "created_at": _iso_now(),
        "expires_at": expires_at,
    }
    with _cursor() as cur:
        cur.execute(
            """
            INSERT OR REPLACE INTO network_intel_rules(
                rule_key, signal_type, signal_hash, mode, reason, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload["rule_key"],
                payload["signal_type"],
                payload["signal_hash"],
                payload["mode"],
                payload["reason"],
                payload["created_at"],
                payload["expires_at"],
            ),
        )
    return payload


def list_suppression_rules(mode: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    with _cursor() as cur:
        if mode:
            rows = cur.execute(
                """
                SELECT rule_key, signal_type, signal_hash, mode, reason, created_at, expires_at
                FROM network_intel_rules
                WHERE mode = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (mode, limit),
            ).fetchall()
        else:
            rows = cur.execute(
                """
                SELECT rule_key, signal_type, signal_hash, mode, reason, created_at, expires_at
                FROM network_intel_rules
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
    return [
        {
            "rule_key": row["rule_key"],
            "signal_type": row["signal_type"],
            "signal_hash": row["signal_hash"],
            "mode": row["mode"],
            "reason": row["reason"] or "",
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "active": _is_rule_active(row["expires_at"]),
        }
        for row in rows
    ]


def is_suppressed(signal_type: str, raw_value: str) -> dict[str, Any]:
    signal_hash = _hash_signal(raw_value)
    with _cursor() as cur:
        suppress = _lookup_rule(cur, signal_type, signal_hash, "suppress")
        allow = _lookup_rule(cur, signal_type, signal_hash, "allow")
    return {
        "suppressed": bool(suppress and not allow),
        "suppress_rule": suppress,
        "allow_rule": allow,
    }
