"""
TokenDNA -- External trust federation registry and quorum verification.

Maintains verifier identity documents and signed federation attestations so
runtime policy can require independent verifier quorum for high-risk actions.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from modules.identity.trust_authority import build_signer_for_algorithm, build_signer_for_key

_lock = threading.Lock()


def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def init_db() -> None:
    db_path = _db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    with _cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS trust_federation_verifiers (
                verifier_id          TEXT PRIMARY KEY,
                tenant_id            TEXT NOT NULL,
                name                 TEXT NOT NULL,
                trust_score          REAL NOT NULL DEFAULT 0.5,
                issuer               TEXT NOT NULL,
                jwks_uri             TEXT,
                metadata_json        TEXT NOT NULL,
                status               TEXT NOT NULL DEFAULT 'active',
                created_at           TEXT NOT NULL,
                updated_at           TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS trust_federation_attestations (
                federation_id        TEXT PRIMARY KEY,
                tenant_id            TEXT NOT NULL,
                verifier_id          TEXT NOT NULL,
                target_type          TEXT NOT NULL,
                target_id            TEXT NOT NULL,
                verdict              TEXT NOT NULL,
                confidence           REAL NOT NULL,
                attested_at          TEXT NOT NULL,
                expires_at           TEXT,
                signature_alg        TEXT NOT NULL,
                ca_key_id            TEXT NOT NULL,
                signature            TEXT NOT NULL,
                payload_json         TEXT NOT NULL,
                metadata_json        TEXT NOT NULL
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_trust_fed_verifier_tenant_status ON trust_federation_verifiers(tenant_id, status, trust_score DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_trust_fed_attest_target ON trust_federation_attestations(tenant_id, target_type, target_id, attested_at DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_trust_fed_attest_verifier ON trust_federation_attestations(tenant_id, verifier_id, attested_at DESC)"
        )
        for ddl in (
            "ALTER TABLE trust_federation_verifiers ADD COLUMN key_expires_at TEXT",
            "ALTER TABLE trust_federation_verifiers ADD COLUMN revoked_at TEXT",
            "ALTER TABLE trust_federation_verifiers ADD COLUMN revocation_reason TEXT",
            "ALTER TABLE trust_federation_verifiers ADD COLUMN last_rotated_at TEXT",
            "ALTER TABLE trust_federation_verifiers ADD COLUMN key_version TEXT",
        ):
            try:
                cur.execute(ddl)
            except Exception:
                pass


def upsert_verifier(
    *,
    tenant_id: str,
    verifier_id: str | None,
    name: str,
    trust_score: float,
    issuer: str,
    jwks_uri: str | None = None,
    metadata: dict[str, Any] | None = None,
    status: str = "active",
) -> dict[str, Any]:
    now = _iso_now()
    normalized_score = max(0.0, min(float(trust_score), 1.0))
    row = {
        "verifier_id": str(verifier_id or uuid.uuid4().hex),
        "tenant_id": tenant_id,
        "name": name,
        "trust_score": normalized_score,
        "issuer": issuer,
        "jwks_uri": (jwks_uri or "").strip() or None,
        "metadata": metadata or {},
        "status": (status or "active").strip().lower(),
        "key_expires_at": (str((metadata or {}).get("key_expires_at", "")).strip() or None),
        "revoked_at": (str((metadata or {}).get("revoked_at", "")).strip() or None),
        "revocation_reason": (str((metadata or {}).get("revocation_reason", "")).strip() or None),
        "last_rotated_at": (str((metadata or {}).get("last_rotated_at", "")).strip() or None),
        "key_version": (str((metadata or {}).get("key_version", "")).strip() or None),
        "created_at": now,
        "updated_at": now,
    }
    with _cursor() as cur:
        existing = cur.execute(
            """
            SELECT created_at
            FROM trust_federation_verifiers
            WHERE verifier_id = ? AND tenant_id = ?
            """,
            (row["verifier_id"], tenant_id),
        ).fetchone()
        if existing:
            row["created_at"] = str(existing["created_at"])
        cur.execute(
            """
            INSERT OR REPLACE INTO trust_federation_verifiers(
                verifier_id, tenant_id, name, trust_score, issuer, jwks_uri,
                metadata_json, status, key_expires_at, revoked_at, revocation_reason,
                last_rotated_at, key_version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["verifier_id"],
                tenant_id,
                row["name"],
                row["trust_score"],
                row["issuer"],
                row["jwks_uri"],
                json.dumps(row["metadata"], sort_keys=True),
                row["status"],
                row["key_expires_at"],
                row["revoked_at"],
                row["revocation_reason"],
                row["last_rotated_at"],
                row["key_version"],
                row["created_at"],
                row["updated_at"],
            ),
        )
    return row


def list_verifiers(
    *,
    tenant_id: str,
    status: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    with _cursor() as cur:
        if status:
            rows = cur.execute(
                """
                SELECT verifier_id, tenant_id, name, trust_score, issuer, jwks_uri,
                       metadata_json, status, key_expires_at, revoked_at, revocation_reason,
                       last_rotated_at, key_version, created_at, updated_at
                FROM trust_federation_verifiers
                WHERE tenant_id = ? AND status = ?
                ORDER BY trust_score DESC, updated_at DESC
                LIMIT ?
                """,
                (tenant_id, status, min(max(limit, 1), 200)),
            ).fetchall()
        else:
            rows = cur.execute(
                """
                SELECT verifier_id, tenant_id, name, trust_score, issuer, jwks_uri,
                       metadata_json, status, key_expires_at, revoked_at, revocation_reason,
                       last_rotated_at, key_version, created_at, updated_at
                FROM trust_federation_verifiers
                WHERE tenant_id = ?
                ORDER BY trust_score DESC, updated_at DESC
                LIMIT ?
                """,
                (tenant_id, min(max(limit, 1), 200)),
            ).fetchall()
    return [
        {
            "verifier_id": row["verifier_id"],
            "tenant_id": row["tenant_id"],
            "name": row["name"],
            "trust_score": float(row["trust_score"]),
            "issuer": row["issuer"],
            "jwks_uri": row["jwks_uri"],
            "metadata": json.loads(row["metadata_json"]),
            "status": row["status"],
            "key_expires_at": row["key_expires_at"],
            "revoked_at": row["revoked_at"],
            "revocation_reason": row["revocation_reason"] or "",
            "last_rotated_at": row["last_rotated_at"],
            "key_version": row["key_version"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
        for row in rows
    ]


def revoke_verifier(
    *,
    tenant_id: str,
    verifier_id: str,
    actor: str,
    reason: str,
) -> dict[str, Any] | None:
    now = _iso_now()
    with _cursor() as cur:
        existing = cur.execute(
            """
            SELECT verifier_id
            FROM trust_federation_verifiers
            WHERE tenant_id = ? AND verifier_id = ?
            """,
            (tenant_id, verifier_id),
        ).fetchone()
        if not existing:
            return None
        cur.execute(
            """
            UPDATE trust_federation_verifiers
            SET status = 'revoked',
                revoked_at = ?,
                revocation_reason = ?,
                updated_at = ?
            WHERE tenant_id = ? AND verifier_id = ?
            """,
            (now, reason, now, tenant_id, verifier_id),
        )
    rows = list_verifiers(tenant_id=tenant_id, limit=500)
    verifier = next((v for v in rows if str(v.get("verifier_id")) == verifier_id), None)
    if verifier:
        verifier["revoked_by"] = actor
    return verifier


def rotate_verifier_key(
    *,
    tenant_id: str,
    verifier_id: str,
    actor: str,
    key_version: str,
    key_expires_at: str | None = None,
) -> dict[str, Any] | None:
    now = _iso_now()
    with _cursor() as cur:
        existing = cur.execute(
            """
            SELECT verifier_id
            FROM trust_federation_verifiers
            WHERE tenant_id = ? AND verifier_id = ?
            """,
            (tenant_id, verifier_id),
        ).fetchone()
        if not existing:
            return None
        cur.execute(
            """
            UPDATE trust_federation_verifiers
            SET status = 'active',
                key_version = ?,
                key_expires_at = ?,
                revoked_at = NULL,
                revocation_reason = NULL,
                last_rotated_at = ?,
                updated_at = ?
            WHERE tenant_id = ? AND verifier_id = ?
            """,
            (key_version, key_expires_at, now, now, tenant_id, verifier_id),
        )
    rows = list_verifiers(tenant_id=tenant_id, limit=500)
    verifier = next((v for v in rows if str(v.get("verifier_id")) == verifier_id), None)
    if verifier:
        verifier["rotated_by"] = actor
    return verifier


def verifier_lifecycle_status(
    *,
    tenant_id: str,
    verifier_id: str,
) -> dict[str, Any] | None:
    rows = list_verifiers(tenant_id=tenant_id, limit=500)
    verifier = next((v for v in rows if str(v.get("verifier_id")) == verifier_id), None)
    if verifier is None:
        return None
    now = datetime.now(timezone.utc)
    expires_at = str(verifier.get("key_expires_at") or "")
    expires_dt: datetime | None = None
    if expires_at:
        try:
            expires_dt = datetime.fromisoformat(expires_at)
        except Exception:
            expires_dt = None
    is_expired = bool(expires_dt and expires_dt <= now)
    return {
        "verifier_id": verifier_id,
        "status": verifier.get("status"),
        "is_expired": is_expired,
        "key_expires_at": verifier.get("key_expires_at"),
        "last_rotated_at": verifier.get("last_rotated_at"),
        "key_version": verifier.get("key_version"),
        "revoked_at": verifier.get("revoked_at"),
        "revocation_reason": verifier.get("revocation_reason"),
    }


def _payload(
    *,
    verifier_id: str,
    target_type: str,
    target_id: str,
    verdict: str,
    confidence: float,
    attested_at: str,
    expires_at: str | None,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    return {
        "verifier_id": verifier_id,
        "target_type": target_type,
        "target_id": target_id,
        "verdict": verdict,
        "confidence": confidence,
        "attested_at": attested_at,
        "expires_at": expires_at,
        "metadata": metadata,
    }


def issue_federation_attestation(
    *,
    tenant_id: str,
    verifier_id: str,
    target_type: str,
    target_id: str,
    verdict: str,
    confidence: float,
    expires_at: str | None = None,
    metadata: dict[str, Any] | None = None,
    key_id: str | None = None,
    algorithm: str = "HS256",
) -> dict[str, Any]:
    now = _iso_now()
    normalized_verdict = (verdict or "allow").strip().lower()
    if normalized_verdict not in {"allow", "step_up", "block"}:
        raise ValueError("verdict must be one of: allow, step_up, block")
    normalized_conf = max(0.0, min(float(confidence), 1.0))
    payload = _payload(
        verifier_id=verifier_id,
        target_type=target_type,
        target_id=target_id,
        verdict=normalized_verdict,
        confidence=normalized_conf,
        attested_at=now,
        expires_at=expires_at,
        metadata=metadata or {},
    )
    signer = (
        build_signer_for_key(key_id, algorithm)
        if key_id
        else build_signer_for_algorithm(algorithm)
    )
    sign_result = signer.sign(payload)
    row = {
        "federation_id": uuid.uuid4().hex,
        "tenant_id": tenant_id,
        "verifier_id": verifier_id,
        "target_type": target_type,
        "target_id": target_id,
        "verdict": normalized_verdict,
        "confidence": normalized_conf,
        "attested_at": now,
        "expires_at": expires_at,
        "signature_alg": sign_result.algorithm,
        "ca_key_id": sign_result.key_id,
        "signature": sign_result.signature,
        "payload": payload,
        "metadata": metadata or {},
    }
    with _cursor() as cur:
        cur.execute(
            """
            INSERT INTO trust_federation_attestations(
                federation_id, tenant_id, verifier_id, target_type, target_id,
                verdict, confidence, attested_at, expires_at, signature_alg,
                ca_key_id, signature, payload_json, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["federation_id"],
                tenant_id,
                verifier_id,
                target_type,
                target_id,
                row["verdict"],
                row["confidence"],
                row["attested_at"],
                row["expires_at"],
                row["signature_alg"],
                row["ca_key_id"],
                row["signature"],
                json.dumps(row["payload"], sort_keys=True),
                json.dumps(row["metadata"], sort_keys=True),
            ),
        )
    return row


def list_federation_attestations(
    *,
    tenant_id: str,
    target_type: str | None = None,
    target_id: str | None = None,
    verifier_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    params: list[Any] = [tenant_id]
    where = ["tenant_id = ?"]
    if target_type:
        where.append("target_type = ?")
        params.append(target_type)
    if target_id:
        where.append("target_id = ?")
        params.append(target_id)
    if verifier_id:
        where.append("verifier_id = ?")
        params.append(verifier_id)
    params.append(min(max(limit, 1), 200))
    with _cursor() as cur:
        rows = cur.execute(
            f"""
            SELECT federation_id, tenant_id, verifier_id, target_type, target_id,
                   verdict, confidence, attested_at, expires_at, signature_alg,
                   ca_key_id, signature, payload_json, metadata_json
            FROM trust_federation_attestations
            WHERE {' AND '.join(where)}
            ORDER BY attested_at DESC
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
    return [
        {
            "federation_id": row["federation_id"],
            "tenant_id": row["tenant_id"],
            "verifier_id": row["verifier_id"],
            "target_type": row["target_type"],
            "target_id": row["target_id"],
            "verdict": row["verdict"],
            "confidence": float(row["confidence"]),
            "attested_at": row["attested_at"],
            "expires_at": row["expires_at"],
            "signature_alg": row["signature_alg"],
            "ca_key_id": row["ca_key_id"],
            "signature": row["signature"],
            "payload": json.loads(row["payload_json"]),
            "metadata": json.loads(row["metadata_json"]),
        }
        for row in rows
    ]


def verify_attestation_signature(attestation: dict[str, Any]) -> dict[str, Any]:
    payload = attestation.get("payload")
    signature = attestation.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        return {"valid": False, "reason": "invalid_payload"}
    algorithm = str(attestation.get("signature_alg", "HS256")).upper()
    key_id = str(attestation.get("ca_key_id") or "").strip()
    signer = (
        build_signer_for_key(key_id, algorithm)
        if key_id
        else build_signer_for_algorithm(algorithm)
    )
    ok = signer.verify(payload, signature)
    return {
        "valid": bool(ok),
        "reason": "ok" if ok else "invalid_signature",
        "federation_id": attestation.get("federation_id"),
    }


def evaluate_federation_quorum(
    *,
    tenant_id: str,
    target_type: str,
    target_id: str,
    min_verifiers: int = 2,
    min_trust_score: float = 0.6,
    min_confidence: float = 0.6,
) -> dict[str, Any]:
    attestations = list_federation_attestations(
        tenant_id=tenant_id,
        target_type=target_type,
        target_id=target_id,
        limit=500,
    )
    verifier_map = {
        row["verifier_id"]: row
        for row in list_verifiers(tenant_id=tenant_id, status="active", limit=500)
    }
    unique_passed: dict[str, dict[str, Any]] = {}
    verdict_weights = {"allow": 0.0, "step_up": 0.0, "block": 0.0}
    rejected: list[dict[str, Any]] = []

    for att in attestations:
        verify = verify_attestation_signature(att)
        if not verify["valid"]:
            rejected.append({"federation_id": att.get("federation_id"), "reason": verify["reason"]})
            continue
        verifier = verifier_map.get(str(att.get("verifier_id")))
        if verifier is None:
            rejected.append({"federation_id": att.get("federation_id"), "reason": "unknown_or_inactive_verifier"})
            continue
        lifecycle = verifier_lifecycle_status(
            tenant_id=tenant_id,
            verifier_id=str(att.get("verifier_id")),
        )
        if lifecycle is None:
            rejected.append({"federation_id": att.get("federation_id"), "reason": "missing_lifecycle"})
            continue
        if lifecycle.get("status") == "revoked":
            rejected.append({"federation_id": att.get("federation_id"), "reason": "verifier_revoked"})
            continue
        if bool(lifecycle.get("is_expired")):
            rejected.append({"federation_id": att.get("federation_id"), "reason": "verifier_key_expired"})
            continue
        trust_score = float(verifier.get("trust_score", 0.0))
        confidence = float(att.get("confidence", 0.0))
        if trust_score < min_trust_score or confidence < min_confidence:
            rejected.append({"federation_id": att.get("federation_id"), "reason": "below_threshold"})
            continue
        unique_passed[str(att["verifier_id"])] = {
            "verifier_id": att["verifier_id"],
            "trust_score": trust_score,
            "confidence": confidence,
            "verdict": att.get("verdict"),
            "federation_id": att.get("federation_id"),
        }
        verdict = str(att.get("verdict", "allow")).lower()
        if verdict in verdict_weights:
            verdict_weights[verdict] += trust_score * confidence

    passed = list(unique_passed.values())
    quorum_met = len(passed) >= max(1, int(min_verifiers))
    if verdict_weights["block"] >= max(verdict_weights["step_up"], verdict_weights["allow"]):
        effective_action = "block"
    elif verdict_weights["step_up"] >= verdict_weights["allow"]:
        effective_action = "step_up"
    else:
        effective_action = "allow"
    return {
        "tenant_id": tenant_id,
        "target_type": target_type,
        "target_id": target_id,
        "quorum": {
            "required_verifiers": max(1, int(min_verifiers)),
            "participating_verifiers": len(passed),
            "met": quorum_met,
            "min_trust_score": float(min_trust_score),
            "min_confidence": float(min_confidence),
        },
        "effective_action": effective_action if quorum_met else "step_up",
        "verdict_weights": {
            "allow": round(verdict_weights["allow"], 4),
            "step_up": round(verdict_weights["step_up"], 4),
            "block": round(verdict_weights["block"], 4),
        },
        "accepted": passed,
        "rejected": rejected,
    }

