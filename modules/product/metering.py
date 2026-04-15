"""
TokenDNA -- Feature usage metering and entitlement limits.
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

from modules.product.feature_gates import PlanTier
from modules.identity.trust_authority import build_signer_for_algorithm, build_signer_for_key

_lock = threading.Lock()


def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _month_bucket(value: str | None = None) -> str:
    if value:
        try:
            dt = datetime.fromisoformat(value)
            return dt.strftime("%Y-%m")
        except Exception:
            pass
    return datetime.now(timezone.utc).strftime("%Y-%m")


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


USAGE_LIMITS: dict[str, dict[str, dict[str, Any]]] = {
    "policy.simulation.advanced": {
        PlanTier.FREE.value: {"mode": "hard", "max": 0},
        PlanTier.STARTER.value: {"mode": "soft", "max": 25},
        PlanTier.PRO.value: {"mode": "soft", "max": 500},
        PlanTier.ENTERPRISE.value: {"mode": "soft", "max": 5000},
    },
    "intel.cross_tenant_controls": {
        PlanTier.FREE.value: {"mode": "hard", "max": 0},
        PlanTier.STARTER.value: {"mode": "hard", "max": 0},
        PlanTier.PRO.value: {"mode": "soft", "max": 250},
        PlanTier.ENTERPRISE.value: {"mode": "soft", "max": 2000},
    },
    "compliance.signed_snapshots": {
        PlanTier.FREE.value: {"mode": "hard", "max": 0},
        PlanTier.STARTER.value: {"mode": "hard", "max": 0},
        PlanTier.PRO.value: {"mode": "soft", "max": 100},
        PlanTier.ENTERPRISE.value: {"mode": "soft", "max": 1000},
    },
}


def _plan_key(plan: PlanTier | str) -> str:
    return str(plan.value if isinstance(plan, PlanTier) else plan).lower()


def _limit_for(feature: str, plan: PlanTier | str) -> dict[str, Any]:
    feature_limits = USAGE_LIMITS.get(feature, {})
    limit = feature_limits.get(_plan_key(plan))
    if limit:
        return {"mode": str(limit["mode"]), "max": int(limit["max"])}
    return {"mode": "soft", "max": 1000000}


def init_db() -> None:
    db_path = _db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    with _cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS feature_usage_events (
                event_id              TEXT PRIMARY KEY,
                tenant_id             TEXT NOT NULL,
                feature_key           TEXT NOT NULL,
                plan                  TEXT NOT NULL,
                amount                INTEGER NOT NULL,
                month_bucket          TEXT NOT NULL,
                status                TEXT NOT NULL,
                detail_json           TEXT NOT NULL,
                created_at            TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS feature_usage_monthly (
                tenant_id             TEXT NOT NULL,
                feature_key           TEXT NOT NULL,
                plan                  TEXT NOT NULL,
                month_bucket          TEXT NOT NULL,
                used_amount           INTEGER NOT NULL,
                updated_at            TEXT NOT NULL,
                PRIMARY KEY (tenant_id, feature_key, month_bucket)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS billing_exports (
                export_id             TEXT PRIMARY KEY,
                tenant_id             TEXT NOT NULL,
                month_bucket          TEXT NOT NULL,
                format                TEXT NOT NULL,
                created_at            TEXT NOT NULL,
                signature_alg         TEXT NOT NULL,
                ca_key_id             TEXT NOT NULL,
                signature             TEXT NOT NULL,
                payload_json          TEXT NOT NULL
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_feature_usage_events_tenant_month ON feature_usage_events(tenant_id, month_bucket, created_at DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_billing_exports_tenant_month ON billing_exports(tenant_id, month_bucket, created_at DESC)"
        )


def evaluate_usage(
    *,
    tenant_id: str,
    feature_key: str,
    plan: PlanTier | str,
    amount: int = 1,
    month_bucket: str | None = None,
) -> dict[str, Any]:
    month = _month_bucket(month_bucket)
    normalized_amount = max(1, int(amount))
    limit = _limit_for(feature_key, plan)
    with _cursor() as cur:
        row = cur.execute(
            """
            SELECT used_amount
            FROM feature_usage_monthly
            WHERE tenant_id = ? AND feature_key = ? AND month_bucket = ?
            """,
            (tenant_id, feature_key, month),
        ).fetchone()
    used = int(row["used_amount"]) if row else 0
    projected = used + normalized_amount
    maximum = int(limit["max"])
    mode = str(limit["mode"])
    if mode == "hard" and projected > maximum:
        status = "blocked"
    elif projected > maximum:
        status = "warning"
    else:
        status = "ok"
    return {
        "tenant_id": tenant_id,
        "feature_key": feature_key,
        "plan": _plan_key(plan),
        "month_bucket": month,
        "mode": mode,
        "limit": maximum,
        "used": used,
        "projected": projected,
        "status": status,
        "remaining": max(0, maximum - projected),
    }


def record_usage(
    *,
    tenant_id: str,
    feature_key: str,
    plan: PlanTier | str,
    amount: int = 1,
    detail: dict[str, Any] | None = None,
    month_bucket: str | None = None,
) -> dict[str, Any]:
    assessment = evaluate_usage(
        tenant_id=tenant_id,
        feature_key=feature_key,
        plan=plan,
        amount=amount,
        month_bucket=month_bucket,
    )
    month = assessment["month_bucket"]
    normalized_amount = max(1, int(amount))
    status = str(assessment["status"])
    now = _iso_now()
    event = {
        "event_id": uuid.uuid4().hex,
        "tenant_id": tenant_id,
        "feature_key": feature_key,
        "plan": _plan_key(plan),
        "amount": normalized_amount,
        "month_bucket": month,
        "status": status,
        "detail": detail or {},
        "created_at": now,
    }
    with _cursor() as cur:
        cur.execute(
            """
            INSERT INTO feature_usage_events(
                event_id, tenant_id, feature_key, plan, amount, month_bucket, status, detail_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["event_id"],
                tenant_id,
                feature_key,
                event["plan"],
                normalized_amount,
                month,
                status,
                json.dumps(event["detail"], sort_keys=True),
                now,
            ),
        )
        if status != "blocked":
            cur.execute(
                """
                INSERT INTO feature_usage_monthly(
                    tenant_id, feature_key, plan, month_bucket, used_amount, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, feature_key, month_bucket)
                DO UPDATE SET
                    plan = excluded.plan,
                    used_amount = feature_usage_monthly.used_amount + excluded.used_amount,
                    updated_at = excluded.updated_at
                """,
                (
                    tenant_id,
                    feature_key,
                    event["plan"],
                    month,
                    normalized_amount,
                    now,
                ),
            )
    updated = evaluate_usage(
        tenant_id=tenant_id,
        feature_key=feature_key,
        plan=plan,
        amount=0,
        month_bucket=month,
    )
    return {"event": event, "usage": updated}


def get_monthly_usage(
    *,
    tenant_id: str,
    month_bucket: str | None = None,
) -> list[dict[str, Any]]:
    month = _month_bucket(month_bucket)
    with _cursor() as cur:
        rows = cur.execute(
            """
            SELECT tenant_id, feature_key, plan, month_bucket, used_amount, updated_at
            FROM feature_usage_monthly
            WHERE tenant_id = ? AND month_bucket = ?
            ORDER BY feature_key ASC
            """,
            (tenant_id, month),
        ).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        limit = _limit_for(str(row["feature_key"]), str(row["plan"]))
        out.append(
            {
                "tenant_id": row["tenant_id"],
                "feature_key": row["feature_key"],
                "plan": row["plan"],
                "month_bucket": row["month_bucket"],
                "used_amount": int(row["used_amount"]),
                "limit": int(limit["max"]),
                "mode": str(limit["mode"]),
                "updated_at": row["updated_at"],
            }
        )
    return out


def build_usage_statement(
    *,
    tenant_id: str,
    month_bucket: str | None = None,
) -> dict[str, Any]:
    month = _month_bucket(month_bucket)
    usage = get_monthly_usage(tenant_id=tenant_id, month_bucket=month)
    totals = {
        "features": len(usage),
        "used_amount": sum(int(row["used_amount"]) for row in usage),
        "over_limit_features": len([row for row in usage if int(row["used_amount"]) > int(row["limit"])]),
    }
    return {
        "tenant_id": tenant_id,
        "month_bucket": month,
        "generated_at": _iso_now(),
        "totals": totals,
        "usage": usage,
    }


def create_signed_usage_statement(
    *,
    tenant_id: str,
    month_bucket: str | None = None,
    key_id: str | None = None,
    algorithm: str = "HS256",
) -> dict[str, Any]:
    statement = build_usage_statement(tenant_id=tenant_id, month_bucket=month_bucket)
    signer = (
        build_signer_for_key(key_id, algorithm)
        if key_id
        else build_signer_for_algorithm(algorithm)
    )
    sign_result = signer.sign(statement)
    return {
        "statement_id": uuid.uuid4().hex,
        "tenant_id": tenant_id,
        "month_bucket": statement["month_bucket"],
        "created_at": _iso_now(),
        "signature_alg": sign_result.algorithm,
        "ca_key_id": sign_result.key_id,
        "signature": sign_result.signature,
        "statement": statement,
    }


def verify_signed_usage_statement(snapshot: dict[str, Any]) -> dict[str, Any]:
    payload = snapshot.get("statement")
    signature = snapshot.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        return {"valid": False, "reason": "invalid_statement_payload"}
    algorithm = str(snapshot.get("signature_alg", "HS256")).upper()
    key_id = str(snapshot.get("ca_key_id") or "").strip()
    signer = (
        build_signer_for_key(key_id, algorithm)
        if key_id
        else build_signer_for_algorithm(algorithm)
    )
    ok = signer.verify(payload, signature)
    return {
        "valid": bool(ok),
        "reason": "ok" if ok else "invalid_signature",
        "statement_id": snapshot.get("statement_id"),
        "month_bucket": snapshot.get("month_bucket"),
    }


def export_billing_statement(
    *,
    tenant_id: str,
    month_bucket: str | None = None,
    export_format: str = "json",
    key_id: str | None = None,
    algorithm: str = "HS256",
) -> dict[str, Any]:
    fmt = str(export_format or "json").strip().lower()
    if fmt not in {"json", "csv"}:
        raise ValueError("export_format must be 'json' or 'csv'")
    signed = create_signed_usage_statement(
        tenant_id=tenant_id,
        month_bucket=month_bucket,
        key_id=key_id,
        algorithm=algorithm,
    )
    statement = signed["statement"]
    if fmt == "csv":
        header = "tenant_id,month_bucket,feature_key,plan,used_amount,limit,mode,updated_at"
        lines = [header]
        for row in statement.get("usage", []):
            lines.append(
                ",".join(
                    [
                        str(row.get("tenant_id", "")),
                        str(row.get("month_bucket", "")),
                        str(row.get("feature_key", "")),
                        str(row.get("plan", "")),
                        str(row.get("used_amount", 0)),
                        str(row.get("limit", 0)),
                        str(row.get("mode", "")),
                        str(row.get("updated_at", "")),
                    ]
                )
            )
        payload_obj: dict[str, Any] = {
            "statement": statement,
            "export": {"format": "csv", "content": "\n".join(lines)},
        }
    else:
        payload_obj = {"statement": statement, "export": {"format": "json", "content": statement}}

    export = {
        "export_id": uuid.uuid4().hex,
        "tenant_id": tenant_id,
        "month_bucket": statement["month_bucket"],
        "export_format": fmt,
        "content_type": "text/csv" if fmt == "csv" else "application/json",
        "created_at": _iso_now(),
        "signature_alg": signed["signature_alg"],
        "ca_key_id": signed["ca_key_id"],
        "signature": signed["signature"],
        "payload": payload_obj,
    }
    with _cursor() as cur:
        cur.execute(
            """
            INSERT OR REPLACE INTO billing_exports(
                export_id, tenant_id, month_bucket, format, created_at,
                signature_alg, ca_key_id, signature, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                export["export_id"],
                export["tenant_id"],
                export["month_bucket"],
                export["export_format"],
                export["created_at"],
                export["signature_alg"],
                export["ca_key_id"],
                export["signature"],
                json.dumps(export["payload"], sort_keys=True),
            ),
        )
    return export


def list_billing_exports(
    *,
    tenant_id: str,
    month_bucket: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    month = _month_bucket(month_bucket) if month_bucket else None
    with _cursor() as cur:
        if month:
            rows = cur.execute(
                """
                SELECT export_id, tenant_id, month_bucket, format, created_at,
                       signature_alg, ca_key_id, signature, payload_json
                FROM billing_exports
                WHERE tenant_id = ? AND month_bucket = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (tenant_id, month, min(max(limit, 1), 200)),
            ).fetchall()
        else:
            rows = cur.execute(
                """
                SELECT export_id, tenant_id, month_bucket, format, created_at,
                       signature_alg, ca_key_id, signature, payload_json
                FROM billing_exports
                WHERE tenant_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (tenant_id, min(max(limit, 1), 200)),
            ).fetchall()
    return [
        {
            "export_id": row["export_id"],
            "tenant_id": row["tenant_id"],
            "month_bucket": row["month_bucket"],
            "export_format": row["format"],
            "content_type": "text/csv" if str(row["format"]) == "csv" else "application/json",
            "created_at": row["created_at"],
            "signature_alg": row["signature_alg"],
            "ca_key_id": row["ca_key_id"],
            "signature": row["signature"],
            "payload": json.loads(row["payload_json"]),
        }
        for row in rows
    ]


def verify_billing_export_signature(export: dict[str, Any]) -> dict[str, Any]:
    payload = export.get("payload")
    signature = export.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        return {"valid": False, "reason": "invalid_export_payload"}
    statement = payload.get("statement")
    if not isinstance(statement, dict):
        return {"valid": False, "reason": "invalid_statement_content"}
    algorithm = str(export.get("signature_alg", "HS256")).upper()
    key_id = str(export.get("ca_key_id") or "").strip()
    signer = (
        build_signer_for_key(key_id, algorithm)
        if key_id
        else build_signer_for_algorithm(algorithm)
    )
    ok = signer.verify(statement, signature)
    return {
        "valid": bool(ok),
        "reason": "ok" if ok else "invalid_signature",
        "export_id": export.get("export_id"),
        "month_bucket": export.get("month_bucket"),
    }
