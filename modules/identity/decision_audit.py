"""
TokenDNA -- Decision provenance store and forensic replay.

Captures deterministic runtime decision inputs/outputs and supports replaying
historical records against newer policy bundle configurations.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from modules.identity.edge_enforcement import evaluate_runtime_enforcement

_lock = threading.Lock()


def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _encode_cursor(created_at: str, audit_id: str) -> str:
    raw = f"{created_at}|{audit_id}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8")


def _decode_cursor(cursor: str | None) -> tuple[str, str] | None:
    if not cursor:
        return None
    try:
        decoded = base64.urlsafe_b64decode(cursor.encode("utf-8")).decode("utf-8")
    except Exception:
        return None
    if "|" not in decoded:
        return None
    created_at, audit_id = decoded.split("|", 1)
    if not created_at or not audit_id:
        return None
    return created_at, audit_id


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
            CREATE TABLE IF NOT EXISTS decision_audits (
                audit_id                 TEXT PRIMARY KEY,
                tenant_id                TEXT NOT NULL,
                request_id               TEXT NOT NULL,
                source_endpoint          TEXT NOT NULL,
                actor_subject            TEXT NOT NULL,
                created_at               TEXT NOT NULL,
                previous_action          TEXT NOT NULL,
                previous_reasons_json    TEXT NOT NULL,
                policy_bundle_name       TEXT,
                policy_bundle_version    TEXT,
                policy_bundle_config_json TEXT NOT NULL,
                evaluation_input_json    TEXT NOT NULL,
                enforcement_result_json  TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_decision_audits_tenant_created
            ON decision_audits(tenant_id, created_at DESC, audit_id DESC)
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_decision_audits_tenant_request
            ON decision_audits(tenant_id, request_id)
            """
        )


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "audit_id": row["audit_id"],
        "tenant_id": row["tenant_id"],
        "request_id": row["request_id"],
        "source_endpoint": row["source_endpoint"],
        "actor_subject": row["actor_subject"],
        "created_at": row["created_at"],
        "previous_action": row["previous_action"],
        "previous_reasons": json.loads(row["previous_reasons_json"]),
        "policy_bundle": {
            "name": row["policy_bundle_name"],
            "version": row["policy_bundle_version"],
            "config": json.loads(row["policy_bundle_config_json"]),
        },
        "evaluation_input": json.loads(row["evaluation_input_json"]),
        "enforcement_result": json.loads(row["enforcement_result_json"]),
    }


def record_decision(
    *,
    tenant_id: str,
    request_id: str,
    source_endpoint: str,
    actor_subject: str,
    evaluation_input: dict[str, Any],
    enforcement_result: dict[str, Any],
    policy_bundle: dict[str, Any] | None = None,
) -> dict[str, Any]:
    audit_id = uuid.uuid4().hex
    created_at = _iso_now()
    decision = enforcement_result.get("decision") or {}
    previous_action = str(decision.get("action", "unknown"))
    previous_reasons = [str(v) for v in decision.get("reasons", [])]
    bundle = policy_bundle or {}
    with _cursor() as cur:
        cur.execute(
            """
            INSERT INTO decision_audits(
                audit_id, tenant_id, request_id, source_endpoint, actor_subject, created_at,
                previous_action, previous_reasons_json, policy_bundle_name,
                policy_bundle_version, policy_bundle_config_json, evaluation_input_json,
                enforcement_result_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit_id,
                tenant_id,
                request_id,
                source_endpoint,
                actor_subject,
                created_at,
                previous_action,
                json.dumps(previous_reasons, sort_keys=True),
                str(bundle.get("name") or ""),
                str(bundle.get("version") or ""),
                json.dumps(bundle.get("config") or {}, sort_keys=True),
                json.dumps(evaluation_input, sort_keys=True),
                json.dumps(enforcement_result, sort_keys=True),
            ),
        )
    return get_decision(tenant_id=tenant_id, audit_id=audit_id) or {}


def get_decision(*, tenant_id: str, audit_id: str) -> dict[str, Any] | None:
    with _cursor() as cur:
        row = cur.execute(
            """
            SELECT *
            FROM decision_audits
            WHERE tenant_id = ? AND audit_id = ?
            """,
            (tenant_id, audit_id),
        ).fetchone()
    if not row:
        return None
    return _row_to_dict(row)


def list_decisions_paginated(
    *,
    tenant_id: str,
    page_size: int = 50,
    cursor: str | None = None,
    source_endpoint: str | None = None,
) -> dict[str, Any]:
    size = max(1, min(int(page_size), 200))
    decoded = _decode_cursor(cursor)
    params: list[Any] = [tenant_id]
    where = ["tenant_id = ?"]
    if source_endpoint:
        where.append("source_endpoint = ?")
        params.append(source_endpoint)
    if decoded:
        created_at, audit_id = decoded
        where.append("(created_at < ? OR (created_at = ? AND audit_id < ?))")
        params.extend([created_at, created_at, audit_id])
    params.append(size + 1)
    with _cursor() as cur:
        rows = cur.execute(
            f"""
            SELECT *
            FROM decision_audits
            WHERE {' AND '.join(where)}
            ORDER BY created_at DESC, audit_id DESC
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
    has_more = len(rows) > size
    selected = rows[:size]
    items = [_row_to_dict(row) for row in selected]
    next_cursor = None
    if has_more and selected:
        last = selected[-1]
        next_cursor = _encode_cursor(str(last["created_at"]), str(last["audit_id"]))
    return {
        "items": items,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "page_size": size,
    }


def _replay_diff(previous: dict[str, Any], replayed: dict[str, Any]) -> dict[str, Any]:
    prev_decision = previous.get("decision") or {}
    replay_decision = replayed.get("decision") or {}
    prev_reasons = [str(v) for v in prev_decision.get("reasons", [])]
    new_reasons = [str(v) for v in replay_decision.get("reasons", [])]
    previous_drift = float((previous.get("drift") or {}).get("score", 0.0))
    replay_drift = float((replayed.get("drift") or {}).get("score", 0.0))
    return {
        "action_changed": str(prev_decision.get("action")) != str(replay_decision.get("action")),
        "previous_action": prev_decision.get("action"),
        "replay_action": replay_decision.get("action"),
        "reasons_added": [r for r in new_reasons if r not in prev_reasons],
        "reasons_removed": [r for r in prev_reasons if r not in new_reasons],
        "drift_score_delta": round(replay_drift - previous_drift, 4),
        "certificate_reason_changed": str((previous.get("certificate_status") or {}).get("reason"))
        != str((replayed.get("certificate_status") or {}).get("reason")),
    }


def replay_decision(
    *,
    record: dict[str, Any],
    policy_bundle_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evaluation_input = record.get("evaluation_input") or {}
    headers = evaluation_input.get("request_headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    observed_scope = evaluation_input.get("observed_scope") or []
    if not isinstance(observed_scope, list):
        observed_scope = []
    required_scope = evaluation_input.get("required_scope") or []
    if not isinstance(required_scope, list):
        required_scope = []
    replayed = evaluate_runtime_enforcement(
        uis_event=evaluation_input.get("uis_event") or {},
        attestation=evaluation_input.get("attestation"),
        certificate=evaluation_input.get("certificate"),
        certificate_id=str(evaluation_input.get("certificate_id", "")),
        request_headers={str(k).lower(): str(v) for k, v in headers.items()},
        observed_scope=[str(v) for v in observed_scope],
        required_scope=[str(v) for v in required_scope],
        policy_bundle_config=policy_bundle_config or {},
    )
    previous = record.get("enforcement_result") or {}
    return {
        "audit_id": record.get("audit_id"),
        "previous_decision": previous.get("decision"),
        "replay_decision": replayed.get("decision"),
        "previous_enforcement": previous,
        "replay_enforcement": replayed,
        "diff": _replay_diff(previous=previous, replayed=replayed),
    }
