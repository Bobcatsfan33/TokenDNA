"""
TokenDNA -- Versioned policy bundle store and simulation utilities.
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

from modules.identity.edge_enforcement import evaluate_runtime_enforcement

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
            CREATE TABLE IF NOT EXISTS policy_bundles (
                bundle_id               TEXT PRIMARY KEY,
                tenant_id               TEXT NOT NULL,
                name                    TEXT NOT NULL,
                version                 TEXT NOT NULL,
                description             TEXT,
                config_json             TEXT NOT NULL,
                status                  TEXT NOT NULL DEFAULT 'draft',
                created_at              TEXT NOT NULL,
                activated_at            TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_bundle_tenant_name_version
            ON policy_bundles(tenant_id, name, version)
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_policy_bundle_tenant_status_time
            ON policy_bundles(tenant_id, status, created_at DESC)
            """
        )


def create_bundle(
    *,
    tenant_id: str,
    name: str,
    version: str,
    description: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    bundle = {
        "bundle_id": uuid.uuid4().hex,
        "tenant_id": tenant_id,
        "name": name,
        "version": version,
        "description": description,
        "config": config,
        "status": "draft",
        "created_at": _iso_now(),
        "activated_at": None,
    }
    with _cursor() as cur:
        cur.execute(
            """
            INSERT INTO policy_bundles(
                bundle_id, tenant_id, name, version, description, config_json, status, created_at, activated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                bundle["bundle_id"],
                tenant_id,
                name,
                version,
                description,
                json.dumps(config, sort_keys=True),
                "draft",
                bundle["created_at"],
                None,
            ),
        )
    return bundle


def get_bundle(tenant_id: str, bundle_id: str) -> dict[str, Any] | None:
    with _cursor() as cur:
        row = cur.execute(
            """
            SELECT bundle_id, tenant_id, name, version, description, config_json, status, created_at, activated_at
            FROM policy_bundles
            WHERE tenant_id = ? AND bundle_id = ?
            """,
            (tenant_id, bundle_id),
        ).fetchone()
    if not row:
        return None
    return {
        "bundle_id": row["bundle_id"],
        "tenant_id": row["tenant_id"],
        "name": row["name"],
        "version": row["version"],
        "description": row["description"] or "",
        "config": json.loads(row["config_json"]),
        "status": row["status"],
        "created_at": row["created_at"],
        "activated_at": row["activated_at"],
    }


def list_bundles(
    tenant_id: str,
    *,
    name: str | None = None,
    status: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    with _cursor() as cur:
        params: list[Any] = [tenant_id]
        where = ["tenant_id = ?"]
        if name:
            where.append("name = ?")
            params.append(name)
        if status:
            where.append("status = ?")
            params.append(status)
        params.append(limit)
        rows = cur.execute(
            f"""
            SELECT bundle_id, tenant_id, name, version, description, config_json, status, created_at, activated_at
            FROM policy_bundles
            WHERE {' AND '.join(where)}
            ORDER BY created_at DESC
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
    return [
        {
            "bundle_id": row["bundle_id"],
            "tenant_id": row["tenant_id"],
            "name": row["name"],
            "version": row["version"],
            "description": row["description"] or "",
            "config": json.loads(row["config_json"]),
            "status": row["status"],
            "created_at": row["created_at"],
            "activated_at": row["activated_at"],
        }
        for row in rows
    ]


def activate_bundle(tenant_id: str, bundle_id: str) -> dict[str, Any] | None:
    bundle = get_bundle(tenant_id, bundle_id)
    if bundle is None:
        return None
    now = _iso_now()
    with _cursor() as cur:
        cur.execute(
            """
            UPDATE policy_bundles
            SET status = 'inactive'
            WHERE tenant_id = ? AND name = ? AND status = 'active'
            """,
            (tenant_id, bundle["name"]),
        )
        cur.execute(
            """
            UPDATE policy_bundles
            SET status = 'active', activated_at = ?
            WHERE tenant_id = ? AND bundle_id = ?
            """,
            (now, tenant_id, bundle_id),
        )
    return get_bundle(tenant_id, bundle_id)


def get_active_bundle(tenant_id: str, name: str = "edge-default") -> dict[str, Any] | None:
    with _cursor() as cur:
        row = cur.execute(
            """
            SELECT bundle_id, tenant_id, name, version, description, config_json, status, created_at, activated_at
            FROM policy_bundles
            WHERE tenant_id = ? AND name = ? AND status = 'active'
            ORDER BY activated_at DESC, created_at DESC
            LIMIT 1
            """,
            (tenant_id, name),
        ).fetchone()
    if not row:
        return None
    return {
        "bundle_id": row["bundle_id"],
        "tenant_id": row["tenant_id"],
        "name": row["name"],
        "version": row["version"],
        "description": row["description"] or "",
        "config": json.loads(row["config_json"]),
        "status": row["status"],
        "created_at": row["created_at"],
        "activated_at": row["activated_at"],
    }


def _build_scenario_list(simulation: dict[str, Any]) -> list[dict[str, Any]]:
    scenarios = simulation.get("scenarios")
    if isinstance(scenarios, list) and scenarios:
        return [s for s in scenarios if isinstance(s, dict)]
    return [simulation]


def simulate_bundle(
    *,
    simulation: dict[str, Any],
    bundle_config: dict[str, Any],
) -> dict[str, Any]:
    scenarios = _build_scenario_list(simulation)
    outputs: list[dict[str, Any]] = []
    expected_action = str(bundle_config.get("expected_action", "")).strip() or None
    required_scope = [str(v) for v in bundle_config.get("required_scope", []) if str(v)]

    for scenario in scenarios:
        request_headers = scenario.get("request_headers") or {}
        if not isinstance(request_headers, dict):
            request_headers = {}
        observed_scope = scenario.get("observed_scope") or []
        if not isinstance(observed_scope, list):
            observed_scope = []

        outcome = evaluate_runtime_enforcement(
            uis_event=scenario.get("uis_event") or {"threat": {"risk_score": 80, "risk_tier": "allow"}},
            attestation=scenario.get("attestation"),
            certificate=scenario.get("certificate"),
            certificate_id=str(scenario.get("certificate_id") or ""),
            request_headers={str(k).lower(): str(v) for k, v in request_headers.items()},
            observed_scope=[str(v) for v in observed_scope],
            required_scope=required_scope,
        )
        action = str(outcome.get("decision", {}).get("action", "unknown"))
        outputs.append(
            {
                "scenario_id": str(scenario.get("scenario_id") or uuid.uuid4().hex),
                "decision": outcome.get("decision"),
                "timing": outcome.get("timing"),
                "drift": outcome.get("drift"),
                "certificate_status": outcome.get("certificate_status"),
                "matches_expected_action": (action == expected_action) if expected_action else None,
            }
        )

    return {
        "scenario_count": len(outputs),
        "expected_action": expected_action,
        "results": outputs,
    }
