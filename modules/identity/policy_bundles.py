"""
TokenDNA -- Versioned policy bundle store and simulation utilities.
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


def _encode_cursor(created_at: str, bundle_id: str) -> str:
    raw = f"{created_at}|{bundle_id}".encode("utf-8")
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
    created_at, bundle_id = decoded.split("|", 1)
    if not created_at or not bundle_id:
        return None
    return created_at, bundle_id


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
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS policy_bundle_approvals (
                approval_id             TEXT PRIMARY KEY,
                tenant_id               TEXT NOT NULL,
                bundle_id               TEXT NOT NULL,
                actor_id                TEXT NOT NULL,
                action                  TEXT NOT NULL,
                note                    TEXT,
                created_at              TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_policy_bundle_approvals_bundle_time
            ON policy_bundle_approvals(tenant_id, bundle_id, created_at DESC)
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS policy_bundle_simulations (
                simulation_id           TEXT PRIMARY KEY,
                tenant_id               TEXT NOT NULL,
                bundle_id               TEXT NOT NULL,
                actor_id                TEXT NOT NULL,
                scenario_count          INTEGER NOT NULL,
                mismatch_count          INTEGER NOT NULL,
                summary_json            TEXT NOT NULL,
                created_at              TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_policy_bundle_simulations_bundle_time
            ON policy_bundle_simulations(tenant_id, bundle_id, created_at DESC)
            """
        )
        # Non-destructive migration fields for governance workflow.
        for ddl in (
            "ALTER TABLE policy_bundles ADD COLUMN activation_window_start TEXT",
            "ALTER TABLE policy_bundles ADD COLUMN activation_window_end TEXT",
            "ALTER TABLE policy_bundles ADD COLUMN activated_by TEXT",
            "ALTER TABLE policy_bundles ADD COLUMN rollback_guard_seconds INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE policy_bundles ADD COLUMN governance_json TEXT NOT NULL DEFAULT '{}'",
        ):
            try:
                cur.execute(ddl)
            except Exception:
                pass


def create_bundle(
    *,
    tenant_id: str,
    name: str,
    version: str,
    description: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    activation_window = config.get("activation_window", {}) if isinstance(config, dict) else {}
    if not isinstance(activation_window, dict):
        activation_window = {}
    governance = {
        # Preserve backward compatibility: governance is opt-in unless requested.
        "review_required": bool(config.get("review_required", False)),
        "two_person_activation": bool(config.get("two_person_activation", False)),
        "rollback_guard_seconds": max(0, int(config.get("rollback_guard_seconds", 0))),
        "created_by": str(config.get("created_by", "unknown")),
    }
    bundle = {
        "bundle_id": uuid.uuid4().hex,
        "tenant_id": tenant_id,
        "name": name,
        "version": version,
        "description": description,
        "config": config,
        "status": "review" if governance["review_required"] else "draft",
        "created_at": _iso_now(),
        "activated_at": None,
        "activation_window_start": str(activation_window.get("start") or "") or None,
        "activation_window_end": str(activation_window.get("end") or "") or None,
        "activated_by": None,
        "rollback_guard_seconds": governance["rollback_guard_seconds"],
        "governance": governance,
    }
    with _cursor() as cur:
        cur.execute(
            """
            INSERT INTO policy_bundles(
                bundle_id, tenant_id, name, version, description, config_json, status, created_at, activated_at,
                activation_window_start, activation_window_end, activated_by, rollback_guard_seconds, governance_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                bundle["bundle_id"],
                tenant_id,
                name,
                version,
                description,
                json.dumps(config, sort_keys=True),
                bundle["status"],
                bundle["created_at"],
                None,
                bundle["activation_window_start"],
                bundle["activation_window_end"],
                None,
                bundle["rollback_guard_seconds"],
                json.dumps(governance, sort_keys=True),
            ),
        )
    return bundle


def get_bundle(tenant_id: str, bundle_id: str) -> dict[str, Any] | None:
    with _cursor() as cur:
        row = cur.execute(
            """
            SELECT bundle_id, tenant_id, name, version, description, config_json, status, created_at, activated_at,
                   activation_window_start, activation_window_end, activated_by, rollback_guard_seconds, governance_json
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
        "activation_window_start": row["activation_window_start"],
        "activation_window_end": row["activation_window_end"],
        "activated_by": row["activated_by"],
        "rollback_guard_seconds": int(row["rollback_guard_seconds"] or 0),
        "governance": json.loads(row["governance_json"] or "{}"),
    }


def list_bundles(
    tenant_id: str,
    *,
    name: str | None = None,
    status: str | None = None,
    limit: int = 50,
    cursor_created_at: str | None = None,
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
        if cursor_created_at:
            where.append("created_at < ?")
            params.append(cursor_created_at)
        params.append(limit)
        rows = cur.execute(
            f"""
            SELECT bundle_id, tenant_id, name, version, description, config_json, status, created_at, activated_at,
                   activation_window_start, activation_window_end, activated_by, rollback_guard_seconds, governance_json
            FROM policy_bundles
            WHERE {' AND '.join(where)}
            ORDER BY created_at DESC, bundle_id DESC
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
            "activation_window_start": row["activation_window_start"],
            "activation_window_end": row["activation_window_end"],
            "activated_by": row["activated_by"],
            "rollback_guard_seconds": int(row["rollback_guard_seconds"] or 0),
            "governance": json.loads(row["governance_json"] or "{}"),
        }
        for row in rows
    ]


def list_bundles_paginated(
    tenant_id: str,
    *,
    page_size: int = 50,
    cursor: str | None = None,
    name: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    size = max(1, min(int(page_size), 200))
    decoded = _decode_cursor(cursor)
    params: list[Any] = [tenant_id]
    where = ["tenant_id = ?"]
    if name:
        where.append("name = ?")
        params.append(name)
    if status:
        where.append("status = ?")
        params.append(status)
    if decoded:
        created_at, bundle_id = decoded
        where.append("(created_at < ? OR (created_at = ? AND bundle_id < ?))")
        params.extend([created_at, created_at, bundle_id])
    params.append(size + 1)
    with _cursor() as cur:
        rows = cur.execute(
            f"""
            SELECT bundle_id, tenant_id, name, version, description, config_json, status, created_at, activated_at,
                   activation_window_start, activation_window_end, activated_by, rollback_guard_seconds, governance_json
            FROM policy_bundles
            WHERE {' AND '.join(where)}
            ORDER BY created_at DESC, bundle_id DESC
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
    has_more = len(rows) > size
    selected = rows[:size]
    items = [
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
            "activation_window_start": row["activation_window_start"],
            "activation_window_end": row["activation_window_end"],
            "activated_by": row["activated_by"],
            "rollback_guard_seconds": int(row["rollback_guard_seconds"] or 0),
            "governance": json.loads(row["governance_json"] or "{}"),
        }
        for row in selected
    ]
    next_cursor = None
    if has_more and selected:
        last = selected[-1]
        next_cursor = _encode_cursor(str(last["created_at"]), str(last["bundle_id"]))
    return {
        "items": items,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "page_size": size,
    }


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def _is_within_activation_window(bundle: dict[str, Any], now: datetime) -> bool:
    start = _parse_iso(bundle.get("activation_window_start"))
    end = _parse_iso(bundle.get("activation_window_end"))
    if start and now < start:
        return False
    if end and now > end:
        return False
    return True


def _bundle_approvals(tenant_id: str, bundle_id: str) -> list[dict[str, Any]]:
    with _cursor() as cur:
        rows = cur.execute(
            """
            SELECT approval_id, tenant_id, bundle_id, actor_id, action, note, created_at
            FROM policy_bundle_approvals
            WHERE tenant_id = ? AND bundle_id = ?
            ORDER BY created_at DESC
            """,
            (tenant_id, bundle_id),
        ).fetchall()
    return [
        {
            "approval_id": row["approval_id"],
            "tenant_id": row["tenant_id"],
            "bundle_id": row["bundle_id"],
            "actor_id": row["actor_id"],
            "action": row["action"],
            "note": row["note"] or "",
            "created_at": row["created_at"],
        }
        for row in rows
    ]


def add_approval(
    *,
    tenant_id: str,
    bundle_id: str,
    actor_id: str,
    action: str,
    note: str = "",
) -> dict[str, Any] | None:
    bundle = get_bundle(tenant_id, bundle_id)
    if bundle is None:
        return None
    action_norm = action.strip().lower()
    if action_norm not in {"reviewed", "approved", "rejected"}:
        raise ValueError("action must be one of: reviewed, approved, rejected")
    row = {
        "approval_id": uuid.uuid4().hex,
        "tenant_id": tenant_id,
        "bundle_id": bundle_id,
        "actor_id": actor_id,
        "action": action_norm,
        "note": note,
        "created_at": _iso_now(),
    }
    with _cursor() as cur:
        cur.execute(
            """
            INSERT INTO policy_bundle_approvals(
                approval_id, tenant_id, bundle_id, actor_id, action, note, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["approval_id"],
                tenant_id,
                bundle_id,
                actor_id,
                action_norm,
                note,
                row["created_at"],
            ),
        )
        # Promotion from review -> approved when approval is recorded.
        if action_norm == "approved" and str(bundle.get("status")) in {"review", "draft"}:
            cur.execute(
                """
                UPDATE policy_bundles
                SET status = 'approved'
                WHERE tenant_id = ? AND bundle_id = ?
                """,
                (tenant_id, bundle_id),
            )
    return row


def list_approvals(
    *,
    tenant_id: str,
    bundle_id: str,
    limit: int = 100,
) -> list[dict[str, Any]]:
    rows = _bundle_approvals(tenant_id, bundle_id)
    return rows[: min(max(limit, 1), 200)]


def _active_bundle_guard(cur: sqlite3.Cursor, tenant_id: str, bundle_name: str, now: datetime) -> tuple[bool, str | None]:
    active = cur.execute(
        """
        SELECT bundle_id, activated_at, rollback_guard_seconds
        FROM policy_bundles
        WHERE tenant_id = ? AND name = ? AND status = 'active'
        ORDER BY activated_at DESC, created_at DESC
        LIMIT 1
        """,
        (tenant_id, bundle_name),
    ).fetchone()
    if not active:
        return True, None
    guard_seconds = int(active["rollback_guard_seconds"] or 0)
    activated_at = _parse_iso(active["activated_at"])
    if guard_seconds <= 0 or activated_at is None:
        return True, None
    elapsed = (now - activated_at).total_seconds()
    if elapsed >= guard_seconds:
        return True, None
    return False, f"rollback_guard_active:{guard_seconds - int(elapsed)}s_remaining"


def activate_bundle(
    tenant_id: str,
    bundle_id: str,
    *,
    actor_id: str = "system",
    approval_actor_id: str | None = None,
) -> dict[str, Any] | None:
    bundle = get_bundle(tenant_id, bundle_id)
    if bundle is None:
        return None
    now_dt = datetime.now(timezone.utc)
    if not _is_within_activation_window(bundle, now_dt):
        raise ValueError("bundle_outside_activation_window")
    governance = bundle.get("governance") or {}
    require_review = bool(governance.get("review_required", True))
    two_person = bool(governance.get("two_person_activation", True))
    approvals = _bundle_approvals(tenant_id, bundle_id)
    approvers = {str(a["actor_id"]) for a in approvals if str(a.get("action")) == "approved"}
    effective_approver = str(approval_actor_id or "")
    if effective_approver:
        approvers.add(effective_approver)
    if require_review and not approvers:
        raise ValueError("bundle_requires_approval")
    if two_person and actor_id in approvers:
        raise ValueError("two_person_activation_violation")
    ok_guard = True
    guard_reason = None
    now = now_dt.isoformat()
    with _cursor() as cur:
        ok_guard, guard_reason = _active_bundle_guard(cur, tenant_id, str(bundle["name"]), now_dt)
        if not ok_guard:
            raise ValueError(str(guard_reason))
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
            SET status = 'active', activated_at = ?, activated_by = ?
            WHERE tenant_id = ? AND bundle_id = ?
            """,
            (now, actor_id, tenant_id, bundle_id),
        )
        cur.execute(
            """
            INSERT INTO policy_bundle_approvals(
                approval_id, tenant_id, bundle_id, actor_id, action, note, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                uuid.uuid4().hex,
                tenant_id,
                bundle_id,
                actor_id,
                "activated",
                "bundle activated",
                now,
            ),
        )
    return get_bundle(tenant_id, bundle_id)


def rollback_to_previous_active(
    *,
    tenant_id: str,
    name: str = "edge-default",
    actor_id: str = "system",
) -> dict[str, Any] | None:
    with _cursor() as cur:
        rows = cur.execute(
            """
            SELECT bundle_id, tenant_id, name, version, description, config_json, status, created_at, activated_at,
                   activation_window_start, activation_window_end, activated_by, rollback_guard_seconds, governance_json
            FROM policy_bundles
            WHERE tenant_id = ? AND name = ? AND status IN ('active', 'inactive')
            ORDER BY COALESCE(activated_at, created_at) DESC, created_at DESC
            LIMIT 2
            """,
            (tenant_id, name),
        ).fetchall()
        if len(rows) < 2:
            return None
        current_active = rows[0]
        previous = rows[1]
        now_dt = datetime.now(timezone.utc)
        ok_guard, guard_reason = _active_bundle_guard(cur, tenant_id, name, now_dt)
        if not ok_guard:
            raise ValueError(str(guard_reason))
        now = now_dt.isoformat()
        cur.execute(
            """
            UPDATE policy_bundles
            SET status = 'inactive'
            WHERE tenant_id = ? AND bundle_id = ?
            """,
            (tenant_id, current_active["bundle_id"]),
        )
        cur.execute(
            """
            UPDATE policy_bundles
            SET status = 'active', activated_at = ?, activated_by = ?
            WHERE tenant_id = ? AND bundle_id = ?
            """,
            (now, actor_id, tenant_id, previous["bundle_id"]),
        )
        cur.execute(
            """
            INSERT INTO policy_bundle_approvals(
                approval_id, tenant_id, bundle_id, actor_id, action, note, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                uuid.uuid4().hex,
                tenant_id,
                previous["bundle_id"],
                actor_id,
                "rollback",
                f"rollback_from:{current_active['bundle_id']}",
                now,
            ),
        )
    return get_bundle(tenant_id, str(previous["bundle_id"]))


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


def review_bundle(
    *,
    tenant_id: str,
    bundle_id: str,
    actor_id: str,
    note: str = "",
) -> dict[str, Any] | None:
    return add_approval(
        tenant_id=tenant_id,
        bundle_id=bundle_id,
        actor_id=actor_id,
        action="reviewed",
        note=note,
    )


def approve_bundle(
    *,
    tenant_id: str,
    bundle_id: str,
    actor_id: str,
    note: str = "",
) -> dict[str, Any] | None:
    return add_approval(
        tenant_id=tenant_id,
        bundle_id=bundle_id,
        actor_id=actor_id,
        action="approved",
        note=note,
    )


def record_simulation_result(
    *,
    tenant_id: str,
    bundle_id: str,
    actor_id: str,
    simulation: dict[str, Any],
) -> dict[str, Any] | None:
    bundle = get_bundle(tenant_id, bundle_id)
    if bundle is None:
        return None
    summary = {
        "scenario_count": int(simulation.get("scenario_count", 0)),
        "expected_action": simulation.get("expected_action"),
    }
    return add_approval(
        tenant_id=tenant_id,
        bundle_id=bundle_id,
        actor_id=actor_id,
        action="reviewed",
        note=f"simulation:{json.dumps(summary, sort_keys=True)}",
    )


def list_governance_log(
    *,
    tenant_id: str,
    bundle_id: str,
    limit: int = 200,
) -> list[dict[str, Any]]:
    return list_approvals(tenant_id=tenant_id, bundle_id=bundle_id, limit=limit)


def activate_bundle_with_approval(
    *,
    tenant_id: str,
    bundle_id: str,
    actor_id: str,
    approval_actor_id: str | None = None,
) -> dict[str, Any] | None:
    return activate_bundle(
        tenant_id=tenant_id,
        bundle_id=bundle_id,
        actor_id=actor_id,
        approval_actor_id=approval_actor_id,
    )
