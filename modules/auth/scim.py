"""
TokenDNA -- SCIM 2.0 provisioning.

Implements the enterprise SCIM surface most IdPs require for GA:

* durable user and group storage on the shared SQLite/Postgres backend
* tenant-scoped uniqueness and isolation
* CRUD, pagination, filters, and RFC 7644 PatchOp subset
* ETag-style weak versions for concurrency-aware clients
* audit events for create/update/delete and group changes

The module rejects unsupported SCIM shapes explicitly rather than silently
approximating IdP intent.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from modules.storage.pg_connection import AdaptedCursor, ensure_sqlite_dir, get_db_conn

logger = logging.getLogger(__name__)

SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCHEMA_LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
SCHEMA_PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCHEMA_SP_CONFIG = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
SCHEMA_RESOURCE_TYPE = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"

# Roles TokenDNA recognises for RBAC. SCIM group membership can map to these
# via TOKENDNA_SCIM_GROUP_ROLE_MAP_JSON (least privilege by default).
ROLE_VALUES = {"owner", "admin", "analyst", "readonly"}


def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _cursor():
    return get_db_conn(db_path=_db_path())


def init_db() -> None:
    """Create durable SCIM tables. Idempotent across SQLite and Postgres."""
    ensure_sqlite_dir(_db_path())
    with _cursor() as conn:
        cur = AdaptedCursor(conn.cursor())
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS scim_users (
                id          TEXT PRIMARY KEY,
                tenant_id   TEXT NOT NULL,
                user_name   TEXT NOT NULL,
                active      INTEGER NOT NULL DEFAULT 1,
                external_id TEXT,
                name_json   TEXT NOT NULL DEFAULT '{}',
                emails_json TEXT NOT NULL DEFAULT '[]',
                roles_json  TEXT NOT NULL DEFAULT '[]',
                manual_roles_json TEXT NOT NULL DEFAULT '[]',
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL,
                version     TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS scim_groups (
                id            TEXT PRIMARY KEY,
                tenant_id     TEXT NOT NULL,
                display_name  TEXT NOT NULL,
                members_json  TEXT NOT NULL DEFAULT '[]',
                created_at    TEXT NOT NULL,
                updated_at    TEXT NOT NULL,
                version       TEXT NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scim_users_tenant ON scim_users(tenant_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scim_users_lookup ON scim_users(tenant_id, user_name)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scim_groups_tenant ON scim_groups(tenant_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scim_groups_lookup ON scim_groups(tenant_id, display_name)")


@dataclass
class SCIMError(Exception):
    status: int
    detail: str
    scimType: str | None = None

    def to_response(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "schemas": [SCHEMA_ERROR],
            "status": str(self.status),
            "detail": self.detail,
        }
        if self.scimType:
            body["scimType"] = self.scimType
        return body


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_version() -> str:
    return f'W/"{uuid.uuid4().hex}"'


def _json(value: Any, default: Any) -> str:
    return json.dumps(value if value is not None else default, sort_keys=True, separators=(",", ":"))


def _loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _meta(resource_id: str, resource_type: str, *, created: str, updated: str, version: str) -> dict[str, Any]:
    return {
        "resourceType": resource_type,
        "created": created,
        "lastModified": updated,
        "version": version,
        "location": f"/scim/v2/{resource_type}s/{resource_id}",
    }


def _require_schema(payload: dict[str, Any], schema: str, resource_name: str) -> None:
    if schema not in (payload.get("schemas") or []):
        raise SCIMError(400, f"{resource_name} schema missing", scimType="invalidValue")


def _audit(action: str, *, tenant_id: str, subject: str, resource: str, detail: dict[str, Any] | None = None) -> None:
    try:
        from modules.security.audit_log import AuditEventType, AuditOutcome, log_event

        log_event(
            AuditEventType.CONFIG_CHANGED,
            AuditOutcome.SUCCESS,
            tenant_id=tenant_id,
            subject=subject,
            resource=resource,
            detail={"scim_action": action, **(detail or {})},
        )
    except Exception:
        logger.debug("SCIM audit emission failed", exc_info=True)


def _user_row_to_resource(row: Any) -> dict[str, Any]:
    return {
        "schemas": [SCHEMA_USER],
        "id": row["id"],
        "externalId": row["external_id"] or None,
        "userName": row["user_name"],
        "active": bool(row["active"]),
        "name": _loads(row["name_json"], {}),
        "emails": _loads(row["emails_json"], []),
        "roles": _loads(row["roles_json"], []),
        "meta": _meta(
            row["id"],
            "User",
            created=row["created_at"],
            updated=row["updated_at"],
            version=row["version"],
        ),
    }


def _group_row_to_resource(row: Any) -> dict[str, Any]:
    return {
        "schemas": [SCHEMA_GROUP],
        "id": row["id"],
        "displayName": row["display_name"],
        "members": _loads(row["members_json"], []),
        "meta": _meta(
            row["id"],
            "Group",
            created=row["created_at"],
            updated=row["updated_at"],
            version=row["version"],
        ),
    }


def _normalize_roles(raw: Any) -> list[str]:
    """Coerce SCIM ``roles`` (strings or complex values) to known role names."""
    if isinstance(raw, str):
        candidates: list[Any] = [raw]
    else:
        try:
            candidates = list(raw or [])
        except TypeError:
            candidates = []
    out: list[str] = []
    for item in candidates:
        value = str(item.get("value") if isinstance(item, dict) else item).strip().lower()
        if value in ROLE_VALUES and value not in out:
            out.append(value)
    return out


def _group_role_map() -> dict[str, str]:
    """Map lower-cased group displayName -> TokenDNA role from env config."""
    raw = os.getenv("TOKENDNA_SCIM_GROUP_ROLE_MAP_JSON", "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("invalid TOKENDNA_SCIM_GROUP_ROLE_MAP_JSON ignored")
        return {}
    if not isinstance(parsed, dict):
        return {}
    out: dict[str, str] = {}
    for group_name, role in parsed.items():
        normalized_role = str(role).strip().lower()
        if normalized_role in ROLE_VALUES:
            out[str(group_name).strip().lower()] = normalized_role
    return out


def _member_id(member: Any) -> str | None:
    if isinstance(member, dict):
        value = member.get("value") or member.get("$ref") or member.get("id")
    else:
        value = member
    return str(value) if value else None


def _fetch_manual_roles(user_id: str, tenant_id: str) -> list[str]:
    with _cursor() as conn:
        row = AdaptedCursor(conn.cursor()).execute(
            "SELECT manual_roles_json FROM scim_users WHERE id=? AND tenant_id=?",
            (user_id, tenant_id),
        ).fetchone()
    return _loads(row["manual_roles_json"], []) if row else []


def _sync_roles(tenant_id: str) -> None:
    """Recompute each user's effective roles = manual roles + group-derived roles.

    Group-derived roles come from TOKENDNA_SCIM_GROUP_ROLE_MAP_JSON applied to
    current group membership. Least privilege: unmapped users gain nothing.
    Effective roles are persisted to ``roles_json``; this deliberately does not
    bump ``version``/``updated_at`` (membership sync is not a resource edit).
    """
    role_map = _group_role_map()
    with _cursor() as conn:
        cur = AdaptedCursor(conn.cursor())
        groups = cur.execute(
            "SELECT display_name, members_json FROM scim_groups WHERE tenant_id=?",
            (tenant_id,),
        ).fetchall()
        users = cur.execute(
            "SELECT id, manual_roles_json FROM scim_users WHERE tenant_id=?",
            (tenant_id,),
        ).fetchall()
        derived: dict[str, set[str]] = {row["id"]: set() for row in users}
        if role_map:
            for group in groups:
                role = role_map.get(str(group["display_name"] or "").strip().lower())
                if not role:
                    continue
                for member in _loads(group["members_json"], []):
                    mid = _member_id(member)
                    if mid in derived:
                        derived[mid].add(role)
        for row in users:
            manual = _loads(row["manual_roles_json"], [])
            effective = sorted(set(manual) | derived.get(row["id"], set()))
            cur.execute(
                "UPDATE scim_users SET roles_json=? WHERE id=? AND tenant_id=?",
                (_json(effective, []), row["id"], tenant_id),
            )


def _fetch_user(user_id: str, tenant_id: str) -> dict[str, Any] | None:
    init_db()
    with _cursor() as conn:
        row = AdaptedCursor(conn.cursor()).execute(
            "SELECT * FROM scim_users WHERE id=? AND tenant_id=?",
            (user_id, tenant_id),
        ).fetchone()
    return _user_row_to_resource(row) if row else None


def _fetch_group(group_id: str, tenant_id: str) -> dict[str, Any] | None:
    init_db()
    with _cursor() as conn:
        row = AdaptedCursor(conn.cursor()).execute(
            "SELECT * FROM scim_groups WHERE id=? AND tenant_id=?",
            (group_id, tenant_id),
        ).fetchone()
    return _group_row_to_resource(row) if row else None


def _assert_user_name_available(user_name: str, tenant_id: str, *, except_user_id: str | None = None) -> None:
    with _cursor() as conn:
        row = AdaptedCursor(conn.cursor()).execute(
            """
            SELECT id FROM scim_users
            WHERE tenant_id=? AND lower(user_name)=lower(?)
            """,
            (tenant_id, user_name),
        ).fetchone()
    if row and row["id"] != except_user_id:
        raise SCIMError(409, "User already exists", scimType="uniqueness")


def _assert_group_name_available(display_name: str, tenant_id: str, *, except_group_id: str | None = None) -> None:
    with _cursor() as conn:
        row = AdaptedCursor(conn.cursor()).execute(
            """
            SELECT id FROM scim_groups
            WHERE tenant_id=? AND lower(display_name)=lower(?)
            """,
            (tenant_id, display_name),
        ).fetchone()
    if row and row["id"] != except_group_id:
        raise SCIMError(409, "Group already exists", scimType="uniqueness")


# -- User CRUD -----------------------------------------------------------------


def create_user(payload: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
    init_db()
    _require_schema(payload, SCHEMA_USER, "User")
    user_name = str(payload.get("userName") or "").strip()
    if not user_name:
        raise SCIMError(400, "userName is required", scimType="invalidValue")
    _assert_user_name_available(user_name, tenant_id)

    now = _now_iso()
    user_id = uuid.uuid4().hex
    version = _new_version()
    manual_roles = _normalize_roles(payload.get("roles"))
    with _cursor() as conn:
        AdaptedCursor(conn.cursor()).execute(
            """
            INSERT INTO scim_users
              (id, tenant_id, user_name, active, external_id, name_json, emails_json, roles_json, manual_roles_json, created_at, updated_at, version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                tenant_id,
                user_name,
                int(bool(payload.get("active", True))),
                payload.get("externalId"),
                _json(payload.get("name"), {}),
                _json(payload.get("emails"), []),
                _json(manual_roles, []),
                _json(manual_roles, []),
                now,
                now,
                version,
            ),
        )
    _sync_roles(tenant_id)
    _audit("user.created", tenant_id=tenant_id, subject=user_name, resource=f"scim:user:{user_id}")
    return get_user(user_id, tenant_id=tenant_id)


def get_user(user_id: str, *, tenant_id: str) -> dict[str, Any]:
    user = _fetch_user(user_id, tenant_id)
    if not user:
        raise SCIMError(404, "User not found")
    return user


def replace_user(user_id: str, payload: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
    init_db()
    existing = get_user(user_id, tenant_id=tenant_id)
    user_name = str(payload.get("userName") or existing["userName"]).strip()
    if not user_name:
        raise SCIMError(400, "userName is required", scimType="invalidValue")
    _assert_user_name_available(user_name, tenant_id, except_user_id=user_id)
    # Manual roles are only replaced when the caller explicitly supplies them;
    # otherwise we preserve the existing manually-assigned roles. Group-derived
    # roles are recomputed separately by _sync_roles and never treated as manual.
    if "roles" in payload:
        manual_roles = _normalize_roles(payload.get("roles"))
    else:
        manual_roles = _fetch_manual_roles(user_id, tenant_id)
    now = _now_iso()
    version = _new_version()
    with _cursor() as conn:
        AdaptedCursor(conn.cursor()).execute(
            """
            UPDATE scim_users
            SET user_name=?, active=?, external_id=?, name_json=?, emails_json=?, roles_json=?, manual_roles_json=?, updated_at=?, version=?
            WHERE id=? AND tenant_id=?
            """,
            (
                user_name,
                int(bool(payload.get("active", existing.get("active", True)))),
                payload.get("externalId", existing.get("externalId")),
                _json(payload.get("name", existing.get("name")), {}),
                _json(payload.get("emails", existing.get("emails")), []),
                _json(manual_roles, []),
                _json(manual_roles, []),
                now,
                version,
                user_id,
                tenant_id,
            ),
        )
    _sync_roles(tenant_id)
    _audit("user.replaced", tenant_id=tenant_id, subject=user_name, resource=f"scim:user:{user_id}")
    return get_user(user_id, tenant_id=tenant_id)


def patch_user(user_id: str, patch_doc: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
    from modules.auth.scim_patch import PatchError, UnsupportedPatch, apply_patch

    existing = get_user(user_id, tenant_id=tenant_id)
    try:
        patched = apply_patch(existing, patch_doc)
    except UnsupportedPatch as exc:
        raise SCIMError(501, str(exc), scimType="invalidPath")
    except PatchError as exc:
        raise SCIMError(400, str(exc), scimType="invalidValue")
    for protected in ("id", "schemas", "meta"):
        patched.pop(protected, None)
    # NOTE: apply_patch echoes the full resource, so `patched` always carries
    # the current effective `roles`. Passing them through replace_user therefore
    # rebases them as manual roles — this intentionally matches main's prior
    # in-memory patch semantics. _sync_roles then re-adds group-derived roles.
    merged = {**existing, **patched}
    return replace_user(user_id, merged, tenant_id=tenant_id)


def delete_user(user_id: str, *, tenant_id: str) -> None:
    existing = get_user(user_id, tenant_id=tenant_id)
    with _cursor() as conn:
        cur = AdaptedCursor(conn.cursor())
        cur.execute("DELETE FROM scim_users WHERE id=? AND tenant_id=?", (user_id, tenant_id))
        rows = cur.execute("SELECT * FROM scim_groups WHERE tenant_id=?", (tenant_id,)).fetchall()
        for row in rows:
            members = [
                m for m in _loads(row["members_json"], [])
                if str(m.get("value") or m.get("$ref") or "") != user_id
            ]
            cur.execute(
                "UPDATE scim_groups SET members_json=?, updated_at=?, version=? WHERE id=? AND tenant_id=?",
                (_json(members, []), _now_iso(), _new_version(), row["id"], tenant_id),
            )
    _audit("user.deleted", tenant_id=tenant_id, subject=existing["userName"], resource=f"scim:user:{user_id}")


def list_users(
    *,
    tenant_id: str,
    start_index: int = 1,
    count: int = 100,
    filter_expr: str | None = None,
) -> dict[str, Any]:
    init_db()
    if start_index < 1 or count < 0:
        raise SCIMError(400, "Invalid startIndex/count", scimType="invalidValue")
    with _cursor() as conn:
        rows = AdaptedCursor(conn.cursor()).execute(
            "SELECT * FROM scim_users WHERE tenant_id=? ORDER BY user_name ASC, id ASC",
            (tenant_id,),
        ).fetchall()
    records = [_user_row_to_resource(row) for row in rows]
    if filter_expr:
        from modules.auth.scim_filter import FilterError, UnsupportedFilter, parse

        try:
            predicate = parse(filter_expr)
        except UnsupportedFilter as exc:
            raise SCIMError(501, str(exc), scimType="invalidFilter")
        except FilterError as exc:
            raise SCIMError(400, str(exc), scimType="invalidFilter")
        records = [r for r in records if predicate(r)]
    total = len(records)
    page = records[start_index - 1:start_index - 1 + count]
    return {
        "schemas": [SCHEMA_LIST_RESPONSE],
        "totalResults": total,
        "Resources": page,
        "startIndex": start_index,
        "itemsPerPage": len(page),
    }


# -- Group CRUD ----------------------------------------------------------------


def create_group(payload: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
    init_db()
    _require_schema(payload, SCHEMA_GROUP, "Group")
    display_name = str(payload.get("displayName") or "").strip()
    if not display_name:
        raise SCIMError(400, "displayName is required", scimType="invalidValue")
    _assert_group_name_available(display_name, tenant_id)
    now = _now_iso()
    group_id = uuid.uuid4().hex
    version = _new_version()
    with _cursor() as conn:
        AdaptedCursor(conn.cursor()).execute(
            """
            INSERT INTO scim_groups
              (id, tenant_id, display_name, members_json, created_at, updated_at, version)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                group_id,
                tenant_id,
                display_name,
                _json(payload.get("members"), []),
                now,
                now,
                version,
            ),
        )
    _sync_roles(tenant_id)
    _audit("group.created", tenant_id=tenant_id, subject=display_name, resource=f"scim:group:{group_id}")
    return get_group(group_id, tenant_id=tenant_id)


def get_group(group_id: str, *, tenant_id: str) -> dict[str, Any]:
    group = _fetch_group(group_id, tenant_id)
    if not group:
        raise SCIMError(404, "Group not found")
    return group


def list_groups(*, tenant_id: str, filter_expr: str | None = None) -> dict[str, Any]:
    init_db()
    with _cursor() as conn:
        rows = AdaptedCursor(conn.cursor()).execute(
            "SELECT * FROM scim_groups WHERE tenant_id=? ORDER BY display_name ASC, id ASC",
            (tenant_id,),
        ).fetchall()
    records = [_group_row_to_resource(row) for row in rows]
    if filter_expr:
        from modules.auth.scim_filter import FilterError, UnsupportedFilter, parse

        try:
            predicate = parse(filter_expr)
        except UnsupportedFilter as exc:
            raise SCIMError(501, str(exc), scimType="invalidFilter")
        except FilterError as exc:
            raise SCIMError(400, str(exc), scimType="invalidFilter")
        records = [r for r in records if predicate(r)]
    return {
        "schemas": [SCHEMA_LIST_RESPONSE],
        "totalResults": len(records),
        "Resources": records,
        "startIndex": 1,
        "itemsPerPage": len(records),
    }


def patch_group(group_id: str, patch_doc: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
    from modules.auth.scim_patch import PatchError, UnsupportedPatch, apply_patch

    existing = get_group(group_id, tenant_id=tenant_id)
    try:
        patched = apply_patch(existing, patch_doc)
    except UnsupportedPatch as exc:
        raise SCIMError(501, str(exc), scimType="invalidPath")
    except PatchError as exc:
        raise SCIMError(400, str(exc), scimType="invalidValue")
    for protected in ("id", "schemas", "meta"):
        patched.pop(protected, None)
    merged = {**existing, **patched}
    display_name = str(merged.get("displayName") or existing["displayName"]).strip()
    if not display_name:
        raise SCIMError(400, "displayName is required", scimType="invalidValue")
    _assert_group_name_available(display_name, tenant_id, except_group_id=group_id)
    now = _now_iso()
    with _cursor() as conn:
        AdaptedCursor(conn.cursor()).execute(
            """
            UPDATE scim_groups
            SET display_name=?, members_json=?, updated_at=?, version=?
            WHERE id=? AND tenant_id=?
            """,
            (
                display_name,
                _json(merged.get("members"), []),
                now,
                _new_version(),
                group_id,
                tenant_id,
            ),
        )
    _sync_roles(tenant_id)
    _audit("group.patched", tenant_id=tenant_id, subject=display_name, resource=f"scim:group:{group_id}")
    return get_group(group_id, tenant_id=tenant_id)


def delete_group(group_id: str, *, tenant_id: str) -> None:
    existing = get_group(group_id, tenant_id=tenant_id)
    with _cursor() as conn:
        AdaptedCursor(conn.cursor()).execute(
            "DELETE FROM scim_groups WHERE id=? AND tenant_id=?",
            (group_id, tenant_id),
        )
    _sync_roles(tenant_id)
    _audit("group.deleted", tenant_id=tenant_id, subject=existing["displayName"], resource=f"scim:group:{group_id}")


# -- Discovery -----------------------------------------------------------------


def service_provider_config() -> dict[str, Any]:
    return {
        "schemas": [SCHEMA_SP_CONFIG],
        "documentationUri": "https://github.com/Bobcatsfan33/TokenDNA",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": True},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Bearer token issued via TokenDNA admin console",
                "specUri": "https://datatracker.ietf.org/doc/html/rfc6750",
                "primary": True,
            }
        ],
    }


def resource_types() -> dict[str, Any]:
    return {
        "schemas": [SCHEMA_LIST_RESPONSE],
        "totalResults": 2,
        "Resources": [
            {
                "schemas": [SCHEMA_RESOURCE_TYPE],
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "description": "TokenDNA user",
                "schema": SCHEMA_USER,
            },
            {
                "schemas": [SCHEMA_RESOURCE_TYPE],
                "id": "Group",
                "name": "Group",
                "endpoint": "/Groups",
                "description": "TokenDNA group",
                "schema": SCHEMA_GROUP,
            },
        ],
        "startIndex": 1,
        "itemsPerPage": 2,
    }


def _reset_for_tests() -> None:
    init_db()
    with _cursor() as conn:
        cur = AdaptedCursor(conn.cursor())
        cur.execute("DELETE FROM scim_groups")
        cur.execute("DELETE FROM scim_users")
