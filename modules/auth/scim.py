"""
TokenDNA — SCIM 2.0 (alpha)

Implements the subset of SCIM 2.0 (RFC 7644) that enterprise customers
typically wire up first: user create / read / update / delete and group
membership management. Storage is the existing tenant store — SCIM is a
shape on top of TokenDNA's tenant + identity primitives, not a separate
identity store.

Resource types implemented:

* ``User``  — CRUD via ``/scim/v2/Users``.
* ``Group`` — CRUD via ``/scim/v2/Groups``.

The module deliberately rejects requests it cannot fulfill rather than
silently approximating SCIM semantics. SCIM PATCH and complex filter
queries (``filter=userName eq "alice"``) are accepted with a documented
subset; anything else returns a SCIM-formatted 501.

Authentication of the SCIM endpoint is handled by the existing
``Authorization: Bearer`` middleware. SCIM tokens are scoped per tenant
and rotated by the operator via the admin console.
"""

from __future__ import annotations

import logging
import json
import os
import threading
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCHEMA_LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
ROLE_VALUES = {"owner", "admin", "analyst", "readonly"}

_lock = threading.Lock()
# Stage 1 in-memory store. Stage 2 will route through tenant_store.
_users: dict[str, dict[str, Any]] = {}
_groups: dict[str, dict[str, Any]] = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _meta(resource_id: str, resource_type: str) -> dict[str, Any]:
    now = _now_iso()
    return {
        "resourceType": resource_type,
        "created": now,
        "lastModified": now,
        "version": f'W/"{uuid.uuid4().hex}"',
        "location": f"/scim/v2/{resource_type}s/{resource_id}",
    }


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


# ── User CRUD ─────────────────────────────────────────────────────────────────


def create_user(payload: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
    if SCHEMA_USER not in (payload.get("schemas") or []):
        raise SCIMError(400, "User schema missing", scimType="invalidValue")
    user_name = payload.get("userName")
    if not user_name:
        raise SCIMError(400, "userName is required", scimType="invalidValue")
    user_id = uuid.uuid4().hex
    record = {
        "schemas": [SCHEMA_USER],
        "id": user_id,
        "userName": user_name,
        "active": bool(payload.get("active", True)),
        "name": payload.get("name") or {},
        "emails": payload.get("emails") or [],
        "roles": _normalize_roles(payload.get("roles") or []),
        "_manual_roles": _normalize_roles(payload.get("roles") or []),
        "_scim_group_roles": [],
        "tenant_id": tenant_id,
        "meta": _meta(user_id, "User"),
    }
    with _lock:
        for existing in _users.values():
            if existing["tenant_id"] == tenant_id and existing["userName"] == user_name:
                raise SCIMError(409, "User already exists", scimType="uniqueness")
        _users[user_id] = record
    return _strip_internal(record)


def get_user(user_id: str, *, tenant_id: str) -> dict[str, Any]:
    with _lock:
        record = _users.get(user_id)
        if not record or record["tenant_id"] != tenant_id:
            raise SCIMError(404, "User not found")
        return _strip_internal(record)


def replace_user(user_id: str, payload: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
    with _lock:
        record = _users.get(user_id)
        if not record or record["tenant_id"] != tenant_id:
            raise SCIMError(404, "User not found")
        if "userName" in payload:
            record["userName"] = payload["userName"]
        if "active" in payload:
            record["active"] = bool(payload["active"])
        if "name" in payload:
            record["name"] = payload["name"]
        if "emails" in payload:
            record["emails"] = payload["emails"]
        if "roles" in payload:
            record["_manual_roles"] = _normalize_roles(payload["roles"])
            _sync_user_roles(record)
        record["meta"]["lastModified"] = _now_iso()
        return _strip_internal(record)


def delete_user(user_id: str, *, tenant_id: str) -> None:
    with _lock:
        record = _users.get(user_id)
        if not record or record["tenant_id"] != tenant_id:
            raise SCIMError(404, "User not found")
        del _users[user_id]


def list_users(
    *,
    tenant_id: str,
    start_index: int = 1,
    count: int = 100,
    filter_expr: str | None = None,
) -> dict[str, Any]:
    if start_index < 1 or count < 0:
        raise SCIMError(400, "Invalid startIndex/count", scimType="invalidValue")
    with _lock:
        all_records = [u for u in _users.values() if u["tenant_id"] == tenant_id]
    if filter_expr:
        from modules.auth.scim_filter import FilterError, UnsupportedFilter, parse
        try:
            predicate = parse(filter_expr)
        except UnsupportedFilter as exc:
            raise SCIMError(501, str(exc), scimType="invalidFilter")
        except FilterError as exc:
            raise SCIMError(400, str(exc), scimType="invalidFilter")
        all_records = [r for r in all_records if predicate(_strip_internal(r))]
    total = len(all_records)
    page = all_records[start_index - 1 : start_index - 1 + count]
    return {
        "schemas": [SCHEMA_LIST_RESPONSE],
        "totalResults": total,
        "Resources": [_strip_internal(r) for r in page],
        "startIndex": start_index,
        "itemsPerPage": len(page),
    }


def patch_user(user_id: str, patch_doc: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
    """Apply a SCIM PatchOp document to a User resource."""
    from modules.auth.scim_patch import PatchError, UnsupportedPatch, apply_patch

    with _lock:
        record = _users.get(user_id)
        if not record or record["tenant_id"] != tenant_id:
            raise SCIMError(404, "User not found")
        # apply_patch operates on a copy; we then merge selected fields
        # back so we never overwrite id / tenant_id from a malicious PATCH.
        try:
            patched = apply_patch(_strip_internal(record), patch_doc)
        except UnsupportedPatch as exc:
            raise SCIMError(501, str(exc), scimType="invalidPath")
        except PatchError as exc:
            raise SCIMError(400, str(exc), scimType="invalidValue")

        for protected in ("id", "schemas", "meta"):
            patched.pop(protected, None)
        if "roles" in patched:
            patched["_manual_roles"] = _normalize_roles(patched["roles"])
        record.update(patched)
        _sync_user_roles(record)
        record["meta"]["lastModified"] = _now_iso()
        return _strip_internal(record)


# ── Group CRUD ────────────────────────────────────────────────────────────────


def create_group(payload: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
    if SCHEMA_GROUP not in (payload.get("schemas") or []):
        raise SCIMError(400, "Group schema missing", scimType="invalidValue")
    display_name = payload.get("displayName")
    if not display_name:
        raise SCIMError(400, "displayName is required", scimType="invalidValue")
    group_id = uuid.uuid4().hex
    record = {
        "schemas": [SCHEMA_GROUP],
        "id": group_id,
        "displayName": display_name,
        "members": payload.get("members") or [],
        "tenant_id": tenant_id,
        "meta": _meta(group_id, "Group"),
    }
    with _lock:
        _groups[group_id] = record
        _sync_roles_locked(tenant_id)
    return _strip_internal(record)


def get_group(group_id: str, *, tenant_id: str) -> dict[str, Any]:
    with _lock:
        record = _groups.get(group_id)
        if not record or record["tenant_id"] != tenant_id:
            raise SCIMError(404, "Group not found")
        return _strip_internal(record)


def list_groups(*, tenant_id: str, filter_expr: str | None = None) -> dict[str, Any]:
    with _lock:
        records = [g for g in _groups.values() if g["tenant_id"] == tenant_id]
    if filter_expr:
        from modules.auth.scim_filter import FilterError, UnsupportedFilter, parse
        try:
            predicate = parse(filter_expr)
        except UnsupportedFilter as exc:
            raise SCIMError(501, str(exc), scimType="invalidFilter")
        except FilterError as exc:
            raise SCIMError(400, str(exc), scimType="invalidFilter")
        records = [r for r in records if predicate(_strip_internal(r))]
    return {
        "schemas": [SCHEMA_LIST_RESPONSE],
        "totalResults": len(records),
        "Resources": [_strip_internal(r) for r in records],
        "startIndex": 1,
        "itemsPerPage": len(records),
    }


def patch_group(group_id: str, patch_doc: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
    """Apply a SCIM PatchOp document to a Group resource."""
    from modules.auth.scim_patch import PatchError, UnsupportedPatch, apply_patch

    with _lock:
        record = _groups.get(group_id)
        if not record or record["tenant_id"] != tenant_id:
            raise SCIMError(404, "Group not found")
        try:
            patched = apply_patch(_strip_internal(record), patch_doc)
        except UnsupportedPatch as exc:
            raise SCIMError(501, str(exc), scimType="invalidPath")
        except PatchError as exc:
            raise SCIMError(400, str(exc), scimType="invalidValue")
        for protected in ("id", "schemas", "meta"):
            patched.pop(protected, None)
        record.update(patched)
        record["meta"]["lastModified"] = _now_iso()
        _sync_roles_locked(tenant_id)
        return _strip_internal(record)


def delete_group(group_id: str, *, tenant_id: str) -> None:
    with _lock:
        record = _groups.get(group_id)
        if not record or record["tenant_id"] != tenant_id:
            raise SCIMError(404, "Group not found")
        del _groups[group_id]
        _sync_roles_locked(tenant_id)


# ── Discovery endpoints ───────────────────────────────────────────────────────


def service_provider_config() -> dict[str, Any]:
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://github.com/Bobcatsfan33/TokenDNA",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
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
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "description": "TokenDNA user",
                "schema": SCHEMA_USER,
            },
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
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


def _strip_internal(record: dict[str, Any]) -> dict[str, Any]:
    out = dict(record)
    out.pop("tenant_id", None)
    out.pop("_manual_roles", None)
    out.pop("_scim_group_roles", None)
    return out


def _reset_for_tests() -> None:
    """Test helper — wipe in-memory state."""
    with _lock:
        _users.clear()
        _groups.clear()


def _normalize_roles(raw: Any) -> list[str]:
    if isinstance(raw, str):
        candidates = [raw]
    else:
        try:
            candidates = list(raw)
        except TypeError:
            candidates = []
    out: list[str] = []
    for item in candidates:
        value = str(item.get("value") if isinstance(item, dict) else item).strip().lower()
        if value in ROLE_VALUES and value not in out:
            out.append(value)
    return out


def _group_role_map() -> dict[str, str]:
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


def _member_ids(group: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for member in group.get("members") or []:
        if isinstance(member, dict):
            value = member.get("value") or member.get("$ref") or member.get("id")
        else:
            value = member
        if value:
            ids.add(str(value))
    return ids


def _sync_roles_locked(tenant_id: str) -> None:
    role_map = _group_role_map()
    for user in _users.values():
        if user.get("tenant_id") == tenant_id:
            user["_scim_group_roles"] = []

    for group in _groups.values():
        if group.get("tenant_id") != tenant_id:
            continue
        role = role_map.get(str(group.get("displayName", "")).strip().lower())
        if not role:
            continue
        for user_id in _member_ids(group):
            user = _users.get(user_id)
            if user and user.get("tenant_id") == tenant_id:
                roles = user.setdefault("_scim_group_roles", [])
                if role not in roles:
                    roles.append(role)

    for user in _users.values():
        if user.get("tenant_id") == tenant_id:
            _sync_user_roles(user)


def _sync_user_roles(user: dict[str, Any]) -> None:
    roles = sorted(set(user.get("_manual_roles") or []) | set(user.get("_scim_group_roles") or []))
    user["roles"] = roles
