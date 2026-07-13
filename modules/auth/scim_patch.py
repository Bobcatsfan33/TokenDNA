"""
TokenDNA — SCIM PATCH (RFC 7644 §3.5.2).

Applies a PatchOp document to a resource dict. Supports:

* ``op = add | replace | remove``
* simple paths: ``active``, ``name.givenName``, ``emails``
* whole-resource replace: omitted ``path`` with ``op = add | replace``

Out of scope (raises :class:`UnsupportedPatch` so the caller can 400):

* value-filtered paths inside multi-valued attributes:
  ``emails[type eq "work"].value``. These appear in the spec but most
  IdPs send the simpler ``replace emails`` shape; we'll add filtered
  paths after observing real customer traffic.

All mutations operate on a *copy* of the input resource — the caller's
input dict is never modified in place.
"""

from __future__ import annotations

import copy
from typing import Any


SCHEMA_PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


class PatchError(ValueError):
    """Generic PATCH validation error."""


class UnsupportedPatch(PatchError):
    """Raised when a PATCH op uses syntax we deliberately don't implement."""


def apply_patch(resource: dict[str, Any], patch_doc: dict[str, Any]) -> dict[str, Any]:
    """Return a new resource dict with the patch applied.

    Raises :class:`PatchError` on malformed documents and
    :class:`UnsupportedPatch` for spec-correct shapes we don't handle yet.
    """
    if SCHEMA_PATCH_OP not in (patch_doc.get("schemas") or []):
        raise PatchError("PatchOp schema missing")
    operations = patch_doc.get("Operations") or []
    if not isinstance(operations, list) or not operations:
        raise PatchError("Operations must be a non-empty list")

    out = copy.deepcopy(resource)
    for op in operations:
        if not isinstance(op, dict):
            raise PatchError("each Operation must be an object")
        op_name = (op.get("op") or "").lower()
        if op_name not in ("add", "replace", "remove"):
            raise PatchError(f"unsupported op: {op.get('op')!r}")
        path = op.get("path")
        value = op.get("value")
        if path and ("[" in path or "]" in path):
            raise UnsupportedPatch(
                "value-filtered paths (path[filter]) are not yet supported"
            )
        if op_name == "remove":
            if not path:
                raise PatchError("remove requires path")
            _remove(out, path)
        elif op_name == "replace":
            if path:
                _set(out, path, value)
            else:
                if not isinstance(value, dict):
                    raise PatchError("replace without path requires an object value")
                # Whole-resource merge replace (preserve id / meta unless caller overwrites).
                for k, v in value.items():
                    out[k] = v
        else:  # add
            if path:
                _add(out, path, value)
            else:
                if not isinstance(value, dict):
                    raise PatchError("add without path requires an object value")
                for k, v in value.items():
                    if k not in out:
                        out[k] = v
                    elif isinstance(out[k], list) and isinstance(v, list):
                        out[k] = out[k] + v
                    else:
                        out[k] = v
    return out


# ── Path helpers ──────────────────────────────────────────────────────────────


def _split_path(path: str) -> list[str]:
    return [p for p in path.split(".") if p]


def _walk(node: dict[str, Any], parts: list[str]) -> tuple[dict[str, Any], str]:
    """Descend through ``parts[:-1]`` creating intermediate dicts, return
    ``(parent, leaf_key)``."""
    cur = node
    for part in parts[:-1]:
        existing = cur.get(part)
        if isinstance(existing, dict):
            cur = existing
        elif existing is None:
            cur[part] = {}
            cur = cur[part]
        else:
            raise PatchError(f"cannot descend into non-object at {part!r}")
    return cur, parts[-1]


def _set(node: dict[str, Any], path: str, value: Any) -> None:
    parts = _split_path(path)
    if not parts:
        raise PatchError("empty path")
    parent, leaf = _walk(node, parts)
    parent[leaf] = value


def _remove(node: dict[str, Any], path: str) -> None:
    parts = _split_path(path)
    if not parts:
        raise PatchError("empty path")
    parent, leaf = _walk(node, parts)
    parent.pop(leaf, None)


def _add(node: dict[str, Any], path: str, value: Any) -> None:
    parts = _split_path(path)
    if not parts:
        raise PatchError("empty path")
    parent, leaf = _walk(node, parts)
    existing = parent.get(leaf)
    if existing is None:
        parent[leaf] = value
    elif isinstance(existing, list) and isinstance(value, list):
        parent[leaf] = existing + value
    elif isinstance(existing, list):
        parent[leaf] = existing + [value]
    else:
        # add on a scalar acts like replace per RFC 7644 §3.5.2.1.
        parent[leaf] = value
