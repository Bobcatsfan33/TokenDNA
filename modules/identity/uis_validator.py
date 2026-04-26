"""
TokenDNA — UIS event validator.

A focused JSON Schema (Draft-07) validator that operates against the
canonical ``uis_schema_v1.json`` artifact. We deliberately do *not* take a
runtime dependency on the ``jsonschema`` library — keeping the SDK and
core modules dependency-free is part of the wedge.

The validator implements just the subset of JSON Schema features that
``uis_schema_v1.json`` actually uses:

  - ``type`` (single string or list, including ``"null"``)
  - ``enum``
  - ``required``
  - ``properties`` (recursive)
  - ``items`` (for arrays)
  - ``minimum`` / ``maximum``  (numeric range)
  - ``oneOf``                  (used for token.audience)
  - ``format``                  ("date-time" only — checked permissively)

Anything else in the schema is ignored, which is fine because the
canonical schema only uses the listed keywords. If we ever extend the
schema with new keywords, the validator must be updated to match — there
is a regression test that asserts the schema only uses the supported
keyword set.
"""

from __future__ import annotations

import functools
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


_SCHEMA_PATH = Path(__file__).parent / "uis_schema_v1.json"


# ── Schema loader (cached) ────────────────────────────────────────────────────

@functools.lru_cache(maxsize=1)
def _schema() -> dict[str, Any]:
    with _SCHEMA_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


def schema_version() -> str:
    return str(_schema().get("version", "unknown"))


def schema_id() -> str:
    return str(_schema().get("$id", ""))


def schema_dict() -> dict[str, Any]:
    """Return a deep-copy of the schema dict — safe for serving from
    /api/schema/uis.json without risking mutation of the cached instance."""
    return json.loads(json.dumps(_schema()))


# ── Type checks ───────────────────────────────────────────────────────────────

_JSON_TYPE_TO_PY: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "integer": (int,),  # bool is a subclass of int — handled specially below
    "number": (int, float),
    "boolean": (bool,),
    "array": (list, tuple),
    "object": (dict,),
    # "null" handled by None check
}


def _matches_type(value: Any, type_spec: Any) -> bool:
    """``type_spec`` may be a string or a list of strings."""
    if isinstance(type_spec, list):
        return any(_matches_type(value, t) for t in type_spec)
    if not isinstance(type_spec, str):
        return True  # Unknown type spec — be permissive.
    if type_spec == "null":
        return value is None
    if value is None:
        return False
    if type_spec in ("integer", "number"):
        # JSON Schema treats booleans separately; bool ⊂ int in Python.
        if isinstance(value, bool):
            return False
    py_types = _JSON_TYPE_TO_PY.get(type_spec)
    if py_types is None:
        return True
    return isinstance(value, py_types)


# ── Format check ──────────────────────────────────────────────────────────────

_DATE_TIME_PERMISSIVE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(\.\d+)?"
    r"(Z|[+-]\d{2}:?\d{2})?$"
)


def _format_ok(value: Any, fmt: str) -> bool:
    if fmt != "date-time":
        return True   # Unknown format — be permissive.
    if not isinstance(value, str):
        return False
    if not _DATE_TIME_PERMISSIVE.match(value):
        return False
    # Final check: the stdlib accepts the value (after Z normalisation).
    s = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        datetime.fromisoformat(s)
        return True
    except (TypeError, ValueError):
        return False


# ── Recursive validator ───────────────────────────────────────────────────────

def _validate(node: Any, schema: dict[str, Any], path: str) -> list[str]:
    errors: list[str] = []

    # oneOf — value must validate against exactly one branch.
    one_of = schema.get("oneOf")
    if isinstance(one_of, list) and one_of:
        passes = 0
        for branch in one_of:
            if isinstance(branch, dict) and not _validate(node, branch, path):
                passes += 1
        if passes != 1:
            errors.append(
                f"{path or '<root>'}: value did not match exactly one of "
                f"{len(one_of)} oneOf branches"
            )
        return errors

    # Type check first; subsequent checks assume the value is the right kind.
    type_spec = schema.get("type")
    if type_spec is not None and not _matches_type(node, type_spec):
        errors.append(
            f"{path or '<root>'}: expected type {type_spec!r}, "
            f"got {type(node).__name__}"
        )
        return errors

    # Enum.
    enum = schema.get("enum")
    if isinstance(enum, list) and node not in enum:
        errors.append(
            f"{path or '<root>'}: value {node!r} is not in enum {enum}"
        )

    # Numeric ranges (minimum/maximum).
    if isinstance(node, (int, float)) and not isinstance(node, bool):
        mn = schema.get("minimum")
        mx = schema.get("maximum")
        if mn is not None and node < mn:
            errors.append(f"{path or '<root>'}: {node} < minimum {mn}")
        if mx is not None and node > mx:
            errors.append(f"{path or '<root>'}: {node} > maximum {mx}")

    # Format.
    fmt = schema.get("format")
    if fmt is not None and isinstance(node, str) and not _format_ok(node, fmt):
        errors.append(f"{path or '<root>'}: value {node!r} fails format {fmt!r}")

    # Object: required + properties.
    if isinstance(node, dict):
        for req in schema.get("required", []) or []:
            if req not in node:
                # Emit dot-path notation so error paths chain consistently
                # (e.g. ``identity.subject: missing required field``).
                full = f"{path}.{req}" if path else req
                errors.append(f"{full}: missing required field")
        props = schema.get("properties") or {}
        for key, val in node.items():
            sub = props.get(key)
            if isinstance(sub, dict):
                child_path = f"{path}.{key}" if path else key
                errors.extend(_validate(val, sub, child_path))

    # Array: items.
    if isinstance(node, list):
        items = schema.get("items")
        if isinstance(items, dict):
            for i, item in enumerate(node):
                child_path = f"{path}[{i}]"
                errors.extend(_validate(item, items, child_path))

    return errors


def validate(event: dict[str, Any]) -> list[str]:
    """Validate a UIS event against the canonical JSON Schema. Returns a
    (possibly empty) list of human-readable error strings. Does not raise —
    callers decide what to do with the errors."""
    if not isinstance(event, dict):
        return ["<root>: event must be an object"]
    return _validate(event, _schema(), "")


# ── Schema introspection helpers ──────────────────────────────────────────────

def required_field_sets() -> dict[str, list[str]]:
    """Return ``{field_set_name: [required, fields, ...]}`` derived from the
    JSON Schema. The single source of truth for both ``uis.py`` and
    ``uis_protocol.py`` — replaces the previously-duplicated constants."""
    out: dict[str, list[str]] = {}
    props = _schema().get("properties", {}) or {}
    for fs_name, fs_schema in props.items():
        if not isinstance(fs_schema, dict):
            continue
        if fs_schema.get("type") != "object":
            continue
        out[fs_name] = list(fs_schema.get("required", []) or [])
    return out


def field_set_descriptions() -> dict[str, str]:
    """``{field_set_name: description}`` derived from the JSON Schema."""
    out: dict[str, str] = {}
    props = _schema().get("properties", {}) or {}
    for fs_name, fs_schema in props.items():
        if isinstance(fs_schema, dict) and fs_schema.get("type") == "object":
            out[fs_name] = str(fs_schema.get("description", ""))
    return out
