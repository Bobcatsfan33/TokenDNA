"""
TokenDNA -- Universal Identity Schema (UIS) normalization.

UIS provides a protocol-agnostic event format with eight field sets:
  - identity.*
  - auth.*
  - token.*
  - session.*
  - behavior.*
  - lifecycle.*
  - threat.*
  - binding.*

This module is intentionally lightweight and open-core friendly: adapters accept
raw protocol artifacts and normalize them into a common event shape that the
rest of the pipeline can consume.

Schema source of truth
----------------------
The canonical schema lives in ``uis_schema_v1.json`` (Draft-07). Both the
runtime validator (``uis_validator.validate``) and the human-readable spec
endpoint derive from it — there is no hand-rolled list of required fields
to drift out of sync.
"""

from __future__ import annotations

import hashlib
import json
import functools
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any



# ── UIS event validator (merged from uis_validator.py — P2.3) ────────────────
#
# Deliberately NO `jsonschema` runtime dependency: keeping the SDK and core
# modules dependency-free is part of the wedge. Implements only the JSON Schema
# subset uis_schema_v1.json actually uses.
#
# Defined ABOVE the module-level UIS_VERSION below, which calls schema_version()
# at import time.

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


# Version pinned to the schema artifact's declared version — single source
# of truth, no drift.
UIS_VERSION = schema_version()

# Includes ``mcp`` because adapter inputs in uis_protocol.ADAPTER_INPUTS
# already cover MCP claims; previously the normalizer silently downgraded
# protocol="mcp" to "custom".
SUPPORTED_PROTOCOLS = {"oidc", "saml", "oauth2_opaque", "spiffe", "mcp", "custom"}


def validate_uis_event(event: dict) -> list[str]:
    """Validate a UIS event dict against the canonical JSON Schema.

    Returns a (possibly empty) list of human-readable error strings. Does
    NOT raise — callers decide what to do with the errors. Errors include
    type mismatches, enum violations, range violations, and missing
    required fields — not just field-set membership.
    """
    return validate(event)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_hash(data: Any) -> str:
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass
class UISNormalizerInput:
    protocol: str
    tenant_id: str
    tenant_name: str
    subject: str
    claims: dict[str, Any]
    request_context: dict[str, Any]
    risk_context: dict[str, Any]


def normalize_identity_event(data: UISNormalizerInput) -> dict[str, Any]:
    protocol = (data.protocol or "custom").lower()
    if protocol not in SUPPORTED_PROTOCOLS:
        protocol = "custom"

    claims = data.claims or {}
    context = data.request_context or {}
    risk = data.risk_context or {}

    issued_at = claims.get("iat")
    expires_at = claims.get("exp")

    identity = {
        "entity_type": claims.get("entity_type", "machine" if claims.get("agent_id") else "human"),
        "subject": data.subject,
        "tenant_id": data.tenant_id,
        "tenant_name": data.tenant_name,
        "display_name": claims.get("name") or claims.get("preferred_username") or data.subject,
        "machine_classification": claims.get("machine_classification", "agent" if claims.get("agent_id") else "user"),
        "agent_id": claims.get("agent_id"),
    }

    auth = {
        "method": claims.get("amr", ["password"])[0] if isinstance(claims.get("amr"), list) and claims.get("amr") else claims.get("auth_method", "unknown"),
        "mfa_asserted": bool(claims.get("mfa") or (isinstance(claims.get("amr"), list) and any(m in claims["amr"] for m in ("mfa", "otp", "hwk", "swk", "fpt")))),
        "protocol": protocol,
        "credential_strength": claims.get("acr", "standard"),
    }

    token_claims_for_hash = {
        "iss": claims.get("iss"),
        "aud": claims.get("aud"),
        "sub": data.subject,
        "scope": claims.get("scope"),
        "roles": claims.get("roles"),
        "permissions": claims.get("permissions"),
    }
    token = {
        "type": claims.get("token_type", "bearer"),
        "issuer": claims.get("iss", "unknown"),
        "audience": claims.get("aud"),
        "claims_hash": _stable_hash(token_claims_for_hash),
        "dpop_bound": bool(claims.get("dpop_jkt") or claims.get("dpop_bound")),
        "expires_at": expires_at,
        "issued_at": issued_at,
        "rotation_history": claims.get("rotation_history", []),
        "jti": claims.get("jti"),
    }

    session = {
        "id": context.get("session_id") or claims.get("session_id"),
        "request_id": context.get("request_id"),
        "ip": context.get("ip"),
        "country": context.get("country"),
        "asn": context.get("asn"),
        "device_fingerprint": context.get("device_fingerprint"),
        "user_agent": context.get("user_agent"),
        "impossible_travel": bool(risk.get("impossible_travel", False)),
        "graph_position": context.get("graph_position"),
    }

    behavior = {
        "dna_fingerprint": context.get("dna_fingerprint"),
        "pattern_deviation_score": float(risk.get("pattern_deviation_score", 0.0)),
        "velocity_anomaly": bool(risk.get("velocity_anomaly", False)),
    }

    lifecycle = {
        "state": claims.get("lifecycle_state", "active"),
        "provisioned_at": claims.get("provisioned_at"),
        "revoked_at": claims.get("revoked_at"),
        "dormant": bool(claims.get("dormant", False)),
    }

    threat = {
        "risk_score": int(risk.get("risk_score", 0)),
        "risk_tier": risk.get("risk_tier", "unknown"),
        "indicators": risk.get("indicators", []),
        "lateral_movement": bool(risk.get("lateral_movement", False)),
    }

    dpop_jkt = claims.get("dpop_jkt")
    binding = {
        "dpop_jkt": dpop_jkt,
        "dpop_bound": dpop_jkt is not None,
        "mtls_subject": claims.get("mtls_subject"),
        "spiffe_id": claims.get("spiffe_id"),
        "attestation_id": claims.get("attestation_id"),
        "supply_chain_hash": claims.get("supply_chain_hash"),
    }

    # Content-addressed event_id: stable across re-normalization with the
    # same inputs. Consumer-side dedup is meaningful only when re-running
    # the normalizer on identical input produces the same id. The previous
    # implementation hashed time.time_ns() and so produced a fresh id every
    # call, defeating dedup. Caller-supplied event_id still wins.
    event_id = context.get("event_id") or _stable_hash({
        "tenant_id": data.tenant_id,
        "subject": data.subject,
        "claims": claims,
        "request_id": context.get("request_id"),
        "session_id": context.get("session_id"),
    })[:32]

    event: dict[str, Any] = {
        "uis_version": UIS_VERSION,
        "event_id": event_id,
        "event_timestamp": _iso_now(),
        "identity": identity,
        "auth": auth,
        "token": token,
        "session": session,
        "behavior": behavior,
        "lifecycle": lifecycle,
        "threat": threat,
        "binding": binding,
    }

    # ── Agent behavioral DNA (non-fatal) ──────────────────────────────────────
    agent_id = identity.get("agent_id")
    if agent_id:
        try:
            from modules.identity import agent_dna as _agent_dna  # noqa: PLC0415
            baseline = _agent_dna.get_agent_dna(data.tenant_id, agent_id)
            if baseline:
                deviation_score = _agent_dna.compute_deviation_score(baseline, event)
                event["behavior"]["pattern_deviation_score"] = deviation_score
                event["behavior"]["dna_fingerprint"] = baseline.get("fingerprint_hash")
                if deviation_score > 0.6:
                    event["behavior"]["velocity_anomaly"] = True
        except Exception:  # noqa: BLE001
            pass  # DNA computation must never break the normalize flow

    return event


def normalize_from_protocol(
    protocol: str,
    tenant_id: str,
    tenant_name: str,
    subject: str,
    claims: dict[str, Any] | None = None,
    request_context: dict[str, Any] | None = None,
    risk_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return normalize_identity_event(
        UISNormalizerInput(
            protocol=protocol,
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            subject=subject,
            claims=claims or {},
            request_context=request_context or {},
            risk_context=risk_context or {},
        )
    )
