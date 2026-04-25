"""
Tests for modules/identity/uis_validator.py — the JSON Schema-backed UIS
event validator that replaces the field-set-membership-only check.

Coverage:
  - Type checks: string / integer / number / boolean / array / object
    detection, including the ``["type", "null"]`` union shape used in the
    schema.
  - Enum violations are detected (e.g. invalid ``risk_tier``).
  - Numeric range violations are detected (``risk_score`` > 100).
  - ``oneOf`` works for ``token.audience`` (string OR array OR null).
  - Required field detection still works.
  - Format check rejects malformed ``date-time`` strings.
  - The schema only uses keywords the validator implements (regression
    guard — adding a new keyword to the schema must come with a validator
    extension).
  - Field-set introspection helpers (``required_field_sets`` /
    ``field_set_descriptions``) match what's actually in the schema.

Plus integration tests:
  - The full normalize → validate round-trip produces 0 errors on a happy
    path event.
  - Removing a required field surfaces the right error path.
  - Stable event_id: re-running the normalizer with identical inputs
    produces the same event_id.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from modules.identity import uis_validator
from modules.identity.uis import (
    SUPPORTED_PROTOCOLS,
    UIS_VERSION,
    normalize_from_protocol,
    validate_uis_event,
)


# ─────────────────────────────────────────────────────────────────────────────
# Schema artifact + introspection
# ─────────────────────────────────────────────────────────────────────────────

class TestSchemaArtifact:
    def test_schema_loads(self):
        s = uis_validator.schema_dict()
        assert isinstance(s, dict)
        assert s.get("type") == "object"

    def test_uis_version_matches_schema(self):
        # Single source of truth — uis.UIS_VERSION must equal the schema's
        # declared version.
        assert UIS_VERSION == uis_validator.schema_version()

    def test_required_field_sets_match_schema(self):
        rfs = uis_validator.required_field_sets()
        # Eight field sets defined in the schema.
        assert set(rfs.keys()) == {
            "identity", "auth", "token", "session",
            "behavior", "lifecycle", "threat", "binding",
        }
        # Spot-check a couple — must reflect the schema verbatim.
        assert "subject" in rfs["identity"]
        assert "risk_tier" in rfs["threat"]


class TestSchemaUsesOnlyKnownKeywords:
    """Regression guard: if the schema gains a JSON-Schema keyword the
    validator doesn't implement, this test fails — preventing silent
    under-validation of newer schema versions.

    The walk visits only sub-schema positions (top-level, ``properties.*``,
    ``items``, ``oneOf[]``) — property names like ``risk_tier`` are
    application identifiers, not schema keywords, so they're excluded.
    """

    SUPPORTED = {
        # Annotation-only — ignored by the validator.
        "$schema", "$id", "title", "description", "version", "example",
        # Constraint keywords the validator implements.
        "type", "enum", "required", "properties", "items",
        "minimum", "maximum", "format", "oneOf",
        # Tolerated no-op (we accept extra fields by default).
        "additionalProperties",
    }

    def _walk_subschema(self, node, found: set[str]) -> None:
        if not isinstance(node, dict):
            return
        for key, value in node.items():
            found.add(key)
            if key == "properties" and isinstance(value, dict):
                for prop_schema in value.values():
                    self._walk_subschema(prop_schema, found)
            elif key == "items" and isinstance(value, dict):
                self._walk_subschema(value, found)
            elif key == "oneOf" and isinstance(value, list):
                for branch in value:
                    self._walk_subschema(branch, found)

    def test_schema_only_uses_supported_keywords(self):
        keys: set[str] = set()
        self._walk_subschema(uis_validator.schema_dict(), keys)
        unsupported = keys - self.SUPPORTED
        assert not unsupported, (
            f"schema uses unsupported keywords {unsupported!r} — extend "
            f"uis_validator before bumping the schema."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Validator behaviour
# ─────────────────────────────────────────────────────────────────────────────

def _good_event() -> dict:
    """A minimal-but-valid UIS event the schema accepts."""
    return {
        "uis_version": UIS_VERSION,
        "event_id": "abc123",
        "event_timestamp": "2026-04-25T00:00:00+00:00",
        "identity": {
            "subject": "u@x", "tenant_id": "t", "entity_type": "human",
        },
        "auth": {
            "protocol": "oidc", "method": "password", "mfa_asserted": True,
        },
        "token": {
            "issuer": "https://x", "type": "bearer", "claims_hash": "h",
        },
        "session": {
            "request_id": "r-1", "ip": "1.2.3.4",
            "country": "US", "asn": "AS1",
        },
        "behavior": {
            "dna_fingerprint": None, "pattern_deviation_score": 0.0,
            "velocity_anomaly": False,
        },
        "lifecycle": {
            "state": "active", "provisioned_at": None, "revoked_at": None,
            "dormant": False,
        },
        "threat": {"risk_score": 10, "risk_tier": "low", "indicators": []},
        "binding": {"dpop_jkt": None, "attestation_id": None},
    }


class TestValidatorRequired:
    def test_happy_path_valid(self):
        assert validate_uis_event(_good_event()) == []

    def test_missing_field_set(self):
        ev = _good_event()
        del ev["threat"]
        errors = validate_uis_event(ev)
        assert any("threat" in e for e in errors)

    def test_missing_required_property(self):
        ev = _good_event()
        del ev["identity"]["subject"]
        errors = validate_uis_event(ev)
        assert any("subject" in e for e in errors)

    def test_non_dict_event(self):
        errors = validate_uis_event(["not", "a", "dict"])  # type: ignore[arg-type]
        assert errors


class TestValidatorTypes:
    def test_wrong_type_for_required_string_caught(self):
        ev = _good_event()
        ev["identity"]["subject"] = 12345  # should be string
        errors = validate_uis_event(ev)
        assert any("identity.subject" in e and "type" in e for e in errors)

    def test_boolean_not_accepted_as_integer(self):
        # JSON Schema separates bool from int.
        ev = _good_event()
        ev["threat"]["risk_score"] = True  # should be int
        errors = validate_uis_event(ev)
        assert any("risk_score" in e and "type" in e for e in errors)

    def test_null_accepted_for_nullable_field(self):
        ev = _good_event()
        ev["session"]["ip"] = None
        assert validate_uis_event(ev) == []

    def test_null_rejected_for_strict_string_field(self):
        ev = _good_event()
        ev["identity"]["subject"] = None
        errors = validate_uis_event(ev)
        assert any("identity.subject" in e for e in errors)


class TestValidatorEnums:
    def test_invalid_risk_tier_rejected(self):
        ev = _good_event()
        ev["threat"]["risk_tier"] = "vibes"
        errors = validate_uis_event(ev)
        assert any("risk_tier" in e and "enum" in e for e in errors)

    def test_invalid_protocol_rejected(self):
        ev = _good_event()
        ev["auth"]["protocol"] = "telepathy"
        errors = validate_uis_event(ev)
        assert any("auth.protocol" in e for e in errors)

    def test_valid_lifecycle_state(self):
        ev = _good_event()
        ev["lifecycle"]["state"] = "suspended"
        assert validate_uis_event(ev) == []

    def test_invalid_lifecycle_state(self):
        ev = _good_event()
        ev["lifecycle"]["state"] = "neither_alive_nor_dead"
        errors = validate_uis_event(ev)
        assert any("lifecycle.state" in e for e in errors)


class TestValidatorRanges:
    def test_risk_score_above_max_rejected(self):
        ev = _good_event()
        ev["threat"]["risk_score"] = 999
        errors = validate_uis_event(ev)
        assert any("risk_score" in e and "maximum" in e for e in errors)

    def test_pattern_deviation_below_min_rejected(self):
        ev = _good_event()
        ev["behavior"]["pattern_deviation_score"] = -1
        errors = validate_uis_event(ev)
        assert any("pattern_deviation_score" in e for e in errors)


class TestValidatorOneOf:
    """token.audience is `oneOf [string, array<string>, null]`."""

    def test_string_audience_valid(self):
        ev = _good_event()
        ev["token"]["audience"] = "api"
        assert validate_uis_event(ev) == []

    def test_array_audience_valid(self):
        ev = _good_event()
        ev["token"]["audience"] = ["a", "b"]
        assert validate_uis_event(ev) == []

    def test_null_audience_valid(self):
        ev = _good_event()
        ev["token"]["audience"] = None
        assert validate_uis_event(ev) == []

    def test_integer_audience_invalid(self):
        ev = _good_event()
        ev["token"]["audience"] = 12345
        errors = validate_uis_event(ev)
        assert any("token.audience" in e for e in errors)


class TestValidatorFormat:
    def test_valid_iso_timestamp(self):
        ev = _good_event()
        ev["event_timestamp"] = "2026-04-25T12:34:56.789+00:00"
        assert validate_uis_event(ev) == []

    def test_invalid_timestamp_rejected(self):
        ev = _good_event()
        ev["event_timestamp"] = "yesterday"
        errors = validate_uis_event(ev)
        assert any("event_timestamp" in e and "format" in e for e in errors)


# ─────────────────────────────────────────────────────────────────────────────
# Normalizer integration
# ─────────────────────────────────────────────────────────────────────────────

class TestNormalizerProducesValidEvents:
    def test_oidc_minimal_input(self):
        ev = normalize_from_protocol(
            protocol="oidc",
            tenant_id="t-1",
            tenant_name="Tenant",
            subject="u@x",
            claims={"iss": "https://x", "aud": "api", "amr": ["pwd"]},
        )
        assert validate_uis_event(ev) == []

    def test_mcp_protocol_no_longer_downgraded(self):
        # Pre-fix: passing protocol="mcp" silently downgraded to "custom"
        # because mcp wasn't in SUPPORTED_PROTOCOLS. Now it stays as "mcp"
        # and validates.
        assert "mcp" in SUPPORTED_PROTOCOLS
        ev = normalize_from_protocol(
            protocol="mcp",
            tenant_id="t-1",
            tenant_name="Tenant",
            subject="agent-x",
            claims={"agent_id": "agent-x", "iss": "https://mcp"},
        )
        assert ev["auth"]["protocol"] == "mcp"
        assert validate_uis_event(ev) == []


class TestStableEventId:
    """event_id must be content-addressed: identical inputs → identical id."""

    def _make(self, **kwargs):
        return normalize_from_protocol(
            protocol="oidc", tenant_id="t-1", tenant_name="T",
            subject="u@x",
            claims={"iss": "https://x", "jti": "j-fixed"},
            request_context={"request_id": "r-fixed"},
            **kwargs,
        )

    def test_same_inputs_same_event_id(self):
        a = self._make()
        b = self._make()
        assert a["event_id"] == b["event_id"]

    def test_different_subject_different_event_id(self):
        a = normalize_from_protocol(
            protocol="oidc", tenant_id="t", tenant_name="T",
            subject="alice", claims={"iss": "https://x"},
            request_context={"request_id": "r"},
        )
        b = normalize_from_protocol(
            protocol="oidc", tenant_id="t", tenant_name="T",
            subject="bob", claims={"iss": "https://x"},
            request_context={"request_id": "r"},
        )
        assert a["event_id"] != b["event_id"]

    def test_caller_supplied_event_id_wins(self):
        ev = normalize_from_protocol(
            protocol="oidc", tenant_id="t", tenant_name="T",
            subject="u@x", claims={"iss": "https://x"},
            request_context={"event_id": "explicit-id-001", "request_id": "r"},
        )
        assert ev["event_id"] == "explicit-id-001"
