"""Schema registry — version-aware deserialiser.

The collector stamps every event with ``schema_version``.  The cloud
must accept frames from collectors at any supported version and reject
frames at unsupported versions with a precise error so the operator
can identify which collector to upgrade.

Adding a new schema version is a two-part change:

  1. Update ``tokendna_collector.schema.SCHEMA_VERSION`` (collector side).
  2. Register a deserialiser here that maps the new shape to the cloud's
     internal ``NormalizedEvent`` representation.

The deserialiser is purely additive — old versions keep working until
they are explicitly retired.  Retirement requires a coordinated
deprecation window on the customer side.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from __future__ import annotations

from typing import Any, Callable

from ..schema import KNOWN_SCHEMA_VERSIONS, NormalizedEvent, SchemaError


Deserializer = Callable[[dict[str, Any]], NormalizedEvent]


class UnsupportedSchemaError(SchemaError):
    """Inbound event carries a schema_version we cannot handle."""


class SchemaRegistry:
    """Version → deserialiser dispatch."""

    def __init__(self) -> None:
        self._deserializers: dict[str, Deserializer] = {}
        # 1.0 is the inaugural shipping version; default deserialiser is
        # ``NormalizedEvent.from_wire`` which already handles 1.0.
        self.register("1.0", NormalizedEvent.from_wire)

    def register(self, version: str, deserialiser: Deserializer) -> None:
        if version in self._deserializers:
            raise ValueError(f"schema version already registered: {version}")
        self._deserializers[version] = deserialiser

    def deserialize(self, payload: dict[str, Any]) -> NormalizedEvent:
        version = str(payload.get("schema_version") or "1.0")
        de = self._deserializers.get(version)
        if de is None:
            raise UnsupportedSchemaError(
                f"schema_version {version!r} is not supported; "
                f"known versions: {sorted(self._deserializers.keys())}"
            )
        return de(payload)

    @property
    def known_versions(self) -> frozenset[str]:
        """Snapshot of every version this registry can deserialise."""
        return frozenset(self._deserializers.keys())


# Module-level guard: we never want the registry's defaults to drift
# from the cloud schema's KNOWN_SCHEMA_VERSIONS constant — the latter
# is the source of truth that downstream engines read.
_DEFAULT = SchemaRegistry()
assert _DEFAULT.known_versions == KNOWN_SCHEMA_VERSIONS, (
    f"SchemaRegistry default versions {_DEFAULT.known_versions} drift from "
    f"schema.KNOWN_SCHEMA_VERSIONS {KNOWN_SCHEMA_VERSIONS}"
)


def default_registry() -> SchemaRegistry:
    """Return a fresh registry preloaded with every known version.

    Tests that need to register custom deserialisers should construct
    a fresh ``SchemaRegistry()`` directly rather than mutate this.
    """
    reg = SchemaRegistry()
    return reg
