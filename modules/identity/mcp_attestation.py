"""
TokenDNA -- MCP server attestation verification.

Implements open-core MCP verification primitives:
  - Manifest integrity verification
  - Capability attestation (declared vs observed tool set)
  - Optional policy gate for agent<->MCP authorization
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


def _hash_json(data: dict[str, Any]) -> str:
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass
class MCPVerificationResult:
    integrity_ok: bool
    capability_ok: bool
    policy_ok: bool
    expected_manifest_hash: str
    computed_manifest_hash: str
    missing_capabilities: list[str]
    unexpected_capabilities: list[str]
    reason: str

    @property
    def trusted(self) -> bool:
        return self.integrity_ok and self.capability_ok and self.policy_ok

    def to_dict(self) -> dict[str, Any]:
        return {
            "integrity_ok": self.integrity_ok,
            "capability_ok": self.capability_ok,
            "policy_ok": self.policy_ok,
            "trusted": self.trusted,
            "expected_manifest_hash": self.expected_manifest_hash,
            "computed_manifest_hash": self.computed_manifest_hash,
            "missing_capabilities": self.missing_capabilities,
            "unexpected_capabilities": self.unexpected_capabilities,
            "reason": self.reason,
        }


def verify_mcp_server(
    *,
    manifest: dict[str, Any],
    expected_manifest_hash: str,
    observed_capabilities: list[str],
    authorized_agent_ids: list[str] | None = None,
    connecting_agent_id: str | None = None,
) -> MCPVerificationResult:
    computed_hash = _hash_json(manifest)
    integrity_ok = computed_hash == expected_manifest_hash

    declared = set(manifest.get("capabilities", []))
    observed = set(observed_capabilities or [])
    missing = sorted(declared - observed)
    unexpected = sorted(observed - declared)
    capability_ok = not missing and not unexpected

    policy_ok = True
    if authorized_agent_ids is not None and connecting_agent_id is not None:
        policy_ok = connecting_agent_id in set(authorized_agent_ids)

    if not integrity_ok:
        reason = "manifest_hash_mismatch"
    elif not capability_ok:
        reason = "capability_attestation_failed"
    elif not policy_ok:
        reason = "agent_not_authorized_for_mcp"
    else:
        reason = "trusted"

    return MCPVerificationResult(
        integrity_ok=integrity_ok,
        capability_ok=capability_ok,
        policy_ok=policy_ok,
        expected_manifest_hash=expected_manifest_hash,
        computed_manifest_hash=computed_hash,
        missing_capabilities=missing,
        unexpected_capabilities=unexpected,
        reason=reason,
    )

