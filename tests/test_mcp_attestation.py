from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity.mcp_attestation import verify_mcp_server


def test_mcp_verify_trusted_when_manifest_capabilities_and_policy_match():
    manifest = {"name": "toolbox", "capabilities": ["search", "read", "write"]}
    from modules.identity.mcp_attestation import _hash_json
    expected_hash = _hash_json(manifest)

    result = verify_mcp_server(
        manifest=manifest,
        expected_manifest_hash=expected_hash,
        observed_capabilities=["search", "read", "write"],
        authorized_agent_ids=["agent-1", "agent-2"],
        connecting_agent_id="agent-1",
    )
    assert result.trusted is True
    assert result.reason == "trusted"


def test_mcp_verify_detects_manifest_hash_mismatch():
    manifest = {"name": "toolbox", "capabilities": ["search"]}
    result = verify_mcp_server(
        manifest=manifest,
        expected_manifest_hash="deadbeef",
        observed_capabilities=["search"],
    )
    assert result.integrity_ok is False
    assert result.trusted is False
    assert result.reason == "manifest_hash_mismatch"


def test_mcp_verify_detects_capability_attestation_failure():
    manifest = {"name": "toolbox", "capabilities": ["search", "read"]}
    from modules.identity.mcp_attestation import _hash_json
    expected_hash = _hash_json(manifest)
    result = verify_mcp_server(
        manifest=manifest,
        expected_manifest_hash=expected_hash,
        observed_capabilities=["search", "delete"],
    )
    assert result.capability_ok is False
    assert result.missing_capabilities == ["read"]
    assert result.unexpected_capabilities == ["delete"]
    assert result.reason == "capability_attestation_failed"

