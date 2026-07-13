from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity.attestation_drift import assess_runtime_drift


def _baseline_attestation() -> dict:
    return {
        "attestation_id": "att-1",
        "who": {"agent_id": "agent-1"},
        "what": {
            "soul_hash": "soul-abc",
            "model_fingerprint": "model-1",
            "mcp_manifest_hash": "mcp-1",
        },
        "how": {
            "dpop_bound": True,
            "mtls_bound": False,
        },
        "why": {
            "scope": ["orders:read", "orders:write"],
            "delegation_chain": ["gateway", "agent-1"],
        },
    }


def test_assess_runtime_drift_no_drift_when_runtime_matches_baseline():
    result = assess_runtime_drift(
        _baseline_attestation(),
        request_headers={
            "x-agent-soul-hash": "soul-abc",
            "x-agent-model-fingerprint": "model-1",
            "x-agent-mcp-manifest-hash": "mcp-1",
            "dpop": "present",
            "x-agent-delegation-chain": "gateway,agent-1",
        },
        observed_scope=["orders:read"],
    )
    assert result.score == 0.0
    assert result.severity == "none"
    assert result.is_drift is False


def test_assess_runtime_drift_detects_high_risk_integrity_mismatch():
    result = assess_runtime_drift(
        _baseline_attestation(),
        request_headers={
            "x-agent-soul-hash": "tampered",
            "x-agent-model-fingerprint": "tampered-model",
            "x-agent-mcp-manifest-hash": "tampered-mcp",
            "x-agent-delegation-chain": "gateway,agent-2",
        },
        observed_scope=["orders:admin"],
    )
    assert result.is_drift is True
    assert result.severity in {"high", "critical"}
    assert result.should_step_up is True
    assert result.should_block is True
    assert "soul_hash_mismatch" in result.reasons

