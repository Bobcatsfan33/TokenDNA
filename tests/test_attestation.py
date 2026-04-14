from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity.attestation import build_agent_dna_fingerprint, create_attestation_record


def test_agent_dna_fingerprint_is_deterministic():
    runtime = {"runtime": "python3.12", "region": "us-east-1"}
    behavior = {"api_call_rate": 12, "resource_profile": "read-heavy"}
    a = build_agent_dna_fingerprint("agent-1", runtime, behavior)
    b = build_agent_dna_fingerprint("agent-1", runtime, behavior)
    assert a == b
    assert len(a) == 64


def test_create_attestation_record_contains_four_dimensions():
    record = create_attestation_record(
        agent_id="agent-9",
        owner_org="Acme",
        created_by="builder@acme.com",
        soul_hash="soulhash",
        directive_hashes=["d1", "d2"],
        model_fingerprint="model-fp",
        mcp_manifest_hash="manifest-hash",
        auth_method="dpop",
        dpop_bound=True,
        mtls_bound=False,
        behavior_confidence=0.91,
        declared_purpose="invoice reconciliation",
        scope=["invoices:read", "invoices:write"],
        delegation_chain=["workflow-service", "agent-9"],
        policy_trace_id="trace-123",
        runtime_context={"runtime": "py"},
        behavior_features={"cadence": "steady"},
    )
    payload = record.to_dict()
    assert payload["who"]["agent_id"] == "agent-9"
    assert payload["what"]["soul_hash"] == "soulhash"
    assert payload["how"]["dpop_bound"] is True
    assert payload["why"]["declared_purpose"] == "invoice reconciliation"
    assert len(payload["integrity_digest"]) == 64
    assert len(payload["agent_dna_fingerprint"]) == 64

