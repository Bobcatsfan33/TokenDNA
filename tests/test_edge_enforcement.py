from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity.attestation_certificates import issue_certificate
from modules.identity.edge_enforcement import evaluate_runtime_enforcement


def _attestation() -> dict:
    return {
        "attestation_id": "att-1",
        "what": {
            "soul_hash": "soul-1",
            "model_fingerprint": "model-1",
            "mcp_manifest_hash": "mcp-1",
        },
        "how": {"dpop_bound": True, "mtls_bound": False},
        "why": {"scope": ["orders:read"], "delegation_chain": ["svc-a"]},
    }


def _uis(score: int = 90, tier: str = "allow") -> dict:
    return {"threat": {"risk_score": score, "risk_tier": tier}}


def _clean_key_env() -> None:
    for key in (
        "ATTESTATION_CA_SECRET",
        "ATTESTATION_CA_ALG",
        "ATTESTATION_CA_KEY_ID",
        "ATTESTATION_ACTIVE_KEY_ID",
        "ATTESTATION_KEYRING_JSON",
    ):
        os.environ.pop(key, None)


def test_edge_enforcement_allows_good_runtime():
    _clean_key_env()
    os.environ["ATTESTATION_CA_SECRET"] = "edge-secret"
    cert = issue_certificate(
        tenant_id="tenant-1",
        attestation_id="att-1",
        subject="agent-1",
        issuer="TokenDNA Trust Authority",
        claims={"integrity_digest": "abc"},
        ttl_hours=1,
        secret="edge-secret",
    )
    result = evaluate_runtime_enforcement(
        uis_event=_uis(),
        attestation=_attestation(),
        certificate=cert,
        certificate_id=cert["certificate_id"],
        request_headers={
            "x-agent-soul-hash": "soul-1",
            "x-agent-model-fingerprint": "model-1",
            "x-agent-mcp-manifest-hash": "mcp-1",
            "dpop": "proof",
            "x-agent-delegation-chain": "svc-a",
        },
        observed_scope=["orders:read"],
        required_scope=["orders:read"],
    )
    assert result["decision"]["action"] == "allow"
    assert result["authn_failure"] is False
    assert result["timing"]["slo_met"] is True
    _clean_key_env()


def test_edge_enforcement_blocks_invalid_certificate():
    _clean_key_env()
    os.environ["ATTESTATION_CA_SECRET"] = "edge-secret"
    cert = issue_certificate(
        tenant_id="tenant-1",
        attestation_id="att-1",
        subject="agent-1",
        issuer="TokenDNA Trust Authority",
        claims={"integrity_digest": "abc"},
        ttl_hours=1,
        secret="edge-secret",
    )
    cert["subject"] = "tampered"
    result = evaluate_runtime_enforcement(
        uis_event=_uis(),
        attestation=_attestation(),
        certificate=cert,
        certificate_id=cert["certificate_id"],
        request_headers={"dpop": "proof"},
        observed_scope=["orders:read"],
        required_scope=["orders:read"],
    )
    assert result["authn_failure"] is True
    assert result["certificate_status"]["status"] in {"invalid", "revoked", "expired"}
    assert result["decision"]["action"] == "block"
    _clean_key_env()


def test_edge_enforcement_can_escalate_on_slo_violation():
    os.environ["EDGE_DECISION_SLO_MS"] = "0.001"
    os.environ["EDGE_SLO_VIOLATION_ACTION"] = "step_up"
    try:
        result = evaluate_runtime_enforcement(
            uis_event=_uis(),
            attestation=_attestation(),
            certificate=None,
            certificate_id="",
            request_headers={},
            observed_scope=["orders:read"],
            required_scope=[],
        )
        assert result["timing"]["slo_met"] is False
        assert result["decision"]["action"] in {"step_up", "block"}
        assert "edge_slo_exceeded" in result["decision"]["reasons"]
    finally:
        os.environ.pop("EDGE_DECISION_SLO_MS", None)
        os.environ.pop("EDGE_SLO_VIOLATION_ACTION", None)
