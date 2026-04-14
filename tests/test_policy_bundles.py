from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity import policy_bundles
from modules.identity.attestation_certificates import issue_certificate


def _setup_tmp_db():
    tmpdir = tempfile.TemporaryDirectory()
    db_path = Path(tmpdir.name) / "tokendna-policy-test.db"
    os.environ["DATA_DB_PATH"] = str(db_path)
    os.environ["ATTESTATION_CA_SECRET"] = "policy-secret"
    os.environ.pop("ATTESTATION_ACTIVE_KEY_ID", None)
    os.environ.pop("ATTESTATION_KEYRING_JSON", None)
    return tmpdir


def _scenario() -> dict:
    cert = issue_certificate(
        tenant_id="tenant-1",
        attestation_id="att-1",
        subject="agent-1",
        issuer="TokenDNA Trust Authority",
        claims={"integrity_digest": "abc"},
        ttl_hours=1,
        secret="policy-secret",
    )
    return {
        "scenario_id": "s1",
        "uis_event": {"threat": {"risk_score": 90, "risk_tier": "allow"}},
        "attestation": {
            "attestation_id": "att-1",
            "what": {
                "soul_hash": "soul-1",
                "model_fingerprint": "model-1",
                "mcp_manifest_hash": "mcp-1",
            },
            "how": {"dpop_bound": True, "mtls_bound": False},
            "why": {"scope": ["orders:read"], "delegation_chain": ["svc-a"]},
        },
        "certificate": cert,
        "certificate_id": cert["certificate_id"],
        "request_headers": {
            "x-agent-soul-hash": "soul-1",
            "x-agent-model-fingerprint": "model-1",
            "x-agent-mcp-manifest-hash": "mcp-1",
            "dpop": "proof",
            "x-agent-delegation-chain": "svc-a",
        },
        "observed_scope": ["orders:read"],
    }


def test_policy_bundle_lifecycle_and_activation():
    tmp = _setup_tmp_db()
    try:
        policy_bundles.init_db()
        bundle = policy_bundles.create_bundle(
            tenant_id="tenant-1",
            name="edge-default",
            version="2026.04.14",
            description="baseline",
            config={"required_scope": ["orders:read"], "expected_action": "allow"},
        )
        assert bundle["status"] == "draft"

        activated = policy_bundles.activate_bundle("tenant-1", bundle["bundle_id"])
        assert activated is not None
        assert activated["status"] == "active"
        assert activated["activated_at"] is not None

        listed = policy_bundles.list_bundles("tenant-1", name="edge-default", limit=10)
        assert len(listed) == 1
        assert listed[0]["bundle_id"] == bundle["bundle_id"]
    finally:
        os.environ.pop("ATTESTATION_CA_SECRET", None)
        tmp.cleanup()


def test_policy_bundle_simulation_matches_expected_action():
    tmp = _setup_tmp_db()
    try:
        policy_bundles.init_db()
        bundle = policy_bundles.create_bundle(
            tenant_id="tenant-1",
            name="edge-default",
            version="2026.04.14",
            description="baseline",
            config={"required_scope": ["orders:read"], "expected_action": "allow"},
        )
        policy_bundles.activate_bundle("tenant-1", bundle["bundle_id"])

        simulation = {
            "scenarios": [
                _scenario(),
            ]
        }
        result = policy_bundles.simulate_bundle(simulation=simulation, bundle_config=bundle["config"])
        assert result["scenario_count"] == 1
        assert result["results"][0]["decision"]["action"] == "allow"
        assert result["results"][0]["matches_expected_action"] is True
    finally:
        os.environ.pop("ATTESTATION_CA_SECRET", None)
        tmp.cleanup()
