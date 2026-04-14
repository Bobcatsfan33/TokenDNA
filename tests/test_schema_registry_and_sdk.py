from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity import schema_registry
from modules.integrations import sdk_wrappers


def test_schema_registry_builds_json_artifacts():
    bundle = schema_registry.build_schema_bundle()
    assert bundle["version"] == schema_registry.SCHEMA_ARTIFACT_VERSION
    assert "uis" in bundle["artifacts"]
    assert "attestation" in bundle["artifacts"]

    uis = schema_registry.get_schema_artifact("uis")
    assert uis is not None
    assert uis["$id"].endswith("/uis.schema.json")

    attest = schema_registry.get_schema_artifact("attestation")
    assert attest is not None
    assert attest["$id"].endswith("/attestation.schema.json")


def test_sdk_wrappers_normalize_and_attestation_requests():
    normalize_req = sdk_wrappers.build_adapter_normalize_request(
        protocol="oidc",
        payload={"sub": "user-1", "iss": "issuer", "aud": "tokendna", "jti": "j1"},
        request_context={"ip": "1.2.3.4"},
        risk_context={"risk_tier": "allow"},
    )
    assert normalize_req["protocol"] == "oidc"
    assert normalize_req["payload"]["sub"] == "user-1"
    assert normalize_req["request_context"]["ip"] == "1.2.3.4"
    assert normalize_req["risk_context"]["risk_tier"] == "allow"

    attestation_req = sdk_wrappers.build_attestation_request(
        agent_id="agent-1",
        owner_org="Acme",
        created_by="builder",
        soul_hash="s1",
        directive_hashes=["d1"],
        model_fingerprint="m1",
        mcp_manifest_hash="mcp1",
    )
    assert attestation_req["agent_id"] == "agent-1"
    assert attestation_req["owner_org"] == "Acme"
    assert attestation_req["directive_hashes"] == ["d1"]
