"""
TokenDNA -- UIS/attestation schema artifact publishing helpers.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from modules.identity.uis_protocol import get_uis_spec

SCHEMA_ARTIFACT_VERSION = "1.0.0"


def _artifact_dir() -> Path:
    root = os.getenv("SCHEMA_ARTIFACTS_DIR", "/tmp/tokendna-schema-artifacts")
    path = Path(root)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _attestation_spec() -> dict[str, Any]:
    return {
        "version": "1.0",
        "record_dimensions": {
            "who": ["agent_id", "created_by", "owner_org"],
            "what": ["soul_hash", "directive_hashes", "model_fingerprint", "mcp_manifest_hash"],
            "how": ["auth_method", "dpop_bound", "mtls_bound", "behavior_confidence"],
            "why": ["declared_purpose", "scope", "delegation_chain", "policy_trace_id"],
        },
        "certificate_fields": [
            "certificate_id",
            "tenant_id",
            "attestation_id",
            "issuer",
            "subject",
            "issued_at",
            "expires_at",
            "signature_alg",
            "ca_key_id",
            "status",
            "revoked_at",
            "revocation_reason",
            "claims",
            "signature",
        ],
    }


def build_uis_schema_artifact() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://schemas.tokendna.dev/uis.schema.json",
        "title": "TokenDNA UIS Event",
        "type": "object",
        "version": SCHEMA_ARTIFACT_VERSION,
        "spec": get_uis_spec(),
    }


def build_attestation_schema_artifact() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://schemas.tokendna.dev/attestation.schema.json",
        "title": "TokenDNA Agent Attestation",
        "type": "object",
        "version": SCHEMA_ARTIFACT_VERSION,
        "spec": _attestation_spec(),
    }


def build_schema_artifacts() -> dict[str, dict[str, Any]]:
    return {
        "uis": build_uis_schema_artifact(),
        "attestation": build_attestation_schema_artifact(),
    }


def get_schema_artifact(name: str) -> dict[str, Any] | None:
    artifacts = build_schema_artifacts()
    return artifacts.get((name or "").strip().lower())


def build_schema_bundle() -> dict[str, Any]:
    return {
        "version": SCHEMA_ARTIFACT_VERSION,
        "artifacts": build_schema_artifacts(),
    }


def publish_identity_schema_artifacts(
    *,
    include_uis: bool = True,
    include_attestation: bool = True,
) -> dict[str, Any]:
    artifact_dir = _artifact_dir()
    published: list[dict[str, Any]] = []
    bundle = build_schema_bundle()

    if include_uis:
        uis_path = artifact_dir / "uis.schema.json"
        uis_path.write_text(json.dumps(bundle["artifacts"]["uis"], sort_keys=True, indent=2), encoding="utf-8")
        published.append({"name": "uis", "path": str(uis_path), "bytes": uis_path.stat().st_size})

    if include_attestation:
        att_path = artifact_dir / "attestation.schema.json"
        att_path.write_text(
            json.dumps(bundle["artifacts"]["attestation"], sort_keys=True, indent=2),
            encoding="utf-8",
        )
        published.append({"name": "attestation", "path": str(att_path), "bytes": att_path.stat().st_size})

    manifest_path = artifact_dir / "schema-bundle.manifest.json"
    manifest_path.write_text(json.dumps(bundle, sort_keys=True, indent=2), encoding="utf-8")

    return {
        "artifact_dir": str(artifact_dir),
        "published": published,
        "manifest": str(manifest_path),
        "bundle_version": SCHEMA_ARTIFACT_VERSION,
    }

