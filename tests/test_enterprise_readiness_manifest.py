from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.ci.verify_enterprise_readiness import ReadinessError, verify_manifest


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs" / "enterprise-readiness.json"


def test_readiness_register_is_honest_and_internally_consistent() -> None:
    result = verify_manifest(MANIFEST)

    assert result["decision"] == "not-approved"
    assert result["gate_count"] == 9
    assert len(result["open_gates"]) == 6


def test_production_promotion_fails_while_external_gates_are_open() -> None:
    with pytest.raises(ReadinessError, match="production deployment is not approved"):
        verify_manifest(MANIFEST, require_approved=True)


def test_approval_cannot_be_self_declared_with_open_gates(tmp_path: Path) -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    manifest["deploymentDecision"] = "approved"
    manifest["approval"] = {
        "approvedBy": "self",
        "approvedAt": "2026-08-10T14:00:00Z",
        "changeRecord": "none",
    }
    path = tmp_path / "readiness.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ReadinessError, match="cannot be approved with open gates"):
        verify_manifest(path)
