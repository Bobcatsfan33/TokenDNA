#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "docs" / "enterprise-readiness.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class ReadinessError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _assert_assessed_commit_is_ancestor(commit: str, root: Path, reference: str = "HEAD") -> None:
    if not GIT_SHA_RE.fullmatch(commit):
        raise ReadinessError("assessedCommit must be a full lowercase Git SHA")
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, reference],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ReadinessError(f"assessedCommit must be an ancestor of {reference}")


def verify_manifest(manifest_path: Path, root: Path = ROOT, require_approved: bool = False) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schemaVersion") != 1:
        raise ReadinessError("unsupported schemaVersion")
    if manifest.get("productVersion") != (root / "VERSION").read_text(encoding="utf-8").strip():
        raise ReadinessError("productVersion does not match VERSION")
    assessed_commit = manifest.get("assessedCommit", "")
    _assert_assessed_commit_is_ancestor(assessed_commit, root)
    github_base_ref = os.environ.get("GITHUB_BASE_REF", "").strip()
    if github_base_ref:
        # PRs are squash-merged in this repository. A feature-branch HEAD is not an ancestor
        # of the resulting default-branch commit, even when both trees are byte-identical.
        # Requiring the assessment pin to come from the PR base preserves the evidence chain
        # before and after squash merge.
        _assert_assessed_commit_is_ancestor(assessed_commit, root, f"origin/{github_base_ref}")

    gates = manifest.get("gates")
    if not isinstance(gates, list) or not gates:
        raise ReadinessError("gates must be a non-empty list")
    ids: set[str] = set()
    blockers: list[str] = []
    for gate in gates:
        gate_id = gate.get("id")
        if not isinstance(gate_id, str) or not gate_id or gate_id in ids:
            raise ReadinessError(f"invalid or duplicate gate id: {gate_id!r}")
        ids.add(gate_id)
        if gate.get("kind") not in {"repository", "external"}:
            raise ReadinessError(f"{gate_id}: invalid kind")
        if gate.get("status") not in {"open", "closed"}:
            raise ReadinessError(f"{gate_id}: invalid status")
        if gate.get("required") is not True:
            raise ReadinessError(f"{gate_id}: every registered gate must be required")
        if not gate.get("owner") or not gate.get("acceptance"):
            raise ReadinessError(f"{gate_id}: owner and acceptance are required")
        evidence = gate.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            raise ReadinessError(f"{gate_id}: evidence is required")
        for item in evidence:
            relative = item.get("path", "")
            expected = item.get("sha256", "")
            if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise ReadinessError(f"{gate_id}: invalid evidence path {relative!r}")
            if not SHA256_RE.fullmatch(expected):
                raise ReadinessError(f"{gate_id}: invalid evidence hash for {relative}")
            path = root / relative
            if not path.is_file():
                raise ReadinessError(f"{gate_id}: missing evidence {relative}")
            if _sha256(path) != expected:
                raise ReadinessError(f"{gate_id}: evidence hash mismatch for {relative}")
        if gate["status"] == "open":
            blockers.append(gate_id)

    decision = manifest.get("deploymentDecision")
    approval = manifest.get("approval")
    if decision not in {"approved", "not-approved"}:
        raise ReadinessError("deploymentDecision must be approved or not-approved")
    if decision == "approved":
        if blockers:
            raise ReadinessError("deploymentDecision cannot be approved with open gates")
        required_fields = {"approvedBy", "approvedAt", "changeRecord"}
        if not isinstance(approval, dict) or not required_fields <= approval.keys():
            raise ReadinessError("approved decision requires complete approval metadata")
    elif approval is not None:
        raise ReadinessError("not-approved decision must not contain approval metadata")

    if require_approved and decision != "approved":
        raise ReadinessError("production deployment is not approved; open gates: " + ", ".join(blockers))
    return {"decision": decision, "open_gates": blockers, "gate_count": len(gates)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify TokenDNA enterprise readiness evidence")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--require-approved", action="store_true")
    args = parser.parse_args()
    try:
        result = verify_manifest(args.manifest, require_approved=args.require_approved)
    except (OSError, ValueError, ReadinessError) as exc:
        print(f"enterprise readiness verification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
