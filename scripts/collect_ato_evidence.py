from __future__ import annotations

import argparse
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from scripts.ato_common import DEFAULT_ATO_OUT, ROOT, evidence_entry, load_control_matrix, write_json
except ModuleNotFoundError:
    from ato_common import DEFAULT_ATO_OUT, ROOT, evidence_entry, load_control_matrix, write_json


BASE_EVIDENCE = [
    "README.md",
    ".github/workflows/ci.yml",
    ".env.production.example",
    "deploy/helm/tokendna/values.yaml",
    "docs/ato/system-security-plan.md",
    "docs/ato/customer-responsibility-matrix.md",
    "docs/ato/continuous-monitoring-plan.md",
    "docs/ato/poam-template.csv",
    "docs/operations/INCIDENT_RESPONSE.md",
    "docs/operations/MTLS.md",
    "docs/ops/backup-dr.md",
    "docs/ops/release-packaging.md",
    "scripts/preflight_prod.py",
]


def git_sha() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return ""
    return result.stdout.strip()


def build_evidence_manifest(matrix: dict[str, Any]) -> dict[str, Any]:
    evidence_paths = set(BASE_EVIDENCE)
    for control in matrix["controls"]:
        evidence_paths.update(control.get("evidence_files", []))

    entries = [evidence_entry(path) for path in sorted(evidence_paths)]
    missing = [entry["path"] for entry in entries if not entry["exists"]]
    controls = [
        {
            "id": control["id"],
            "title": control["title"],
            "owner": control["owner"],
            "implementation_status": control["implementation_status"],
            "evidence_files": control.get("evidence_files", []),
        }
        for control in matrix["controls"]
    ]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_sha": git_sha(),
        "system": matrix["system"],
        "baseline": matrix["baseline"],
        "profiles": matrix["profiles"],
        "control_count": len(controls),
        "missing_evidence_count": len(missing),
        "missing_evidence": missing,
        "controls": controls,
        "evidence": entries,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect TokenDNA DoD ATO evidence manifest")
    parser.add_argument("--output", type=Path, default=DEFAULT_ATO_OUT / "evidence-manifest.json")
    parser.add_argument("--fail-on-missing", action="store_true")
    args = parser.parse_args()

    manifest = build_evidence_manifest(load_control_matrix())
    write_json(args.output, manifest)
    print(args.output)
    if args.fail_on_missing and manifest["missing_evidence_count"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
