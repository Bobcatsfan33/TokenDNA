from __future__ import annotations

"""
Build a local TokenDNA release manifest.

The manifest is the operator-facing inventory for an appliance release: image
tags, Python packages, runbooks, gates, and provenance inputs. It is designed
to be archived beside signed images and wheels without requiring TokenDNA to be
hosted as a SaaS service.
"""

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "dist" / "release-bundle" / "tokendna-release-manifest.json"


def _read_version() -> str:
    init_file = ROOT / "tokendna_sdk" / "__init__.py"
    text = init_file.read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("__version__"):
            return line.split("=", 1)[1].strip().strip('"')
    return "0.0.0"


def _git_sha() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_entry(path: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": _sha256(path),
    }


def build_manifest(image_tag: str, output: Path) -> dict[str, Any]:
    required_docs = [
        ROOT / "docs" / "operations" / "LOCAL_APPLIANCE_RUNBOOK.md",
        ROOT / "docs" / "ops" / "release-packaging.md",
        ROOT / "docs" / "ops" / "local-control-plane.md",
        ROOT / "docs" / "ops" / "backup-dr.md",
        ROOT / "docs" / "ato" / "system-security-plan.md",
        ROOT / "docs" / "ato" / "customer-responsibility-matrix.md",
        ROOT / "docs" / "ato" / "continuous-monitoring-plan.md",
    ]
    missing = [path.relative_to(ROOT).as_posix() for path in required_docs if not path.exists()]
    if missing:
        raise RuntimeError("missing release docs: " + ", ".join(missing))

    manifest = {
        "product": "TokenDNA AI Agent Identity Control Plane",
        "version": _read_version(),
        "git_sha": _git_sha(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "deployment_model": "customer-local appliance",
        "components": {
            "control_plane_image": {
                "tag": image_tag,
                "compose_files": ["docker-compose.yml", "docker-compose.production.yml"],
            },
            "python_packages": [
                {"name": "tokendna-sdk", "path": "tokendna_sdk"},
                {"name": "tokendna-collector", "path": "collector"},
                {"name": "tokendna-platform", "path": "platform"},
            ],
            "operator_console": {"path": "dashboard/index.html"},
        },
        "required_gates": [
            "python scripts/preflight_prod.py --environment production",
            "python scripts/generate_oscal.py",
            "python scripts/stig_evidence.py",
            "python scripts/collect_ato_evidence.py --fail-on-missing",
            "python scripts/migrate_storage.py",
            "python scripts/postgres_smoke.py",
            "docker compose -f docker-compose.yml -f docker-compose.production.yml run --rm tokendna-deployment-gate",
        ],
        "runbooks": [_file_entry(path) for path in required_docs],
        "provenance": {
            "sbom": _file_entry(ROOT / "sbom.json") if (ROOT / "sbom.json").exists() else None,
            "source_manifest": "this file",
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Build TokenDNA release manifest")
    parser.add_argument("--image-tag", default="tokendna/control-plane:local", help="Control-plane image tag")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUT, help="Manifest output path")
    args = parser.parse_args()

    manifest = build_manifest(args.image_tag, args.output)
    print(json.dumps({"ok": True, "output": str(args.output), "version": manifest["version"]}, sort_keys=True))


if __name__ == "__main__":
    main()
