from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

try:
    from scripts.ato_common import DEFAULT_ATO_OUT, evidence_entry, write_json
except ModuleNotFoundError:
    from ato_common import DEFAULT_ATO_OUT, evidence_entry, write_json


STIG_MAPPINGS = [
    {
        "stig": "Application Security and Development STIG",
        "status": "product",
        "evidence": [
            ".github/workflows/ci.yml",
            "requirements.txt",
            "scripts/preflight_prod.py",
            "docs/operations/INCIDENT_RESPONSE.md",
        ],
    },
    {
        "stig": "Kubernetes STIG",
        "status": "shared",
        "evidence": [
            "deploy/helm/tokendna/values.yaml",
            "deploy/k8s/deployment.yaml",
            "docs/ops/kubernetes-deployment.md",
        ],
    },
    {
        "stig": "PostgreSQL STIG",
        "status": "customer-inherited",
        "evidence": [
            "docs/ops/postgres-migration.md",
            "docs/ops/backup-dr.md",
            "scripts/preflight_prod.py",
        ],
    },
    {
        "stig": "Redis Enterprise STIG",
        "status": "customer-inherited",
        "evidence": [
            "docs/operations/MTLS.md",
            "modules/identity/cache_redis.py",
            "scripts/preflight_prod.py",
        ],
    },
    {
        "stig": "Linux / Container Host STIG",
        "status": "customer-inherited",
        "evidence": [
            "docs/operations/DOCKER.md",
            "deploy/helm/tokendna/values.yaml",
        ],
    },
]


def build_stig_evidence() -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "description": "TokenDNA STIG applicability and evidence starter mapping for DoD deployments.",
        "mappings": [
            {
                **item,
                "evidence_entries": [evidence_entry(path) for path in item["evidence"]],
            }
            for item in STIG_MAPPINGS
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate TokenDNA STIG evidence mapping")
    parser.add_argument("--output", type=Path, default=DEFAULT_ATO_OUT / "stig-evidence.json")
    args = parser.parse_args()

    payload = build_stig_evidence()
    write_json(args.output, payload)
    print(args.output)


if __name__ == "__main__":
    main()
