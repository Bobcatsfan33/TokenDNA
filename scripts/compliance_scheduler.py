from __future__ import annotations

"""
Compliance evidence automation helper.

Generates evidence packages + signed snapshots for configured frameworks on a
schedule (intended for cron/CI invocation).
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.identity import attestation_store
from modules.identity import compliance
from modules.identity import network_intel
from modules.identity import uis_store


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _collect_inputs(tenant_id: str) -> dict[str, Any]:
    uis_events = uis_store.list_events(tenant_id=tenant_id, limit=1000)
    attestations = attestation_store.list_attestations(tenant_id=tenant_id, limit=1000)
    certificates = attestation_store.list_certificates(tenant_id=tenant_id, limit=1000)
    drift_events = attestation_store.list_drift_events(tenant_id=tenant_id, limit=1000)
    threat_signals = network_intel.get_feed(limit=1000, min_tenant_count=1, min_confidence=0.0)
    return {
        "uis_event_count": len(uis_events),
        "attestation_count": len(attestations),
        "certificate_count": len(certificates),
        "revoked_certificate_count": len([c for c in certificates if c.get("status") == "revoked"]),
        "drift_event_count": len(drift_events),
        "threat_signal_count": len(threat_signals),
    }


def run(tenant_id: str, frameworks: list[str], export_format: str, algorithm: str, key_id: str | None = None) -> dict[str, Any]:
    uis_store.init_db()
    attestation_store.init_db()
    compliance.init_db()
    network_intel.init_db()

    frames = [f.strip().lower() for f in frameworks if f.strip()]
    if not frames:
        frames = sorted(compliance.CONTROL_MAPS.keys())

    inputs = _collect_inputs(tenant_id)
    generated: list[dict[str, Any]] = []
    for framework in frames:
        if framework not in compliance.CONTROL_MAPS:
            generated.append({"framework": framework, "error": "unsupported_framework"})
            continue
        package = compliance.generate_evidence_package(
            tenant_id=tenant_id,
            framework=framework,
            inputs=inputs,
        )
        compliance.store_evidence_package(package)
        snapshot = compliance.create_signed_snapshot(
            package=package,
            export_format=export_format,
            key_id=key_id,
            algorithm=algorithm,
        )
        compliance.store_signed_snapshot(snapshot)
        verification = compliance.verify_signed_snapshot(snapshot)
        generated.append(
            {
                "framework": framework,
                "package_id": package["package_id"],
                "snapshot_id": snapshot["snapshot_id"],
                "verification": verification,
            }
        )

    return {
        "tenant_id": tenant_id,
        "generated_at": _iso_now(),
        "export_format": export_format,
        "algorithm": algorithm,
        "key_id": key_id,
        "frameworks": frames,
        "results": generated,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="TokenDNA compliance scheduler automation")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--framework", action="append", default=[])
    parser.add_argument("--export-format", choices=["oscal", "emass"], default="oscal")
    parser.add_argument("--algorithm", default=os.getenv("ATTESTATION_CA_ALG", "HS256"))
    parser.add_argument("--key-id", default=(os.getenv("ATTESTATION_ACTIVE_KEY_ID", "").strip() or None))
    args = parser.parse_args()
    report = run(
        tenant_id=args.tenant_id,
        frameworks=args.framework,
        export_format=args.export_format,
        algorithm=str(args.algorithm).upper(),
        key_id=args.key_id,
    )
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
