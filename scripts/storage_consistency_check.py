#!/usr/bin/env python3
"""
TokenDNA storage consistency checker for sqlite/postgres migration.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
import sys

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.identity import attestation_store, decision_audit, uis_store
from modules.storage import db_backend


def _collect_counts_sqlite(tenant_id: str) -> dict[str, int]:
    # Force sqlite reads.
    prev_backend = os.getenv("TOKENDNA_DB_BACKEND")
    os.environ["TOKENDNA_DB_BACKEND"] = "sqlite"
    try:
        uis = len(uis_store.list_events(tenant_id=tenant_id, limit=100000))
        atts = len(attestation_store.list_attestations(tenant_id=tenant_id, limit=100000))
        certs = len(attestation_store.list_certificates(tenant_id=tenant_id, limit=100000))
        decisions = len(
            decision_audit.list_decisions_paginated(tenant_id=tenant_id, page_size=100000).get("items", [])
        )
    finally:
        if prev_backend is None:
            os.environ.pop("TOKENDNA_DB_BACKEND", None)
        else:
            os.environ["TOKENDNA_DB_BACKEND"] = prev_backend
    return {"uis_events": uis, "attestations": atts, "certificates": certs, "decision_audits": decisions}


def _collect_counts_postgres(tenant_id: str) -> dict[str, int]:
    if not db_backend.get_backend_config().postgres_dsn:
        return {"uis_events": -1, "attestations": -1, "certificates": -1, "decision_audits": -1}
    prev_backend = os.getenv("TOKENDNA_DB_BACKEND")
    os.environ["TOKENDNA_DB_BACKEND"] = "postgres"
    try:
        uis = len(uis_store.list_events(tenant_id=tenant_id, limit=100000))
        atts = len(attestation_store.list_attestations(tenant_id=tenant_id, limit=100000))
        certs = len(attestation_store.list_certificates(tenant_id=tenant_id, limit=100000))
        decisions = len(
            decision_audit.list_decisions_paginated(tenant_id=tenant_id, page_size=100000).get("items", [])
        )
    except Exception:
        return {"uis_events": -1, "attestations": -1, "certificates": -1, "decision_audits": -1}
    finally:
        if prev_backend is None:
            os.environ.pop("TOKENDNA_DB_BACKEND", None)
        else:
            os.environ["TOKENDNA_DB_BACKEND"] = prev_backend
    return {"uis_events": uis, "attestations": atts, "certificates": certs, "decision_audits": decisions}


def run(tenant_id: str) -> dict[str, Any]:
    uis_store.init_db()
    attestation_store.init_db()
    decision_audit.init_db()

    sqlite_counts = _collect_counts_sqlite(tenant_id)
    postgres_counts = _collect_counts_postgres(tenant_id)
    diffs: dict[str, int] = {}
    for key, sqlite_val in sqlite_counts.items():
        pg_val = postgres_counts.get(key, -1)
        if pg_val >= 0:
            diffs[key] = sqlite_val - pg_val
        else:
            diffs[key] = sqlite_val
    ok = True
    for key, sqlite_val in sqlite_counts.items():
        pg_val = postgres_counts.get(key, -1)
        if pg_val >= 0 and sqlite_val != pg_val:
            ok = False

    return {
        "ok": ok,
        "tenant_id": tenant_id,
        "sqlite": sqlite_counts,
        "postgres": postgres_counts,
        "diffs": diffs,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="TokenDNA sqlite/postgres consistency checker")
    parser.add_argument("--tenant-id", default="dev-tenant")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when mismatches are found")
    args = parser.parse_args()

    report = run(args.tenant_id)
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.strict and not report["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

