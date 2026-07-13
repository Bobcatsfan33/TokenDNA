#!/usr/bin/env python3
"""
TokenDNA CA key rotation drill automation.

Exercises issuer behavior across two CA keys and verifies that certificates
issued before/after rotation validate with their embedded key ids.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from unittest import mock
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def run_rotation_drill(secret_old: str, secret_new: str) -> dict:
    from modules.identity import attestation_store
    from modules.identity.attestation_certificates import (
        issue_certificate_with_key,
        verify_certificate,
    )

    tmpdir = tempfile.TemporaryDirectory()
    db_path = Path(tmpdir.name) / "rotation-drill.db"
    os.environ["DATA_DB_PATH"] = str(db_path)

    keyring = [
        {"key_id": "ca-2026q2", "algorithm": "HS256", "backend": "software"},
        {"key_id": "ca-2026q3", "algorithm": "HS256", "backend": "software"},
    ]
    os.environ["ATTESTATION_KEYRING_JSON"] = json.dumps(keyring)

    attestation_store.init_db()
    attestation_store.upsert_ca_key(
        key_id="ca-2026q2",
        algorithm="HS256",
        backend="software",
        status="active",
        activated_at="2026-04-01T00:00:00+00:00",
        metadata={"drill": True},
    )
    attestation_store.upsert_ca_key(
        key_id="ca-2026q3",
        algorithm="HS256",
        backend="software",
        status="standby",
        metadata={"drill": True},
    )

    # Issue with old key.
    with mock.patch("modules.identity.trust_authority._load_keyring", return_value={}):
        os.environ["ATTESTATION_CA_SECRET"] = secret_old
        cert_old = issue_certificate_with_key(
            tenant_id="drill-tenant",
            attestation_id="att-old",
            subject="agent-old",
            issuer="TokenDNA Drill CA",
            claims={"phase": "before_rotation"},
            key_id="ca-2026q2",
            algorithm="HS256",
            ttl_hours=1,
        )
    attestation_store.insert_certificate("drill-tenant", cert_old)
    old_valid = verify_certificate(cert_old)

    # Rotate and issue with new key.
    attestation_store.upsert_ca_key(
        key_id="ca-2026q2",
        algorithm="HS256",
        backend="software",
        status="retired",
        deactivated_at="2026-07-01T00:00:00+00:00",
        metadata={"drill": True},
    )
    attestation_store.upsert_ca_key(
        key_id="ca-2026q3",
        algorithm="HS256",
        backend="software",
        status="active",
        activated_at="2026-07-01T00:00:00+00:00",
        metadata={"drill": True},
    )
    with mock.patch("modules.identity.trust_authority._load_keyring", return_value={}):
        os.environ["ATTESTATION_CA_SECRET"] = secret_new
        cert_new = issue_certificate_with_key(
            tenant_id="drill-tenant",
            attestation_id="att-new",
            subject="agent-new",
            issuer="TokenDNA Drill CA",
            claims={"phase": "after_rotation"},
            key_id="ca-2026q3",
            algorithm="HS256",
            ttl_hours=1,
        )
    attestation_store.insert_certificate("drill-tenant", cert_new)
    new_valid = verify_certificate(cert_new)

    keys = attestation_store.list_ca_keys(limit=10)
    tmpdir.cleanup()
    return {
        "ok": bool(old_valid.get("valid") and new_valid.get("valid")),
        "old_cert_valid": old_valid,
        "new_cert_valid": new_valid,
        "keys": keys,
        "issued_key_ids": [cert_old["ca_key_id"], cert_new["ca_key_id"]],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run TokenDNA key rotation drill")
    parser.add_argument("--secret-old", default="rotation-old-secret")
    parser.add_argument("--secret-new", default="rotation-new-secret")
    args = parser.parse_args()
    result = run_rotation_drill(secret_old=args.secret_old, secret_new=args.secret_new)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
