#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = ROOT / "modules" / "identity" / "uis_spec.lock.json"
LOCAL_SCHEMA = ROOT / "modules" / "identity" / "uis_schema_v1.json"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify(*, verify_upstream: bool = False) -> dict[str, str]:
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    local_bytes = LOCAL_SCHEMA.read_bytes()
    local_schema = json.loads(local_bytes)
    expected_hash = lock["schema_sha256"]
    if _sha256(local_bytes) != expected_hash:
        raise RuntimeError("TokenDNA UIS schema differs from the locked uis-spec artifact")
    if local_schema.get("$id") != lock["schema_id"]:
        raise RuntimeError("UIS schema $id differs from uis-spec.lock.json")
    if local_schema.get("version") != lock["schema_version"]:
        raise RuntimeError("UIS schema version differs from uis-spec.lock.json")

    if verify_upstream:
        revision = lock["revision"]
        schema_path = lock["schema_path"]
        url = f"https://raw.githubusercontent.com/Bobcatsfan33/uis-spec/{revision}/{schema_path}"
        with urllib.request.urlopen(url, timeout=20) as response:  # noqa: S310 - fixed HTTPS host
            upstream_bytes = response.read()
        if upstream_bytes != local_bytes:
            raise RuntimeError("locked upstream UIS artifact differs byte-for-byte from TokenDNA")

    return {
        "revision": lock["revision"],
        "schema_sha256": expected_hash,
        "schema_version": lock["schema_version"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify TokenDNA's pinned UIS specification contract")
    parser.add_argument("--verify-upstream", action="store_true")
    args = parser.parse_args()
    try:
        result = verify(verify_upstream=args.verify_upstream)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f"UIS specification verification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
