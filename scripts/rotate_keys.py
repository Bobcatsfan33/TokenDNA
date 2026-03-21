#!/usr/bin/env python3
"""
TokenDNA — Key Rotation CLI  (v2.8.0)
======================================
Offline key rotation utility for encrypted ClickHouse columns.
Suitable for scheduled ConMon rotation, key expiry events, and KMS key version changes.

Usage:
    python3 scripts/rotate_keys.py --table sessions --columns ip ua email
    python3 scripts/rotate_keys.py --table trap_hits --columns attacker_ip ua
    python3 scripts/rotate_keys.py --dry-run --table sessions --columns ip

Environment:
    ENC_PROVIDER     aws | azure | vault | env  (default: env)
    ENC_MASTER_KEY   64-char hex (env provider only)
    ENC_KMS_KEY_ID   ARN or alias (aws provider)
    VAULT_ADDR       Vault server URL (vault provider)
    VAULT_TOKEN      Vault token (vault provider)
    CLICKHOUSE_HOST / CLICKHOUSE_PORT / CLICKHOUSE_USER / CLICKHOUSE_PASSWORD

Options:
    --table    TABLE      ClickHouse table name (required)
    --columns  COL [COL]  Column(s) to rotate (required)
    --batch    N          Batch size (default: 500)
    --dry-run             Decrypt + re-encrypt in memory only — no DB writes
    --verbose             Print per-batch progress
    --help                Show this message
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time

# Ensure project root is on sys.path
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _root not in sys.path:
    sys.path.insert(0, _root)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("rotate_keys")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="TokenDNA key rotation — re-encrypts ClickHouse columns under new DEK",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--table",    required=True, help="ClickHouse table name")
    p.add_argument("--columns",  nargs="+", required=True, help="Columns to rotate")
    p.add_argument("--batch",    type=int, default=500, help="Batch size (default: 500)")
    p.add_argument("--dry-run",  action="store_true", help="Decrypt/re-encrypt in memory only")
    p.add_argument("--verbose",  action="store_true", help="Print per-batch progress")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("TokenDNA Key Rotation CLI v2.8.0")
    logger.info("Table    : %s", args.table)
    logger.info("Columns  : %s", ", ".join(args.columns))
    logger.info("Batch    : %d", args.batch)
    logger.info("Dry-run  : %s", args.dry_run)
    logger.info("Provider : %s", os.getenv("ENC_PROVIDER", "env"))

    # Import after sys.path is set
    try:
        from modules.security.encryption import KeyRotator, check_encryption_config, _get_provider
    except ImportError as exc:
        logger.error("Import error — is the project root on PYTHONPATH? %s", exc)
        return 1

    # Validate provider configuration
    logger.info("Validating encryption provider...")
    try:
        enc_summary = check_encryption_config()
        if not enc_summary.get("provider_ready"):
            logger.error("Encryption provider is not ready — aborting rotation")
            return 1
        provider = _get_provider()
        logger.info("Provider ready: %s", provider.provider_name())
    except Exception as exc:
        logger.error("Provider initialization failed: %s", exc)
        return 1

    if args.dry_run:
        logger.info("DRY RUN — testing decrypt/re-encrypt for 1 batch (no DB writes)")
        from modules.identity import clickhouse_client as _ch
        if not _ch.is_available():
            logger.error("ClickHouse unreachable — cannot perform dry-run")
            return 1
        try:
            col_list = ", ".join(args.columns)
            rows = _ch.query(
                f"SELECT {col_list} FROM {args.table} LIMIT {args.batch}"
            )
        except Exception as exc:
            logger.error("ClickHouse query failed: %s", exc)
            return 1

        rotator = KeyRotator()
        ok = errors = 0
        for row in rows:
            for col in args.columns:
                val = row.get(col, "")
                if not val:
                    continue
                try:
                    rotator.rotate_value(val)
                    ok += 1
                except Exception as exc:
                    logger.warning("Dry-run rotate error for column %s: %s", col, exc)
                    errors += 1
        logger.info("Dry-run result: ok=%d errors=%d (no DB writes performed)", ok, errors)
        return 0 if errors == 0 else 1

    # Live rotation
    logger.info("Starting live key rotation...")
    start_ts = time.time()
    try:
        rotator = KeyRotator()
        result  = rotator.rotate_clickhouse(
            table=args.table,
            columns=args.columns,
            batch_size=args.batch,
        )
    except Exception as exc:
        logger.error("Rotation failed: %s", exc)
        return 1

    elapsed = time.time() - start_ts
    logger.info(
        "Rotation complete: rotated=%d errors=%d batches=%d elapsed=%.1fs",
        result.get("rotated", 0),
        result.get("errors", 0),
        result.get("batches", 0),
        elapsed,
    )

    if result.get("errors", 0) > 0:
        logger.warning("Rotation completed with errors — review logs and re-run to retry failed rows")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
