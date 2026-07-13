from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.storage.migrations import apply_migrations, migration_status


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply or inspect TokenDNA storage migrations")
    parser.add_argument("--status", action="store_true", help="Only print migration status")
    args = parser.parse_args()

    report = migration_status() if args.status else apply_migrations()
    print(json.dumps(report, sort_keys=True, indent=2))
    if report.get("pending"):
        sys.exit(1)


if __name__ == "__main__":
    main()
