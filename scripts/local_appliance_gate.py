from __future__ import annotations

"""
Production gate for a local TokenDNA appliance deployment.

Runs the production preflight and then the live Postgres smoke test from the
same container image/operators will deploy. This avoids requiring host-level
Docker tools such as psql or a published Postgres port.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.postgres_smoke import main as run_postgres_smoke
from scripts.preflight_prod import run_preflight


def main() -> None:
    report = run_preflight("production")
    print(json.dumps(report, sort_keys=True, indent=2))
    if not report.get("passed"):
        sys.exit(1)
    run_postgres_smoke()


if __name__ == "__main__":
    main()
