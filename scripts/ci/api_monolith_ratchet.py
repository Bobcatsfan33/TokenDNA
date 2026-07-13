#!/usr/bin/env python3
"""CI ratchet: api.py may only shrink (T-1).

The budget file is committed. Any PR that grows api.py fails; any PR that
shrinks it must also lower the budget (the script prints the new number) so the
gain is locked in. Add as a CI step immediately after checkout:

    - name: Monolith ratchet
      run: python scripts/ci/api_monolith_ratchet.py

New endpoints are born in api_routers/<domain>.py, never in api.py.
"""
import pathlib
import sys

BUDGET_FILE = pathlib.Path("scripts/ci/api_line_budget.txt")
TARGET = pathlib.Path("api.py")


def main() -> int:
    budget = int(BUDGET_FILE.read_text().strip())
    actual = len(TARGET.read_text(encoding="utf-8").splitlines())

    if actual > budget:
        print(
            f"::error file=api.py::api.py grew to {actual} lines (budget {budget}). "
            f"New endpoints belong in api_routers/<domain>.py — see api_routers/__init__.py."
        )
        return 1

    if actual < budget:
        print(
            f"::error file=scripts/ci/api_line_budget.txt::api.py shrank to {actual} "
            f"(budget {budget}). Lower the committed budget to {actual} in this PR to "
            f"lock in the gain."
        )
        return 1

    print(f"monolith ratchet OK: api.py at {actual}/{budget} lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
