#!/usr/bin/env python3
"""Smoke test: the SDK README's decorator example must actually run.

Extracts the first ```python fenced block containing the ``@identified``
decorator from ``tokendna_sdk/README.md`` and executes it, so README drift
(a renamed export, a broken signature) fails CI instead of shipping.

Usage: python scripts/ci/smoke_sdk_readme.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
README = REPO / "tokendna_sdk" / "README.md"


def main() -> int:
    text = README.read_text(encoding="utf-8")
    blocks = re.findall(r"```python\n(.*?)```", text, re.S)
    example = next((b for b in blocks if "@identified" in b), None)
    if example is None:
        print("::error::no @identified decorator example found in "
              "tokendna_sdk/README.md", file=sys.stderr)
        return 1
    ns: dict = {}
    exec(compile(example, "<sdk-readme-decorator-example>", "exec"), ns)  # noqa: S102
    print("SDK README decorator example executed OK "
          f"({len(example.splitlines())} lines).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
