#!/usr/bin/env python3
"""Fail when a workflow executes a third-party action by a mutable ref."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
FULL_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def find_unpinned(workflow_dir: Path = WORKFLOWS) -> list[str]:
    failures: list[str] = []
    for path in sorted(workflow_dir.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        for match in USES.finditer(text):
            target = match.group(1)
            if target.startswith("./"):
                continue
            action, separator, ref = target.rpartition("@")
            if not separator or not action or not FULL_COMMIT.fullmatch(ref):
                line = text.count("\n", 0, match.start()) + 1
                base = ROOT if path.is_relative_to(ROOT) else workflow_dir
                failures.append(f"{path.relative_to(base)}:{line}: {target}")
    return failures


def main() -> int:
    failures = find_unpinned()
    if failures:
        for failure in failures:
            print(f"::error::{failure} must use a full immutable commit SHA")
        return 1
    print("workflow action pin guard OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
