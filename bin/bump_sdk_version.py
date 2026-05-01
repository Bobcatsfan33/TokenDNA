#!/usr/bin/env python3
"""
Bump the SDK version across pyproject.toml + tokendna_sdk/__init__.py.

The CI guard in .github/workflows/release-pypi.yml refuses to publish
unless these two and the pushed git tag all agree, so this is the canonical
place to change the version string.

Usage:
    bin/bump_sdk_version.py 0.2.0
    bin/bump_sdk_version.py 0.2.0 --tag      # also creates a v0.2.0 git tag
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PYPROJECT = REPO / "pyproject.toml"
INIT = REPO / "tokendna_sdk" / "__init__.py"


def _replace(path: Path, pattern: str, replacement: str) -> bool:
    text = path.read_text()
    new_text, n = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if n == 0:
        print(f"::error::no version line matched in {path}", file=sys.stderr)
        return False
    path.write_text(new_text)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="New semver version, e.g. 0.2.0")
    parser.add_argument("--tag", action="store_true",
                        help="Also create a v<version> git tag")
    args = parser.parse_args()

    if not re.match(r"^\d+\.\d+\.\d+(?:[-.][\w.]+)?$", args.version):
        print(f"refusing to bump to non-semver version: {args.version}", file=sys.stderr)
        return 2

    ok = True
    ok &= _replace(PYPROJECT, r'^version\s*=\s*"[^"]+"', f'version = "{args.version}"')
    ok &= _replace(INIT,      r'^__version__\s*=\s*"[^"]+"', f'__version__ = "{args.version}"')
    if not ok:
        return 1

    print(f"bumped to {args.version}")
    print(f"  {PYPROJECT.relative_to(REPO)}")
    print(f"  {INIT.relative_to(REPO)}")

    if args.tag:
        subprocess.run(["git", "add", str(PYPROJECT), str(INIT)], check=True, cwd=REPO)
        subprocess.run(["git", "commit", "-m", f"chore(sdk): bump tokendna-sdk to {args.version}"],
                       check=True, cwd=REPO)
        subprocess.run(["git", "tag", "-a", f"v{args.version}",
                        "-m", f"tokendna-sdk v{args.version}"], check=True, cwd=REPO)
        print(f"  tagged v{args.version} — push with: git push && git push --tags")
    return 0


if __name__ == "__main__":
    sys.exit(main())
