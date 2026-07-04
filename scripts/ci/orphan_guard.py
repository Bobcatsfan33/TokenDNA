#!/usr/bin/env python3
"""Orphan-module CI guard (SIMPLIFICATION_PLAN P0.5).

Builds a static import graph rooted at the live entrypoints and fails if any
module under ``modules/`` has zero inbound edges (i.e. nothing reachable from a
root imports it). This is the enforcement mechanism for the simplification
mission's "zero orphaned modules" invariant.

Roots (operational tooling counts, so scripts keep their imports alive):
    api.py, serve.py, auth.py, config.py,
    api_routers/**.py, tokendna_sdk/**.py, scripts/**.py

Because a fully-static resolver cannot see dynamic imports (importlib, string
module paths), two escape hatches keep it honest:
  * Any dotted module path that appears as a *string literal* anywhere under the
    roots is treated as reachable (covers importlib/__import__/config-driven loads).
  * ``ALLOWLIST`` holds modules that are knowingly-orphaned-but-kept. Phase 0
    seeds it with the current orphan set so CI is green; Phase 1 empties it as
    each module is actually cut. Adding a NEW orphan not in the allowlist fails CI.

Usage:
    python scripts/ci/orphan_guard.py            # CI mode: exit 1 on un-allowlisted orphans
    python scripts/ci/orphan_guard.py --report   # list all orphans, exit 0 (for seeding)
    python scripts/ci/orphan_guard.py --json      # machine-readable
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# First-party top-level import prefixes we resolve (everything else is stdlib/3rd-party).
FIRST_PARTY = {"modules", "api_routers", "tokendna_sdk", "onboarding", "scripts",
               "config", "auth", "api", "serve"}

# Directories whose every .py file is a graph ROOT.
ROOT_DIRS = ["api_routers", "tokendna_sdk", "scripts"]
ROOT_FILES = ["api.py", "serve.py", "auth.py", "config.py"]

# ── Known orphans that are KEPT (not cut yet). Seeded in Phase 0 from `--report`
# so the guard is green on introduction. Each entry is DECISION-flagged in
# SIMPLIFICATION_STATUS.md: these are all built + unit-tested but not wired into
# the live request path. Most are candidates to WIRE IN (they serve
# verify/authorize/federal) rather than attic — resolved in Phase 1/2, not here.
#
# NOTE: this set is DISJOINT from the P1 audit cut-list. That audit traced
# api_routers/ only; this guard also roots at scripts/*, so the P1 modules are
# reachable via demo seeders / harnesses and are NOT orphans by this definition.
# See SIMPLIFICATION_STATUS.md "Decisions" for the reconciliation.
ALLOWLIST: set[str] = {
    "modules.auth.scopes",           # OAuth-style scope model — wire into AUTHORIZE
    "modules.identity.dpop",         # DPoP proof validation — wire into VERIFY
    "modules.security.field_crypto", # field encryption at rest — federal posture
    "modules.security.mtls",         # internal mTLS helper (+mtls_server/mtls_peer cluster)
    "modules.security.mtls_peer",    # peer-auth for internal mTLS
    "modules.security.mtls_server",  # server side of internal mTLS
    "modules.security.secrets",      # secrets-manager abstraction (fully unreferenced)
}


def _module_name(path: Path) -> str:
    rel = path.relative_to(REPO).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def discover() -> dict[str, Path]:
    """Map every first-party dotted module name -> file path."""
    mods: dict[str, Path] = {}
    for path in REPO.rglob("*.py"):
        rel = path.relative_to(REPO).as_posix()
        if rel.startswith((".git/", "build/", "attic/")) or ".egg-info/" in rel:
            continue
        top = rel.split("/", 1)[0]
        top_mod = top[:-3] if top.endswith(".py") else top
        if top_mod not in FIRST_PARTY:
            continue
        mods[_module_name(path)] = path
    return mods


def _candidates_from_import(node: ast.AST, pkg_parts: list[str]) -> set[str]:
    """Dotted-name candidates an import statement could resolve to."""
    out: set[str] = set()
    if isinstance(node, ast.Import):
        for alias in node.names:
            out.add(alias.name)
    elif isinstance(node, ast.ImportFrom):
        if node.level:  # relative import
            base = pkg_parts[: len(pkg_parts) - (node.level - 1)]
            mod = (base + (node.module.split(".") if node.module else []))
        else:
            mod = node.module.split(".") if node.module else []
        base_dotted = ".".join(mod)
        if base_dotted:
            out.add(base_dotted)
        # `from pkg import name` — name may itself be a submodule.
        for alias in node.names:
            if alias.name != "*":
                out.add(".".join(mod + [alias.name]) if mod else alias.name)
    return out


def imports_of(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return set()
    rel = path.relative_to(REPO).with_suffix("")
    pkg_parts = list(rel.parts[:-1]) if rel.parts[-1] != "__init__" else list(rel.parts[:-1])
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            out |= _candidates_from_import(node, pkg_parts)
    return out


def _resolve(dotted: str, mods: dict[str, Path]) -> str | None:
    """Resolve a dotted candidate to a known module name (exact, or its package)."""
    if dotted in mods:
        return dotted
    # `from a.b import c` where c is an attribute, not a submodule -> resolve a.b
    parent = dotted.rsplit(".", 1)[0] if "." in dotted else None
    if parent and parent in mods:
        return parent
    return None


def string_referenced_modules(mods: dict[str, Path]) -> set[str]:
    """Modules whose dotted path appears as a string literal anywhere under roots
    (covers importlib / __import__ / config-driven dynamic loads)."""
    referenced: set[str] = set()
    names = set(mods)
    self_path = Path(__file__).resolve()
    for path in mods.values():
        if path.resolve() == self_path:
            continue  # don't let this guard's own ALLOWLIST literals count as refs
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for name in names:
            if name.startswith("modules.") and (f'"{name}"' in text or f"'{name}'" in text):
                referenced.add(name)
    return referenced


def build_reachable(mods: dict[str, Path]) -> set[str]:
    roots: list[str] = []
    for f in ROOT_FILES:
        name = f[:-3]
        if name in mods:
            roots.append(name)
    for d in ROOT_DIRS:
        for name, p in mods.items():
            if p.relative_to(REPO).as_posix().startswith(d + "/"):
                roots.append(name)

    reachable: set[str] = set()
    stack = list(roots)
    while stack:
        cur = stack.pop()
        if cur in reachable or cur not in mods:
            continue
        reachable.add(cur)
        for cand in imports_of(mods[cur]):
            resolved = _resolve(cand, mods)
            if resolved and resolved not in reachable:
                stack.append(resolved)
    return reachable


def find_orphans() -> list[str]:
    mods = discover()
    reachable = build_reachable(mods)
    reachable |= string_referenced_modules(mods)
    orphans = []
    for name, path in sorted(mods.items()):
        rel = path.relative_to(REPO).as_posix()
        if not rel.startswith("modules/"):
            continue
        if rel.endswith("/__init__.py") or path.name == "__init__.py":
            continue
        if name not in reachable:
            orphans.append(name)
    return orphans


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", action="store_true", help="list orphans, exit 0")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    orphans = find_orphans()
    unallowed = [o for o in orphans if o not in ALLOWLIST]
    stale_allow = sorted(ALLOWLIST - set(orphans))

    if args.json:
        print(json.dumps({"orphans": orphans, "allowlist": sorted(ALLOWLIST),
                          "unallowed": unallowed, "stale_allowlist": stale_allow}, indent=2))
    elif args.report:
        print(f"# {len(orphans)} orphan module(s) under modules/ (zero inbound edges):")
        for o in orphans:
            print(o)
    else:
        if stale_allow:
            print("::warning::orphan-guard ALLOWLIST has entries that are no longer "
                  "orphans (were they wired back in?): " + ", ".join(stale_allow))
        if unallowed:
            print(f"::error::orphan-guard found {len(unallowed)} module(s) under "
                  "modules/ with zero inbound edges and not on the ALLOWLIST:")
            for o in unallowed:
                print(f"::error::  {o}")
            print("Cut them (git rm module + test) or, if reachable dynamically, "
                  "add to ALLOWLIST with a comment.")
            return 1
        print(f"orphan-guard OK: {len(orphans)} known orphan(s), all allowlisted; "
              f"no new orphans.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
