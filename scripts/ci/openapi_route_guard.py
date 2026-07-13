#!/usr/bin/env python3
"""CI guard: the API route surface may not change during decomposition (T-1).

Moving a handler from api.py into api_routers/<domain>.py must preserve the
exact route surface — same paths, same methods. This guard imports the app,
computes the set of ``METHOD path`` route signatures, and compares it to the
committed snapshot. Tags/internal grouping may change; the externally-visible
surface may not.

    - name: API route-surface guard
      run: python scripts/ci/openapi_route_guard.py

Re-baseline ONLY when intentionally adding/removing endpoints:
    python scripts/ci/openapi_route_guard.py --update
"""
import json
import os
import pathlib
import sys

SNAPSHOT = pathlib.Path("scripts/ci/openapi_routes.json")

# Infra/transport routes whose method set varies by framework internals.
_IGNORE_PATHS = {"/openapi.json", "/docs", "/redoc", "/docs/oauth2-redirect"}


def current_surface() -> list[str]:
    # Import in a side-effect-light mode. CI runs this from the repo root;
    # ensure the root is importable regardless of the script's own location.
    os.environ.setdefault("DEV_MODE", "true")
    sys.path.insert(0, str(pathlib.Path.cwd()))
    import api  # noqa: PLC0415

    surface: set[str] = set()
    for route in api.app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if not path or not methods or path in _IGNORE_PATHS:
            continue
        for method in methods:
            if method in {"HEAD", "OPTIONS"}:
                continue
            surface.add(f"{method} {path}")
    return sorted(surface)


def main(argv: list[str]) -> int:
    surface = current_surface()

    if "--update" in argv:
        SNAPSHOT.write_text(json.dumps(surface, indent=2) + "\n", encoding="utf-8")
        print(f"route snapshot updated: {len(surface)} routes -> {SNAPSHOT}")
        return 0

    if not SNAPSHOT.exists():
        print(f"::error::route snapshot missing at {SNAPSHOT}; run with --update to seed it")
        return 1

    expected = set(json.loads(SNAPSHOT.read_text(encoding="utf-8")))
    actual = set(surface)

    added = sorted(actual - expected)
    removed = sorted(expected - actual)
    if added or removed:
        for r in added:
            print(f"::error::route ADDED (not in snapshot): {r}")
        for r in removed:
            print(f"::error::route REMOVED (in snapshot, now missing): {r}")
        print(
            "::error::route surface changed. Decomposition PRs must preserve it. "
            "If this change is intentional, re-baseline with --update."
        )
        return 1

    print(f"route-surface guard OK: {len(actual)} routes unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
