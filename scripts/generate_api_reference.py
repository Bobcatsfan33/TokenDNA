#!/usr/bin/env python3
"""
Generate a static, self-contained API reference HTML page from the FastAPI
``/openapi.json`` schema.

Output:
  docs/api/openapi.json     the raw schema (committed so external tools can
                            consume without running the server)
  docs/api/index.html       a single-page reference using Redoc (CDN-hosted,
                            no build step) — works offline once cached

Run:
  python3 scripts/generate_api_reference.py

CI hook:
  .github/workflows/ci.yml regenerates this on every change to api.py and
  fails the job if the diff is non-trivial (forces the doc to track code).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure the repo is importable without installing
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

OUT_DIR = REPO / "docs" / "api"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def _render_html(title: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{title} — API reference</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" href="data:,">
  <style>body {{ margin: 0; }}</style>
</head>
<body>
  <redoc spec-url="openapi.json"></redoc>
  <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
</body>
</html>
"""


def main() -> int:
    # Importing the module builds the FastAPI app + every route registration
    print("importing api.py …", file=sys.stderr)
    import api as api_mod
    schema = api_mod.app.openapi()

    schema_path = OUT_DIR / "openapi.json"
    schema_path.write_text(json.dumps(schema, indent=2, sort_keys=True))
    print(f"wrote {schema_path}  ({schema_path.stat().st_size:,} bytes)", file=sys.stderr)

    title = schema.get("info", {}).get("title", "TokenDNA")
    html_path = OUT_DIR / "index.html"
    html_path.write_text(_render_html(title))
    print(f"wrote {html_path}  ({html_path.stat().st_size:,} bytes)", file=sys.stderr)

    paths_count = len(schema.get("paths", {}))
    print(f"\n{paths_count} route paths documented.", file=sys.stderr)
    print(f"Open: file://{html_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
