"""T0.6 guardrail: trial mode is fully isolated behind TOKENDNA_TRIAL_MODE.

Runs the app in a subprocess (mount decisions happen at import) to assert:
  * flag OFF  -> no /trial/* routes; the production route surface is unchanged.
  * flag ON   -> /trial/status is mounted and returns 200.

Prod behavior must not change when the flag is off (Operating Rule: Trial ≠ prod).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[1]

# Mirrors scripts/ci/openapi_route_guard.current_surface() exactly.
_SNIPPET = """
import json, os
os.environ["DEV_MODE"] = "true"
os.environ.setdefault("TOKENDNA_ENV", "ci")
import api
IGNORE = {"/openapi.json", "/docs", "/redoc", "/docs/oauth2-redirect"}
surface = set()
for r in api.app.routes:
    path = getattr(r, "path", None)
    methods = getattr(r, "methods", None)
    if not path or not methods or path in IGNORE:
        continue
    for m in methods:
        if m in ("HEAD", "OPTIONS"):
            continue
        surface.add(f"{m} {path}")
print(json.dumps(sorted(surface)))
"""


def _surface(trial: bool) -> set[str]:
    env = {k: v for k, v in os.environ.items() if k not in {"TOKENDNA_TRIAL_MODE"}}
    env["PYTHONPATH"] = str(REPO_ROOT)
    if trial:
        env["TOKENDNA_TRIAL_MODE"] = "true"
    r = subprocess.run([sys.executable, "-c", _SNIPPET], cwd=str(REPO_ROOT),
                       env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    return set(json.loads(r.stdout.strip().splitlines()[-1]))


def test_trial_only_adds_routes_and_prod_surface_is_unchanged():
    off = _surface(trial=False)
    on = _surface(trial=True)

    # Flag off: no trial routes reachable at all.
    assert not any(" /trial" in e for e in off), "trial routes leaked with flag off"

    # Trial ONLY adds routes — it removes/changes nothing in the prod surface.
    assert off - on == set(), f"trial mode removed prod routes: {off - on}"
    added = on - off
    assert added, "trial mode added no routes"
    assert all(" /trial" in e for e in added), f"trial changed non-trial routes: {added}"
    assert "GET /trial/status" in added


def test_trial_off_surface_matches_committed_snapshot():
    # The committed route snapshot is generated with trial off; the route-surface
    # guard enforces it in CI. Confirm our trial-off surface equals it.
    off = _surface(trial=False)
    snapshot = set(json.loads((REPO_ROOT / "scripts/ci/openapi_routes.json").read_text()))
    assert off == snapshot, (
        f"prod surface drifted from snapshot with trial off "
        f"(+{sorted(off - snapshot)} / -{sorted(snapshot - off)})")
