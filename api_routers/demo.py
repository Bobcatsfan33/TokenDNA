"""Interactive demo console (serves dashboard/demo.html).

A self-contained console that exercises every TokenDNA feature against the REAL
API — paired with scripts/demo_seed_gap.py + demo_seed_v2.py for fake data and
DEV_MODE for auth bypass, it is an exact working prototype.

When TOKENDNA_DEMO=<tenant> is set, this module also seeds the in-memory demo
IdP config at app load so the kill-switch IdP planes show connected in the
running server (the on-disk seeder runs in a separate process). Demo/dev only.
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse

from api_routers._shared import serve_dashboard_html

router = APIRouter(tags=["demo"])

_DEMO_PATH = Path(__file__).resolve().parent.parent / "dashboard" / "demo.html"

# In-process demo IdP config so kill-switch IdP planes show connected on the
# running server (in-memory only — never enabled in production).
_demo_tenant = os.getenv("TOKENDNA_DEMO")
if _demo_tenant:
    try:
        from modules.identity import idp_revocation
        idp_revocation.configure_demo_idp(_demo_tenant)
    except Exception:  # noqa: BLE001 - demo bootstrap is best-effort
        pass


@router.get("/demo", response_class=HTMLResponse)
async def demo_console():
    if not _DEMO_PATH.exists():
        raise HTTPException(status_code=404, detail="demo console not found")
    return serve_dashboard_html(_DEMO_PATH)
