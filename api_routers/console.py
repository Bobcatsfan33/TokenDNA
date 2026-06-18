"""AI Asset Management console (Gap roadmap Phase 1 / C2 / D3).

Serves the rebuilt console: a Cytoscape+dagre hierarchical workflow DAG with a
header stat strip (Agents/Tools/MCP/Vulnerabilities) and a click-a-node ->
rip-credentials kill flow wired to /api/kill. Static page (auth happens on the
API calls it makes), served alongside the legacy /dashboard.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, HTMLResponse

router = APIRouter(tags=["console"])

# dashboard/console.html lives at the repo root (this file is in api_routers/).
_CONSOLE_PATH = Path(__file__).resolve().parent.parent / "dashboard" / "console.html"


@router.get("/console", response_class=HTMLResponse)
async def console():
    if not _CONSOLE_PATH.exists():
        raise HTTPException(status_code=404, detail="console not found")
    return FileResponse(_CONSOLE_PATH)
