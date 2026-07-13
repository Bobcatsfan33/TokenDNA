"""AI Asset Management console (Gap roadmap Phase 1 / C2 / D3).

Serves the rebuilt console: a Cytoscape+dagre hierarchical workflow DAG with a
header stat strip (Agents/Tools/MCP/Vulnerabilities) and a click-a-node ->
rip-credentials kill flow wired to /api/kill. Static page (auth happens on the
API calls it makes), served alongside the legacy /dashboard.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse

from api_routers._shared import serve_dashboard_html

router = APIRouter(tags=["console"])

# dashboard/*.html live at the repo root (this file is in api_routers/).
_DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"
_CONSOLE_PATH = _DASHBOARD_DIR / "console.html"
_TRUSTGRAPH_PATH = _DASHBOARD_DIR / "trustgraph.html"


@router.get("/console", response_class=HTMLResponse)
async def console():
    if not _CONSOLE_PATH.exists():
        raise HTTPException(status_code=404, detail="console not found")
    return serve_dashboard_html(_CONSOLE_PATH)


@router.get("/trust-graph", response_class=HTMLResponse)
async def trust_graph():
    """Clean trust-graph explorer — toggle Nodes / Edges / Anomalies / Correlate."""
    if not _TRUSTGRAPH_PATH.exists():
        raise HTTPException(status_code=404, detail="trust graph view not found")
    return serve_dashboard_html(_TRUSTGRAPH_PATH)
