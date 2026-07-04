"""Route registry for the decomposed API surface (T-1).

api.py is FROZEN (the CI ratchet fails any PR that grows it). New endpoints are
born here, one router per product domain. Routers are appended to ALL_ROUTERS
as domains migrate out of api.py; the route-surface guard keeps the externally
visible surface unchanged. See api_routers/MIGRATION.md.
"""
from __future__ import annotations

import hashlib
import os
import pathlib

from fastapi import APIRouter, FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from api_routers.agents import router as agents_router
from api_routers.assets import router as assets_router
from api_routers.certs import router as certs_router
from api_routers.compliance import router as compliance_router
from api_routers.console import router as console_router
from api_routers.delegation import router as delegation_router
from api_routers.demo import router as demo_router
from api_routers.discovery import router as discovery_router
from api_routers.enforcement import router as enforcement_router
from api_routers.enterprise import router as enterprise_router
from api_routers.federation import router as federation_router
from api_routers.identity_surface import router as identity_surface_router
from api_routers.intel import router as intel_router
from api_routers.kill import router as kill_router
from api_routers.license import router as license_router
from api_routers.mcp import router as mcp_router
from api_routers.misc import router as misc_router
from api_routers.passport import router as passport_router
from api_routers.policy_bundles import router as policy_bundles_router
from api_routers.policy_export import router as policy_export_router
from api_routers.policy_guard import router as policy_guard_router
from api_routers.policy_suggestions import router as policy_suggestions_router
from api_routers.product import router as product_router
from api_routers.retrieval import router as retrieval_router
from api_routers.siem import router as siem_router
from api_routers.verifier import router as verifier_router
from api_routers.workflow import router as workflow_router

ALL_ROUTERS: tuple[APIRouter, ...] = (
    agents_router,
    assets_router,
    certs_router,
    compliance_router,
    console_router,
    delegation_router,
    demo_router,
    discovery_router,
    enforcement_router,
    enterprise_router,
    federation_router,
    identity_surface_router,
    intel_router,
    kill_router,
    license_router,
    mcp_router,
    misc_router,
    passport_router,
    policy_bundles_router,
    policy_export_router,
    policy_guard_router,
    policy_suggestions_router,
    product_router,
    retrieval_router,
    siem_router,
    verifier_router,
    workflow_router,
)


_STATIC_DIR = pathlib.Path(__file__).resolve().parent.parent / "dashboard" / "static"


class _CachingStatic(StaticFiles):
    """StaticFiles whose cache policy is env-driven.

    * Local dev (default): ``no-store`` so edits to local assets show up on a
      normal reload (paired with versioned ?v= URLs).
    * Production: set ``ASSET_CACHE_SECONDS`` (e.g. 86400) to serve
      ``public, max-age=<n>`` — safe because every asset URL is version-busted.
    """

    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        secs = int(os.getenv("ASSET_CACHE_SECONDS", "0") or "0")
        if secs > 0:
            response.headers["Cache-Control"] = f"public, max-age={secs}"
        else:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return response


# Paths the demo-password gate never blocks (health probes + the login page).
_DEMO_OPEN_PATHS = {"/healthz", "/readyz", "/", "/metrics", "/__demo_login"}
_DEMO_COOKIE = "tdna_demo"


def _demo_token(password: str) -> str:
    return hashlib.sha256(("tokendna-demo::" + password).encode()).hexdigest()


def _demo_login_page(error: bool = False) -> str:
    msg = '<p class="err">Incorrect password.</p>' if error else ""
    return (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>TokenDNA — Demo Access</title><style>"
        "html,body{height:100%;margin:0;background:#070b12;color:#e2e8f0;"
        "font:15px/1.5 ui-sans-serif,system-ui,sans-serif;display:flex;align-items:center;justify-content:center}"
        ".box{background:#0f1622;border:1px solid #1e293b;border-radius:12px;padding:32px 28px;width:320px;text-align:center}"
        ".brand{font-weight:800;font-size:20px;margin-bottom:4px}.brand span{color:#3aa9ff}"
        ".sub{color:#94a3b8;font-size:13px;margin-bottom:20px}"
        "input{width:100%;box-sizing:border-box;background:#0b1220;border:1px solid #1e293b;color:#e2e8f0;"
        "padding:10px 12px;border-radius:8px;font-size:14px;margin-bottom:12px}"
        "button{width:100%;background:#3aa9ff;color:#00131f;border:0;padding:10px;border-radius:8px;"
        "font-weight:700;font-size:14px;cursor:pointer}.err{color:#ef4444;font-size:12px;margin:0 0 12px}"
        "</style></head><body><form class=box method=post action=/__demo_login>"
        "<div class=brand>Token<span>DNA</span></div>"
        "<div class=sub>Enter the demo password to continue.</div>"
        f"{msg}"
        "<input type=password name=password placeholder=Password autofocus>"
        "<button type=submit>Enter</button></form></body></html>"
    )


class DemoAuthMiddleware(BaseHTTPMiddleware):
    """Shared-password gate for a public demo. Active only when DEMO_PASSWORD is
    set; otherwise a pure pass-through (local dev stays open). Health probes and
    the login page are always reachable so Railway's healthcheck still passes."""

    def __init__(self, app, password: str):
        super().__init__(app)
        self._token = _demo_token(password)
        self._password = password

    async def dispatch(self, request, call_next):
        path = request.url.path
        if path in _DEMO_OPEN_PATHS and path != "/__demo_login":
            return await call_next(request)
        if path == "/__demo_login":
            if request.method == "POST":
                form = await request.form()
                if form.get("password") == self._password:
                    resp = RedirectResponse(url="/dashboard", status_code=303)
                    resp.set_cookie(_DEMO_COOKIE, self._token, httponly=True, samesite="lax", max_age=86400 * 7)
                    return resp
                return HTMLResponse(_demo_login_page(error=True), status_code=401)
            return HTMLResponse(_demo_login_page())
        if request.cookies.get(_DEMO_COOKIE) == self._token:
            return await call_next(request)
        # Unauthenticated: API/asset calls get 401, navigations get the login page.
        accept = request.headers.get("accept", "")
        if path.startswith("/api/") or path.startswith("/static/") or "text/html" not in accept:
            return Response("authentication required", status_code=401)
        return HTMLResponse(_demo_login_page(), status_code=401)


def mount_all(app: FastAPI) -> None:
    """Mount every registered domain router onto the app (called from api.py).

    Also mounts the locally-vendored dashboard assets (React + the
    dependency-free trust-graph engine) at /static so the dashboard runs fully
    offline with zero third-party CDN requests. A StaticFiles ``Mount`` has no
    ``methods`` attribute, so the route-surface guard skips it.
    """
    for router in ALL_ROUTERS:
        app.include_router(router)
    if _STATIC_DIR.is_dir():
        app.mount("/static", _CachingStatic(directory=str(_STATIC_DIR)), name="static")
    # Optional public-demo password gate (no-op unless DEMO_PASSWORD is set, so
    # local dev stays open). Added last → outermost middleware → gates everything.
    demo_pw = (os.getenv("DEMO_PASSWORD") or "").strip()
    if demo_pw:
        app.add_middleware(DemoAuthMiddleware, password=demo_pw)
