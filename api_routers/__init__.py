"""Route registry for the decomposed API surface (T-1).

api.py is FROZEN (the CI ratchet fails any PR that grows it). New endpoints are
born here, one router per product domain. Routers are appended to ALL_ROUTERS
as domains migrate out of api.py; the route-surface guard keeps the externally
visible surface unchanged. See api_routers/MIGRATION.md.
"""
from __future__ import annotations

from fastapi import APIRouter, FastAPI

from api_routers.agents import router as agents_router
from api_routers.compliance import router as compliance_router
from api_routers.enforcement import router as enforcement_router
from api_routers.mcp import router as mcp_router
from api_routers.policy_bundles import router as policy_bundles_router
from api_routers.policy_guard import router as policy_guard_router
from api_routers.policy_suggestions import router as policy_suggestions_router

ALL_ROUTERS: tuple[APIRouter, ...] = (
    agents_router,
    compliance_router,
    enforcement_router,
    mcp_router,
    policy_bundles_router,
    policy_guard_router,
    policy_suggestions_router,
)


def mount_all(app: FastAPI) -> None:
    """Mount every registered domain router onto the app (called from api.py)."""
    for router in ALL_ROUTERS:
        app.include_router(router)
