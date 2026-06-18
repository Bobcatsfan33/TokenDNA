"""Route registry for the decomposed API surface (T-1).

api.py is FROZEN (the CI ratchet fails any PR that grows it). New endpoints are
born here, one router per product domain. Routers are appended to ALL_ROUTERS
as domains migrate out of api.py; the route-surface guard keeps the externally
visible surface unchanged. See api_routers/MIGRATION.md.
"""
from __future__ import annotations

from fastapi import APIRouter, FastAPI

from api_routers.agents import router as agents_router
from api_routers.assets import router as assets_router
from api_routers.certs import router as certs_router
from api_routers.compliance import router as compliance_router
from api_routers.delegation import router as delegation_router
from api_routers.discovery import router as discovery_router
from api_routers.enforcement import router as enforcement_router
from api_routers.enterprise import router as enterprise_router
from api_routers.federation import router as federation_router
from api_routers.identity_surface import router as identity_surface_router
from api_routers.intel import router as intel_router
from api_routers.kill import router as kill_router
from api_routers.mcp import router as mcp_router
from api_routers.misc import router as misc_router
from api_routers.passport import router as passport_router
from api_routers.policy_bundles import router as policy_bundles_router
from api_routers.policy_export import router as policy_export_router
from api_routers.policy_guard import router as policy_guard_router
from api_routers.policy_suggestions import router as policy_suggestions_router
from api_routers.product import router as product_router
from api_routers.retrieval import router as retrieval_router
from api_routers.threat_sharing import router as threat_sharing_router
from api_routers.verifier import router as verifier_router
from api_routers.workflow import router as workflow_router

ALL_ROUTERS: tuple[APIRouter, ...] = (
    agents_router,
    assets_router,
    certs_router,
    compliance_router,
    delegation_router,
    discovery_router,
    enforcement_router,
    enterprise_router,
    federation_router,
    identity_surface_router,
    intel_router,
    kill_router,
    mcp_router,
    misc_router,
    passport_router,
    policy_bundles_router,
    policy_export_router,
    policy_guard_router,
    policy_suggestions_router,
    product_router,
    retrieval_router,
    threat_sharing_router,
    verifier_router,
    workflow_router,
)


def mount_all(app: FastAPI) -> None:
    """Mount every registered domain router onto the app (called from api.py)."""
    for router in ALL_ROUTERS:
        app.include_router(router)
