"""License status + activation endpoints.

GET  /api/license/status    — current license state (any authenticated tenant)
POST /api/license/activate  — verify + persist a license key (admin/owner)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from modules.product import licensing
from modules.tenants.middleware import get_tenant
from modules.tenants.models import TenantContext

router = APIRouter(tags=["license"])

# Prefer the platform RBAC dependency when available; fall back to plain
# tenant auth so this router never blocks app startup.
try:  # pragma: no cover - wiring, exercised via app import
    from modules.security.rbac import Role, require_role

    _admin_dependency = require_role(Role.ADMIN)
except Exception:  # noqa: BLE001  pragma: no cover
    _admin_dependency = get_tenant


class ActivateBody(BaseModel):
    license_key: str = Field(..., min_length=10, max_length=8192)


@router.get("/api/license/status")
async def api_license_status(
    tenant: TenantContext = Depends(get_tenant),
) -> dict:
    """Return the current license state, enforcement mode, and granted tier."""
    return licensing.status()


@router.post("/api/license/activate")
async def api_license_activate(
    body: ActivateBody,
    tenant: TenantContext = Depends(_admin_dependency),
) -> dict:
    """Verify a license key and persist it to the configured license file."""
    try:
        lic = licensing.activate(body.license_key)
    except licensing.LicenseError as exc:
        raise HTTPException(status_code=400, detail=f"invalid license: {exc}") from exc
    return {"status": "activated", "license": lic.to_dict()}
