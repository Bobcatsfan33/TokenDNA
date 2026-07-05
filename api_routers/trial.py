"""Trial-mode router (T0).

Mounted by ``mount_all`` ONLY when ``trial_enabled()`` — so the production route
surface is unchanged when the flag is off. Every endpoint additionally depends
on ``require_trial`` as defense in depth. Onboarding/import/reset/license
endpoints (Phases T1–T3) are added here.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from modules.trial.guard import require_trial, trial_enabled

router = APIRouter(prefix="/trial", tags=["trial"], dependencies=[Depends(require_trial)])


@router.get("/status")
async def trial_status() -> dict:
    """Liveness + capability probe for the trial console."""
    return {
        "trial_mode": trial_enabled(),
        "phase": "T0",
        "capabilities": [],  # populated by T1 (license), T2 (idp), T3 (import)
    }
