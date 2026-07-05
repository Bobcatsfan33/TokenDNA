"""Trial-mode gate.

``trial_enabled()`` reads the environment fresh so mounting decisions and
request-time checks agree regardless of import order. ``require_trial`` is a
FastAPI dependency that 404s when trial mode is off — trial endpoints must be
invisible in a production deployment.
"""
from __future__ import annotations

import os

from fastapi import HTTPException, status


def trial_enabled() -> bool:
    """True when TOKENDNA_TRIAL_MODE is on. Read fresh (not import-cached)."""
    return (os.getenv("TOKENDNA_TRIAL_MODE", "false") or "false").strip().lower() == "true"


def require_trial() -> None:
    """FastAPI dependency: reject when trial mode is off (defense in depth even
    though the router is only mounted when enabled)."""
    if not trial_enabled():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="trial mode is not enabled on this deployment",
        )
