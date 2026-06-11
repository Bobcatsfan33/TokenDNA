"""Shared helpers used by extracted domain routers (T-1).

Helpers that used to live as module-level functions in api.py and are referenced
by moved handlers land here so routers don't import api.py (which would create a
cycle: api.py imports api_routers).
"""
from __future__ import annotations

from fastapi import HTTPException


def _delegation_error_to_http(exc: Exception) -> HTTPException:
    """Translate DelegationError reason codes to structured 4xx responses."""
    code_map = {
        "scope_must_be_list_of_strings":      400,
        "expires_in_seconds_must_be_positive": 400,
        "root_delegator_must_be_human":       400,
        "parent_not_found":                   404,
        "parent_cross_tenant":                403,
        "parent_revoked":                     409,
        "parent_expired":                     409,
        "delegator_not_parent_delegatee":     403,
        "scope_exceeds_parent":               403,
        "not_found":                          404,
        "cross_tenant":                       403,
    }
    reason = str(exc)
    return HTTPException(
        status_code=code_map.get(reason, 400),
        detail={"error": reason, "message": reason.replace("_", " ")},
    )
