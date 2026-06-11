"""Route registry for the decomposed API surface (T-1).

Contract:
  * ``api.py`` is FROZEN. The CI ratchet (scripts/ci/api_monolith_ratchet.py)
    fails any PR that grows it. New endpoints are born here.
  * One router per product domain, owned by the module that implements it.
  * Every router declares its own prefix, tags, and tier-gate dependency, so
    mounting is uniform and nothing is implicit.
  * The route surface must not change during a move — scripts/ci/openapi_route_guard.py
    diffs ``METHOD path`` signatures against a committed snapshot.

Migration order (largest cohesive groups first; one row per sprint PR):
  1) /api/policy (22) + /api/enforcement (12)      — same tier gate
  2) /api/mcp (22)
  3) /api/compliance (22)
  4) /api/agent (19) + /api/agents (9)
  5) /api/threat-sharing (14) + /api/intel (7)
  6) /api/federation (14) + /api/delegation (7)
  7) /api/discovery (13) + /api/passport (11) + /api/verifier (10)
  8) /api/certs (8) + /api/workflow (7) + /api/product (7)
  9) /api/honeypot, /api/behavioral, /api/uis, /api/drift, /api/oss, /api/intent, /api/graph
 10) /admin, /saml, /profile, /onboarding + residue; then api.py -> main.py

Each sprint PR:
  * adds api_routers/<domain>.py (handlers MOVE verbatim; only the decorator
    changes from @app.<verb>("/api/<domain>/...") to @router.<verb>("/...")),
  * imports the router below and appends it to ALL_ROUTERS,
  * deletes the moved handlers from api.py,
  * lowers scripts/ci/api_line_budget.txt to the new api.py line count,
  * keeps the route-surface guard green (no signature change).
"""
from __future__ import annotations

from fastapi import APIRouter, FastAPI

from api_routers.policy_guard import router as policy_guard_router  # /api/policy/guard (6)

# Routers are appended here one sprint at a time. Each addition moves its
# handlers OUT of api.py (enforced by the monolith ratchet) and must keep the
# route-surface guard green (no signature change).
ALL_ROUTERS: tuple[APIRouter, ...] = (
    policy_guard_router,
)


def mount_all(app: FastAPI) -> None:
    """Mount every registered domain router onto the app.

    Called from api.py's app factory. A no-op while ALL_ROUTERS is empty, so
    wiring it in now changes nothing about the route surface.
    """
    for router in ALL_ROUTERS:
        app.include_router(router)
