# T-1 — api.py decomposition runbook

`api.py` is a 6,940-line, 305-route monolith. This is the safety net + the
mechanical recipe to decompose it into per-domain routers without changing the
externally-visible API surface. The infrastructure (this PR) lands first; the
route moves follow as ~10 small sprint PRs.

## Safety net (enforced in CI from PR #1)

- **Monolith ratchet** — `scripts/ci/api_monolith_ratchet.py` + the committed
  `scripts/ci/api_line_budget.txt`. `api.py` may only shrink: a PR that grows
  it fails; a PR that shrinks it must lower the budget in the same PR.
- **Route-surface guard** — `scripts/ci/openapi_route_guard.py` + the committed
  `scripts/ci/openapi_routes.json` (305 `METHOD path` signatures). A move that
  adds/removes any route fails. Re-baseline only for intentional API changes:
  `python scripts/ci/openapi_route_guard.py --update`.
- **Registry** — `api_routers/__init__.py` exposes `mount_all(app)`, already
  wired into `api.py`'s app factory (no-op while `ALL_ROUTERS` is empty).

## Per-sprint recipe (repeat for each row of the migration order)

1. Create `api_routers/<domain>.py`:
   ```python
   from fastapi import APIRouter, Depends
   from modules.tenants.middleware import get_tenant            # if needed
   from modules.product.commercial_tiers import require_feature # tier gate
   # ... import the underlying modules the handlers call (NOT api.py — avoid
   #     the import cycle; api.py imports api_routers).

   router = APIRouter(
       prefix="/api/<domain>",
       tags=["<domain>"],
       dependencies=[Depends(require_feature("ent.<gate>"))],  # if shared
   )

   @router.get("/...")            # was @app.get("/api/<domain>/...")
   async def handler(...):
       ...                        # body MOVED verbatim from api.py
   ```
2. Any helper a handler uses that currently lives in `api.py` (e.g.
   `_record_decision_audit`, `_encode_cursor`) moves to `api_routers/_shared.py`
   and is imported by both during the transition.
3. In `api_routers/__init__.py`: import the new router and append it to
   `ALL_ROUTERS`.
4. Delete the moved handlers from `api.py`.
5. Lower `scripts/ci/api_line_budget.txt` to the new `api.py` line count.
6. Run locally and confirm green:
   ```bash
   python scripts/ci/api_monolith_ratchet.py
   python scripts/ci/openapi_route_guard.py     # surface unchanged
   pytest -q
   ```
7. Open the sprint PR. CI re-runs the ratchet + guard + full suite.

## Migration order (one row per sprint PR)

1. `/api/policy` (22) + `/api/enforcement` (12) — same tier gate
2. `/api/mcp` (22)
3. `/api/compliance` (22)
4. `/api/agent` (19) + `/api/agents` (9)
5. `/api/threat-sharing` (14) + `/api/intel` (7)
6. `/api/federation` (14) + `/api/delegation` (7)
7. `/api/discovery` (13) + `/api/passport` (11) + `/api/verifier` (10)
8. `/api/certs` (8) + `/api/workflow` (7) + `/api/product` (7)
9. `/api/honeypot`, `/api/behavioral`, `/api/uis`, `/api/drift`, `/api/oss`,
   `/api/intent`, `/api/graph`
10. `/admin`, `/saml`, `/profile`, `/onboarding` + residue; then rename
    `api.py` → `main.py` (app factory only: lifespan, middleware, `mount_all`,
    `/healthz` `/readyz` `/metrics`).

## Done when

- Budget < 300; `api.py` (now `main.py`) is the app factory only.
- Route-surface guard green at every step (surface never changed).
- Every router declares explicit auth + tier-gate dependencies; no route relies
  on incidental global state from `api.py`.
