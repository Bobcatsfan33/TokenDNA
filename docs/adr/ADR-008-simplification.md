# ADR-008: Simplification to a three-questions product

- **Status:** Accepted
- **Date:** 2026-07-04
- **Supersedes roadmap in:** `CLAUDE.md` module-status tables (partially stale)
- **Plan of record:** [`SIMPLIFICATION_PLAN.md`](../../SIMPLIFICATION_PLAN.md)
- **Progress tracker:** [`SIMPLIFICATION_STATUS.md`](../../SIMPLIFICATION_STATUS.md)

## Context

TokenDNA grew to ~95,961 LOC across 416 files and 67 identity modules. Much of
it is unwired R&D: modules reachable only from demo seeders or their own tests,
duplicate stub frameworks, and an ingestion split (`platform/`, `collector/`)
that never connected to the request path. The surface (31 routers) is larger
than the value proposition, and the product is hard to explain in one screen.

## Decision

Refocus the product on **three questions answered about any AI agent at
runtime**, and make every module either serve one of them, support the
infrastructure they run on, or move to the attic:

1. **VERIFY** — is this a legitimate agent identity with valid credentials?
2. **AUTHORIZE** — is it allowed to do what it's doing, where it is, and where
   it's going?
3. **CONTAIN** — has it been compromised, what is the blast radius, and can we
   trace every downstream impact?

Target end state: ~60K LOC, ~38 identity modules, 9 routers, zero orphaned
modules (CI-enforced by `scripts/ci/orphan_guard.py`), single-container
zero-dependency default deployment, a live 3-view console, and the IL5-target
federal profile intact.

## What is cut (and why it is safe)

Unwired modules move to the **`attic/2026-07`** branch (tagged
`v3.0.0-pre-simplification`). Nothing is deleted from history — the attic is
indexed in `ATTIC.md` as "validated R&D options," diligence-facing. A module is
removed only after at-cut-time verification of zero live inbound imports across
`api.py`, `serve.py`, `auth.py`, `api_routers/`, `modules/`, `tokendna_sdk/`,
and `scripts/` (Operating Rule 2). Each cut is an individual, bisectable commit;
its test file is cut in the same commit; CI (full pytest + ruff + orphan guard +
demo smoke) stays green at every commit.

## What is explicitly kept

- The **SDK** (`tokendna_sdk/`, Apache-2.0, on PyPI) — untouched except where a
  phase explicitly extends it.
- The **federal track** — FIPS gate, `Dockerfile.fips`,
  `TOKENDNA_COMPLIANCE_PROFILE` (target `dod_il5`), control matrix, `docs/ato/`,
  STIG/OSCAL scripts, `compliance_engine.py`, `compliance_posture.py`,
  SAML/SCIM.
- The **honesty framing** — "no independent audit / no production deployments /
  compliance = mappings and design intent, not certification." Never written as
  "compliant"; only "designed toward" / "mapped to."
- The **MCP wedge** (`mcp_inspector.py` / `mcp_gateway.py`) internals, an
  interlock for a separate GTM effort.

## Consequences

- CI gains an orphan guard: any module under `modules/` with zero inbound edges
  fails the build unless allowlisted. The allowlist starts with the 7 currently
  orphaned modules and empties as they are cut or wired in.
- Endpoint paths that move keep a one-release deprecation shim + `Deprecation`
  header; `scripts/ci/openapi_route_guard.py` tracks the mapping.
- A near-term finding (see `SIMPLIFICATION_STATUS.md` D-2): several orphaned
  modules (`dpop`, `scopes`, `field_crypto`, `mtls*`, `secrets`) are better
  **wired in** to VERIFY/AUTHORIZE/federal than atticked — enrichment at low
  cost.

## Links

- Attic branch: `attic/2026-07` (from tag `v3.0.0-pre-simplification`)
- Guard: `scripts/ci/orphan_guard.py`
- Smoke CI: `.github/workflows/simplification-guards.yml`
