# Simplification — Status

Progress tracker for `SIMPLIFICATION_PLAN.md`. Updated at the start and end of
every session (Operating Rule 9).

- **Current phase:** Phase 0 — Safety Net
- **Session status:** Phase 0 COMPLETE (pending PR review/merge)
- **Next action:** owner reviews/merges the Phase 0 PR + the three in-flight PRs
  (#142, #143, #145), then start Phase 1 (Dead Code Removal). See Decision D-4.

---

## Phase checklist

- [x] **Phase 0 — Safety Net**
  - [x] 0.1 tag `v3.0.0-pre-simplification` + branch `attic/2026-07` (both pushed)
  - [x] 0.2 `SIMPLIFICATION_STATUS.md` created
  - [x] 0.3 baselines recorded (below)
  - [x] 0.4 three demo smoke tests in CI (`.github/workflows/simplification-guards.yml`)
  - [x] 0.5 orphan-module guard (`scripts/ci/orphan_guard.py`)
  - [x] 0.6 ADR `docs/adr/ADR-008-simplification.md` + plan committed
- [ ] Phase 1 — Dead Code Removal
- [ ] Phase 2 — Consolidation & Kill Path
- [ ] Phase 3 — 31 → 9 routers
- [ ] Phase 4 — Repo hygiene, naming, README
- [ ] Phase 5 — Console, CLI, hosted demo
- [ ] Phase 6 — Deployment tiers + federal consolidation
- [ ] Final verification

---

## Baseline metrics (recorded 2026-07-04, main @ `4dafb9e`, tag `v3.0.0-pre-simplification`)

| Metric | Baseline | Target (end state) |
|---|---|---|
| Total Python LOC | **95,961** | ~60K (incl. tests) |
| Python files | **416** | — |
| `modules/identity/` files | **67** | ~38 |
| `api_routers/` files (with `APIRouter`) | **31 (29)** | 9 |
| OpenAPI route count | **331** | (surface preserved via shims) |
| pytest | **2204 passed, 0 failed, 0 skipped** | ≥ ratio held |
| Test files / functions | **141 / ~2117** | — |
| `modules/` coverage | **84%** (13,779 stmts, 2,264 missed) | ≥ 84% floor |

Measurement env: `/tmp/tdna-venv` (Python 3.13; repo `requires-python>=3.9`, CI
uses 3.12). Command: `pytest --import-mode=importlib --cov=modules tests
platform/tests collector/tests` with `PYTHONPATH=$PWD/platform:$PWD/collector`.

---

## Decisions

**D-1 — Orphan guard disagrees with the P1 audit cut-list (by design).**
The prior audit traced imports from `api_routers/` only. `orphan_guard.py` roots
the graph additionally at `scripts/*` and `tokendna_sdk/*` (Operating Rule 2 +
P0.5: "scripts count as roots"). Under that broader definition the P1 cut-list
modules (federation, verifier_reputation, threat_sharing, network_intel,
cert_dashboard, campaign_correlation, etc.) are **reachable** — the demo seeders
and harnesses (`scripts/demo_seed_gap.py`, `scripts/demo_seed_v2.py`,
`scripts/adversarial_harness.py`) import them. They are orphaned *from the
product* but not *from the repo*. **Implication for Phase 1:** cutting a P1
module requires cutting/updating its script importers in the SAME commit (P1.14
already anticipates this); only then does it become a true orphan the guard
enforces. Re-verify each P1 item with `orphan_guard.py --report` after removing
its script importers. Treat the guard (not the stale audit) as authoritative
(Rule 2).

**D-2 — The 7 genuine orphans are WIRE-IN candidates, not obvious attic.**
`orphan_guard.py --report` finds 7 modules with zero live inbound edges (only
their own tests import them): `modules.auth.scopes`, `modules.identity.dpop`,
`modules.security.{field_crypto, mtls, mtls_peer, mtls_server, secrets}`. These
are built + unit-tested capabilities that were never wired into the request
path. Several map directly onto the three-questions thesis and the retained
federal track: **dpop → VERIFY** (DPoP proof validation), **scopes → AUTHORIZE**,
**field_crypto / mtls* / secrets → federal posture (Rule 8)**. Recommendation:
in Phase 1/2, prefer WIRING THESE IN (enriches the product at near-zero new code)
over atticking them. Seeded into `ALLOWLIST` for now so CI is green; `DECISION
NEEDED` for the owner on wire-in vs. attic per module.

**D-3 — Phase 0 CI lives in a new workflow file.** Smoke tests + orphan guard are
in `.github/workflows/simplification-guards.yml`, not appended to `ci.yml`, so
they don't conflict with the three in-flight PRs that edit `ci.yml`.

**D-4 — Merge/close the in-flight PRs before Phase 1.** Open PRs #142
(efficacy-benchmark, edits ci.yml), #143 (release-hygiene: ci.yml,
release-docker.yml, publish.yml, CONTRIBUTING.md, adds ARCHITECTURE.md), #145
(README pointers) all touch files that Phases 3–4 rewrite heavily. Landing them
first avoids repeated rebase churn. `ARCHITECTURE.md` (#143) will also need a
refresh after the 31→9 router consolidation.

---

## Deviations

- **DEV-1:** Coverage measured on `modules/` only (the cut target) rather than
  whole-repo, and via the `/tmp/tdna-venv` Python 3.13 env (no repo venv exists;
  see the project's local-env note). Ratio floor tracked against 84%.
- **DEV-2:** ADR numbered **008** per the plan even though `docs/adr/` jumps from
  ADR-006 to 008 (no ADR-007 present). Left the gap; did not renumber.

---

## Blockers

None.
