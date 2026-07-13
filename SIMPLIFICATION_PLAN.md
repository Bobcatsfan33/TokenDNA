# TokenDNA Simplification & Acquisition-Readiness — Claude Code Execution Prompt

**How to use this file:**
1. Save this file into the repo root as `SIMPLIFICATION_PLAN.md` and commit it.
2. Start Claude Code in the repo and say: *"Read SIMPLIFICATION_PLAN.md and execute the next incomplete phase. Follow the Operating Rules exactly."*
3. Run **one phase per session** (Phase 1 may take 2–3 sessions). Claude Code tracks progress in `SIMPLIFICATION_STATUS.md` (it creates this in Phase 0).
4. Review and merge the PR/commits at the end of each session before starting the next.

---

## MISSION

You are simplifying TokenDNA (this repo) from a 95,961-LOC, 416-file, 67-module runtime risk engine into a focused, user-friendly, acquisition-ready product. The product is three questions answered about any AI agent at runtime:

1. **VERIFY** — "Is this a legitimate agent identity, and are its credentials valid?"
2. **AUTHORIZE** — "Is it allowed to do what it's doing, be where it is, and go where it's going?"
3. **CONTAIN** — "Has it been compromised — and if so, what is the blast radius, and can I trace every downstream impact?"

Every module either serves one of these three questions, supports the infrastructure they run on, or gets moved to the attic branch. Target end state: ~60K LOC (incl. tests), ~38 identity modules, 9 routers, zero orphaned modules (CI-enforced), single-container zero-dependency default deployment, live 3-view console, IL5-target federal profile intact.

## OPERATING RULES (non-negotiable, apply to every phase)

1. **Nothing is ever deleted from history.** Before any removal, confirm the attic branch `attic/2026-07` exists (created in Phase 0). Removed code lives there.
2. **Verify before cutting.** A module may only be removed after YOU verify zero inbound imports at cut time: grep for its import across `api_routers/`, `modules/` (or `tokendna/` after rename), `serve.py`, `api.py`, `auth.py`, `tokendna_sdk/`, `scripts/`, and dynamic-import patterns (`importlib`, `__import__`, string module paths in config). A prior audit classified these modules as orphaned, but the audit is advisory — your at-cut-time grep is authoritative. If you find a live import the audit missed, STOP that cut, note it in `SIMPLIFICATION_STATUS.md`, and move on.
3. **One cut = one commit.** Each module removal is an individual commit (`cut: remove <module> (0 live imports, see SIMPLIFICATION_PLAN.md P1.<n>)`) so everything is bisectable and cherry-pickable.
4. **CI green at every commit.** Full `pytest` + `ruff check .` must pass after every commit. The three demo smoke paths (see Phase 0.4) must pass at the end of every session.
5. **Never break the SDK.** `tokendna_sdk/` is the product's best asset (published on PyPI, Apache-2.0). Do not modify it except where a phase explicitly says so. Its tests must always pass.
6. **Coverage floor:** repo-wide test ratio must not drop below the Phase-0 baseline. When you cut a module, cut its test file in the same commit.
7. **Honesty framing is preserved everywhere.** The README's "no independent audit / no production deployments / compliance = mappings and design intent, not certification" caveat must survive every docs change. Never write "compliant"; write "designed toward" / "mapped to."
8. **Federal track is KEPT.** FIPS gate, Dockerfile.fips, `TOKENDNA_COMPLIANCE_PROFILE` (target profile: `dod_il5`), control matrix, docs/ato/, STIG/OSCAL scripts, compliance_engine.py, compliance_posture.py, SAML/SCIM — none of these are cut. Owner requires DISA/CISA-grade posture at IL5 target for both government and commercial adoption.
9. **Update `SIMPLIFICATION_STATUS.md`** at the start and end of every session: phase, items done, deviations, blockers, next action.
10. **API compatibility:** any endpoint path that changes gets a deprecation shim keeping the old path alive for one release, emitting a `Deprecation` header. `scripts/ci/openapi_route_guard.py` must be updated with the mapping, never bypassed.
11. **Ask-before-acting exceptions:** if a phase instruction conflicts with what you find in the code, do the safe subset, document the conflict in `SIMPLIFICATION_STATUS.md`, and leave a `DECISION NEEDED:` line for the owner. Do not improvise scope.

---

## PHASE 0 — Safety Net (est. one short session)

- [ ] 0.1 Tag current main: `git tag v3.0.0-pre-simplification && git push --tags`. Create branch `attic/2026-07` from it and push.
- [ ] 0.2 Create `SIMPLIFICATION_STATUS.md` at repo root with: phase checklist mirroring this file, baseline metrics section, decisions log, deviations log.
- [ ] 0.3 Record baselines into `SIMPLIFICATION_STATUS.md`: total LOC (`find . -name '*.py' -not -path './.git/*' | xargs wc -l`), pytest pass/fail/skip counts, coverage %, file count, router count, `modules/identity/` file count, OpenAPI route count (from `scripts/ci/openapi_routes.json`).
- [ ] 0.4 Add three **demo smoke tests** to CI (a new workflow job or extension of ci.yml):
  - `python examples/quickstart/local_mode.py` exits 0
  - `DEV_MODE=true` server boot + `python scripts/demo_runtime_risk_engine.py` completes the full arc
  - SDK import + decorator example from `tokendna_sdk/README.md` runs
- [ ] 0.5 Write the **orphan-module CI guard**: `scripts/ci/orphan_guard.py`. It builds an import graph rooted at `api.py`, `serve.py`, `auth.py`, `api_routers/*`, `tokendna_sdk/*`, `scripts/*` (scripts count as roots so operational tooling keeps its imports), and fails CI listing any module under `modules/` with zero inbound edges. Ship it with an `ALLOWLIST` constant (initially populated with the currently-orphaned modules so CI stays green; Phase 1 empties the allowlist as it cuts).
- [ ] 0.6 Add ADR: `docs/adr/ADR-008-simplification.md` — one page: the three-questions thesis, what is being cut and why, link to attic branch.

**Exit criteria:** tag + attic pushed; status file committed; smoke tests + orphan guard in CI and green; baselines recorded.

---

## PHASE 1 — Dead Code Removal (est. 2–3 sessions)

Procedure per item: verify imports (Operating Rule 2) → `git rm` module + its test file(s) → remove from orphan-guard ALLOWLIST → full test suite → individual commit. If a router is listed, remove its mount in `api_routers/__init__.py` / `mount_all()` and update `scripts/ci/openapi_route_guard.py` expectations.

Cut list (audit-verified zero-live-import as of 2026-07-03; re-verify each):

- [ ] P1.1 `platform/` — entire directory (3,829 LOC). Contains stub duplicates of behavioral_dna/policy_guard/mcp_inspector/permission_drift/trust_graph plus unwired ingestion/alerts/findings/response/siem_forward/compliance/enterprise frameworks. Also remove `platform/tests/` and any CI references.
- [ ] P1.2 `modules/identity/federation.py` + `modules/identity/trust_federation.py` (1,348 LOC) + `tests/test_federation.py`, `tests/test_trust_federation.py` + `api_routers/federation.py` (470 LOC, verify what it actually imports first — if it imports other live modules, migrate any genuinely-used endpoint to admin router in Phase 3, else cut now).
- [ ] P1.3 `modules/identity/verifier_reputation.py` (986) + `api_routers/verifier.py` (356) + `tests/test_verifier_reputation.py`.
- [ ] P1.4 `modules/product/threat_sharing.py` + `modules/product/threat_sharing_flywheel.py` + `api_routers/threat_sharing.py` + related tests (`test_threat_sharing*.py`, `test_flywheel_calibration.py`) + `scripts/flywheel_calibration.py` (~1,100+ LOC).
- [ ] P1.5 `modules/identity/policy_bundles.py` (804) — module only. KEEP `api_routers/policy_bundles.py` if it imports policy_advisor/policy_guard (audit says it does); it merges into `authorize.py` in Phase 3.
- [ ] P1.6 `modules/identity/network_intel.py` (740) + `modules/identity/geo_intel.py` (204) + tests. KEEP `threat_intel.py` (20 live imports).
- [ ] P1.7 `modules/identity/cert_dashboard.py` (869) + `tests/test_cert_dashboard*.py`. Certificate lifecycle endpoints stay in `api_routers/certs.py`.
- [ ] P1.8 `modules/identity/honeypot_mesh.py` (497) + `modules/identity/hvip.py` (294) + tests. NOTE: check `tests/test_edge_enforcement_honeytoken.py` — if edge_enforcement has a honeytoken dependency on honeypot_mesh, keep the honeytoken primitive by inlining what edge_enforcement needs, cut the rest.
- [ ] P1.9 `modules/identity/compliance.py` (440, legacy) + `tests/test_compliance.py`. KEEP compliance_engine.py + compliance_posture.py. Migrate any api_routers/compliance.py imports of the legacy module to the engine/posture equivalents first.
- [ ] P1.10 `modules/identity/campaign_correlation.py` (292) + `api_routers/campaigns.py` (64) + tests.
- [ ] P1.11 `modules/identity/certificate_transparency.py` (271) — **CONFLICT FLAGGED**: audit says 0 imports, but HANDOFF doc claims transparency-log endpoints exist. Grep `api_routers/certs.py` and `api_routers/identity_surface.py` for transparency. If wired: KEEP (it's part of the trust-authority story). If truly unwired: cut.
- [ ] P1.12 Small stubs: `session_graph.py` (213), `schema_registry.py` (124), `siem_schema.py` (164), `ml_model.py` (162), `async_pipeline.py` (36), `policy_export.py` (168) + `api_routers/policy_export.py` (66) + tests for each.
- [ ] P1.13 `collector/` — move to attic (2,701 LOC): confirm nothing outside `collector/` imports `tokendna_collector`, remove directory, remove its CI jobs/Dockerfile references. Note in attic README: "standalone telemetry collector; agent telemetry arrives via SDK/UIS in the simplified product; revisit post-acquisition."
- [ ] P1.14 Sweep `scripts/` for now-dead helpers referencing cut modules (e.g., anything importing threat_sharing/verifier_reputation) — cut or fix each.
- [ ] P1.15 Attic README: on `attic/2026-07`, add `ATTIC.md` indexing everything parked (module → one-line purpose → why parked → LOC). This document is diligence-facing; write it as "validated R&D options," not scraps.
- [ ] P1.16 Issue triage: for all 19 open GitHub issues, close any that reference cut features with comment "moved to attic/2026-07, see ATTIC.md"; label the rest with target phases.

**Exit criteria:** ~15,700 LOC removed/relocated; orphan-guard ALLOWLIST empty except items explicitly kept; suite + smoke tests green; LOC delta recorded in status file.

---

## PHASE 2 — Consolidation & Wiring the Kill Path (est. 2 sessions)

- [ ] P2.1 **Unify revocation (most important item in the whole plan).** Create `modules/identity/revocation.py` consolidating `revocation_bus.py` (440), `idp_revocation.py` (180), `session_revocation.py` (27), `mcp_revocation.py` (37): a single `RevocationBus` with three backends (IdP token revoke, session revoke, MCP server revoke) and an audit event per action. Delete the four originals. Wire it into `api_routers/kill.py` (which currently imports NONE of them). Add e2e test: seed demo compromise → one revoke call → assert passport revoked + sessions invalidated + MCP access cut + trust_graph edge marked + audit chain entry.
- [ ] P2.2 **TraceReport.** New orchestration (~400 LOC, no new algorithms) composing `blast_radius.py` (affected sets) + `delegation_receipt.py` (who delegated to whom) + `trust_graph.py` (edges) + `uis_narrative.py` (English annotations) into a time-ordered `TraceReport`: list of `(timestamp, agent, credential, action, resource, evidence_pointer)` from the anomaly window outward. Expose via the contain endpoint (P2.4). Unit tests against demo fixtures in `data/demo_fixtures/`.
- [ ] P2.3 **Micro-module merges** (each an individual commit, preserve public function signatures via re-export or update call sites): `attestation.py` (151) → into `attestation_store.py`; `uis_validator.py` (229) → into `uis_protocol.py`; `scoring.py` (140) + `token_dna.py` (162) → new `pipeline.py`. Update the many import sites (scoring has 21, token_dna 20 — do this mechanically and run tests after each merge).
- [ ] P2.4 **Flagship endpoints.** New `api_routers/` additions (thin orchestration, no business logic):
  - `POST /v1/verify` — input: agent credential/passport/DPoP proof. Calls passport validation + attestation check + certificate_status + proof_of_control. Output: **verdict object** (schema below).
  - `POST /v1/authorize` — input: agent_id + action + resource + destination. Calls abac + policy_guard + enforcement_plane + permission_drift. Output: verdict object with policy clause + drift evidence in `reasons[]`.
  - `GET /v1/contain/{agent_id}` — calls trust_graph anomalies + behavioral_dna drift + mcp_inspector chain hits + blast_radius; returns verdict + `blast_radius{affected_agents[], affected_resources[], trace[]}` (the TraceReport).
  - `POST /v1/contain/{agent_id}/revoke` — executes P2.1 RevocationBus; returns post-containment verdict.
  - Verdict schema (Pydantic, shared): `{agent_id, verdict: ALLOW|STEP_UP|BLOCK|REVOKE, confidence: float, reasons: [str], evidence: [dict], blast_radius?: {...}, recommended_action: str}`. Reuse existing tier→HTTP mapping (200/202/403/401).
- [ ] P2.5 **Storage defaults.** Make ClickHouse optional: default UIS event store on Postgres/SQLite (`uis_store.py` is already dual-backend — make the ClickHouse path activate only when `CLICKHOUSE_URL` is set). Make Redis optional: add in-process LRU+TTL fallback in `cache_redis.py` (~150 LOC) used when `REDIS_URL` unset; log a startup warning that it's single-process only. Acceptance: `DEV_MODE=true python serve.py` works on a machine with no Postgres, no Redis, no ClickHouse; full test suite passes in both modes (add a no-services CI job).

**Exit criteria:** kill path real and e2e-tested; TraceReport rendering in demo script output; 67 → ~38 files in modules/identity; zero-dependency boot in CI.

---

## PHASE 3 — API Surface: 31 Routers → 9 (est. 1–2 sessions)

Consolidation map (absorb = move endpoint functions, keep old paths via deprecation shims, update `openapi_route_guard.py` mapping):

| New router | Absorbs |
|---|---|
| `verify.py` | passport.py, certs.py, discovery.py, identity parts of agents.py, the P2.4 /v1/verify |
| `authorize.py` | policy_guard.py, policy_suggestions.py, enforcement.py, policy_bundles.py, /v1/authorize |
| `contain.py` | kill.py, intel.py, graph/anomaly queries from identity_surface.py, /v1/contain |
| `agents.py` | agent lifecycle, delegation.py, workflow.py |
| `mcp.py` | unchanged (gateway + inspector — the wedge product; do not disturb) |
| `compliance.py` | unchanged (evidence, posture, profile status) |
| `admin.py` | enterprise.py, license.py, product.py, siem.py, assets.py, retrieval.py, surviving misc.py endpoints |
| `console.py` | console.py + demo.py |
| `public.py` | uis spec, oss onboarding, health/version (from misc.py / identity_surface.py) |

- [ ] P3.1 Execute the map one target-router at a time; each is a commit. `misc.py` (892 LOC) is **dissolved**: every endpoint is either claimed by a target router or deleted with justification in the commit message. `identity_surface.py` (990 LOC) finishes its decomposition.
- [ ] P3.2 Deprecation shims: old path → 307/alias to new path + `Deprecation` header; document sunset in CHANGELOG.md.
- [ ] P3.3 Regenerate `docs/openapi.yaml` + `docs/api/` (`scripts/generate_api_reference.py` exists); update `scripts/ci/openapi_routes.json`.
- [ ] P3.4 SDK check: run all `tokendna_sdk/tests/`; if the SDK calls any moved path, point it at the new path and keep shim coverage for released SDK versions.

**Exit criteria:** 9 routers mounted; route-guard green with full old→new mapping; SDK tests green; API reference regenerated.

---

## PHASE 4 — Repo Hygiene, Naming, README (est. 1 session)

- [ ] P4.1 **README rewrite.** First screen: the three questions verbatim, a 60-second quickstart (`pip install tokendna-sdk` → `tokendna demo`), placeholder for console GIF, honest status paragraph (PRESERVE the no-audit caveat). Move RSA-2026 gap table into a "Why these detections" section below the fold. Remove "Aegis Security" branding repo-wide (grep it). Architecture diagram becomes: Client → TokenDNA API → optional stores; the Cloudflare edge worker appears only as an optional pattern.
- [ ] P4.2 **Docs relocation to attic** (they are data-room material, not repo content): `HANDOFF_TOKENDNA_ROADMAP_EXECUTION.md`, `docs/marketing/`, `docs/partners/`, `docs/EXPANSION_FEATURES.md`, `docs/OSS_PAID_BOUNDARY_MATRIX.md`. Commit them to `attic/2026-07` under `dataroom/` before removing from main.
- [ ] P4.3 **Keep and surface:** `docs/adr/` (add nothing, remove nothing), SECURITY.md, sbom.json, CHANGELOG.md, quickstart, integration guides. Add a docs index page.
- [ ] P4.4 **Package rename `modules/` → `tokendna/`** — mechanical: `git mv`, rewrite imports repo-wide, update pyproject/Dockerfiles/Makefile/alembic/env.py/CI. One commit. Full suite after. (If this proves riskier than expected mid-session, defer to its own session; do not half-land it.)
- [ ] P4.5 CHANGELOG entry drafting the v3.1.0 narrative: "Focused the product on verify/authorize/contain; removed N LOC of unwired code to attic; single-container default; 9-router API."

**Exit criteria:** fresh-clone reader reaches "what is this + how do I try it" in one screen; no marketing/strategy docs on main; rename landed with green CI.

---

## PHASE 5 — Console, CLI, Hosted Demo (est. 2–3 sessions)

- [ ] P5.1 **Console skeleton.** Replace `dashboard/` with `console/`: one small React SPA (reuse `dashboard/static/vendor/react*.js` and `trustgraph-engine.js` — the renderer is real; the fixtures are not). No build system beyond what exists; keep it servable by FastAPI static mount. Three views only:
  - **Fleet (VERIFY):** agent table — identity status, passport validity, attestation freshness, last-verified. Row click → verdict detail. Source: `/v1/verify` + agents endpoints.
  - **Policy (AUTHORIZE):** per-agent permissions, drift indicators (permission_drift z-scores), policy_advisor suggestions with approve action (reuse the operator-approval flow from `scripts/demo_runtime_risk_engine.py`). Source: `/v1/authorize` + authorize router.
  - **Incidents (CONTAIN):** anomaly feed → incident → blast-radius graph (trustgraph renderer, live data) + TraceReport as time-ordered narrative sidebar → Revoke button → post-containment state.
- [ ] P5.2 Delete `trustgraph-fixture.js` / `workflow-fixtures.js` once live-data parity is reached; demo data comes from `scripts/demo_seed_v2.py` through the real API, never hardcoded in JS.
- [ ] P5.3 **CLI verbs** in `tokendna_sdk/cli.py` (this is the sanctioned SDK change): `tokendna verify <agent>`, `tokendna check <agent> --action X --resource Y`, `tokendna trace <agent>` — thin wrappers over the /v1 endpoints, with local-mode fallbacks where sensible. Keep existing demo/status/baseline verbs. Add tests mirroring existing CLI tests.
- [ ] P5.4 **Hosted demo.** Use `Dockerfile.railway` + `serve.py` SEED_ON_START + the existing password gate; deploy config committed (owner performs the actual deploy/DNS). Acceptance script: from README link → Incidents view → watch a blast-radius trace, under 90 seconds.
- [ ] P5.5 Record a terminal-cast / GIF of the Incidents trace for the README placeholder (use `scripts/demo_launch.sh` arc).

**Exit criteria:** console renders all three views against a live local server with seeded data; fixtures deleted; CLI verbs shipped with tests; deploy config ready.

---

## PHASE 6 — Deployment Tiers + Federal Consolidation (est. 1 session)

- [ ] P6.1 **Deployment tiers doc** (`docs/DEPLOYMENT.md`): Tier 1 pip/single-container SQLite zero-deps (evaluation); Tier 2 compose + Postgres + Redis (team); Tier 3 Helm + Postgres + Redis + ClickHouse + SAML/SCIM (enterprise); Tier 4 `deploy/federal/` FIPS + IL5 profile (regulated). README shows Tier 1 only. Compose gets `--profile full` for ClickHouse/Grafana; default profile app-only.
- [ ] P6.2 Move `edge/` → `examples/edge-enforcement/` with a README framing it as an optional pattern; update `tests/test_edge_parity.py` paths or mark the parity suite as example-scoped.
- [ ] P6.3 **Federal home:** create `deploy/federal/` (Dockerfile.fips, cert rotation scripts) and consolidate `compliance/` as the single federal index: `COMPLIANCE.md` linking control_matrix.json, docs/ato/* (SSP, POA&M template, customer responsibility matrix, conmon plan), stig_evidence.py, generate_oscal.py, collect_ato_evidence.py.
- [ ] P6.4 **IL5 profile CI test:** one integration test boots the app with `TOKENDNA_COMPLIANCE_PROFILE=dod_il5` (+ `REQUIRE_FIPS` asserted or mocked per existing test_fips_gate.py pattern) and asserts every profile gate engages.
- [ ] P6.5 **IL5 gap register** (`compliance/IL5_GAP_REGISTER.md`): no 3PAO assessment, no pen test, no sponsoring agency/ATO; IL5 US-persons + dedicated-infrastructure requirements documented as deployment-owner responsibilities (cross-link customer responsibility matrix). Frame: converts an unverifiable claim into a costed roadmap.

**Exit criteria:** four tiers documented; IL5 profile boots under CI; single federal index page; edge relocated.

---

## FINAL VERIFICATION (last session)

- [ ] V.1 Fresh-clone test: clean venv, follow README exactly, reach first verdict < 5 min.
- [ ] V.2 Metrics delta into `SIMPLIFICATION_STATUS.md`: LOC, files, modules, routers vs. Phase-0 baseline. Targets: ~60K LOC, ~38 identity modules, 9 routers, 0 orphans, test ratio ≥ baseline.
- [ ] V.3 Full e2e: seed → verify → authorize → simulated compromise → contain → trace → revoke → post-state, via curl AND via console, both from smoke CI.
- [ ] V.4 Grep sweeps: no "Aegis", no "compliant" without "mapping/designed toward", no references to cut modules in docs, no fixture JS.
- [ ] V.5 Tag `v3.1.0`, update RELEASES.md, write release notes from the P4.5 CHANGELOG narrative.

## DEFINITION OF DONE (all simultaneously true)

1. Stranger: `pip install tokendna-sdk && tokendna demo` → verdict < 5 min; hosted demo → blast-radius trace < 90 sec.
2. Every module reachable from the live import graph — CI-enforced, empty allowlist.
3. Three questions ↔ three endpoints ↔ three console views ↔ three README sentences, 1:1:1:1.
4. Compromise→containment real: one call revokes across IdP/session/MCP, trace shows it, e2e-tested.
5. Zero external services by default; IL5 profile boots under CI with FIPS gate asserted.
6. 31→9 routers, 67→~38 identity modules, ~96K→~60K LOC, test ratio held.
7. Strategy/marketing docs off main (in attic `dataroom/`); ATTIC.md indexes everything parked.

## CONTEXT FOR CLAUDE CODE (read once)

- Repo: `Bobcatsfan33/TokenDNA`, Python 3.12, FastAPI, pytest, ruff. Existing CLAUDE.md has commands and an 80% per-touched-module coverage gate — honor it, but know its module status tables are partially stale; this plan supersedes its roadmap.
- `api.py` is frozen at ~205 LOC by a CI ratchet (`scripts/ci/api_monolith_ratchet.py`) — never grow it; new endpoints go in routers.
- The prior audit (2026-07-03) that produced the cut list traced imports from `api_routers/` only. Your at-cut-time verification must be broader (Rule 2).
- Owner constraints: solo maintainer + AI tooling; federal/IL5 track retained; BUSL-1.1 licensing untouched; SDK stays Apache-2.0; honesty framing sacred.
- Interlock: a separate GTM plan launches an extracted MCP-inspector wedge tool and a hosted demo — Phases 1–5 here are its prerequisites. Do not refactor `mcp_inspector.py`/`mcp_gateway.py` internals beyond what phases specify.
- When in doubt: smaller diff, individual commit, note it in `SIMPLIFICATION_STATUS.md`, keep CI green.
