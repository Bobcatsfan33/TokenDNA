# Simplification — Status

Progress tracker for `SIMPLIFICATION_PLAN.md`. Updated at the start and end of
every session (Operating Rule 9).

- **Current phase:** Phase 1 — Dead Code Removal (IN PROGRESS)
- **Session status:** Phase 0 merged (#146). Phase 1 started with the
  platform/+collector/ cut (P1.1, P1.13 — D-5). Collector extracted to its own
  archived repo `github.com/Bobcatsfan33/tokendna-collector`.
- **Next action:** **OWNER DECISION** on the legacy behavioral layer (see "Phase 1
  cut-list reality check" below) — most of the remaining audit cut-list is wired,
  not dead. The clean orphan removal is done through `policy_export`. Once the
  keep/cut calls are made, the follow-on is: legacy-layer removal (if cut, fused
  with Phase-3 `enterprise.py`→`admin.py`), then the decouplings (cert_dashboard,
  compliance, verifier, federation, honeypot) + demo-arc rebuild.

## Phase 1 progress + metrics delta

| Cut | Commit | LOC removed | Tests removed | Suite after |
|---|---|---|---|---|
| collector/ (P1.13) | `41bccdf` | 2,701 | 37 | 2167 pass |
| platform/ (P1.1) | `f7876f0` | 3,829 | 94 | 2073 pass |
| threat_sharing (+flywheel) (P1.4) | `d559706` | ~1,100 | 85 | 1988 pass |
| campaign_correlation (P1.10) | `13684a5` | ~360 | 12 | 1976 pass |

Route surface: 331 → 314 (threat-sharing + campaigns removed; snapshot re-baselined).

**Lessons (apply to every remaining cut):**
- `modules/storage/migrations.py` `INIT_TARGETS` is a **dynamic-import (importlib)
  registry** — a hidden product importer static grep misses (Rule 2). Candidates
  still in it: `cert_dashboard`, `verifier_reputation`, `certificate_transparency`,
  `network_intel`, `compliance`, `policy_bundles`, `trust_federation`,
  `honeypot_mesh`. Remove the entry in the same cut.
- Also check: `.github/workflows/ci.yml` import-verification list (`ml_model`,
  `session_graph`, `async_pipeline`), `tests/test_demo.py` seeded-count asserts,
  and `api_routers/enterprise.py` / `compliance_posture.py` importlib.
- **`verifier_reputation` DEFERRED:** it has a live product importer
  (`modules/identity/proof_of_control.py`, which is KEPT). Per Rule 2, not a clean
  orphan — needs proof_of_control decoupled first. `DECISION NEEDED`: inline what
  proof_of_control uses, or keep verifier_reputation.

- **Coverage re-baseline (D-5):** pre-cut `modules/` = 84% (13,779 stmts / 2,264
  missed, measured *with* platform+collector tests). **Post-cut `modules/` = 84%
  (13,889 stmts / 2,266 missed, backend-only).** New floor rule: **never below
  84% post-cut.** (The cuts removed their own code+tests, not `modules/`
  coverage, so the % held.)
- Running LOC delta: **-6,530** (95,961 → ~89,431 Python LOC).

## Sequencing override (owner-approved 2026-07-04)

The demo trio is pulled AHEAD of the full router consolidation because it is the
90-second demo and the acquisition centerpiece:

1. **RevocationBus** (P2.1) — one call revokes across IdP/session/MCP.
2. **Tamper-evident TraceReport** (P2.2) — each trace row chained to the existing
   hash-chained `modules/security/audit_log.py`, so the whole report is
   cryptographically verifiable ("evidence", not just "what happened").
3. **Incidents console view** (P5.1c) — anomaly → blast graph → trace → Revoke.

The 31→9 router consolidation (Phase 3) may slip a week or two behind this trio.
Phase 1 (dead-code removal) still runs first as the prerequisite for everything.

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

## Phase 1 cut-list reality check (IMPORTANT — needs owner decisions)

At-cut-time verification (Rule 2) shows the audit's remaining cut-list is **mostly
NOT dead code**. The audit traced `api_routers/` top-level reachability only; these
modules are in fact wired into kept code (`enterprise.py` legacy behavioral layer,
`misc.py`, `siem.py`, `certs.py`, `compliance_posture.py`) or into each other.
The genuinely-clean orphan removal is now essentially **done**:

**CLEAN — cut (done):** platform/, collector/, threat_sharing(+flywheel),
campaign_correlation, **policy_export** (`ecda322`).

**WIRED — NOT clean orphans (each is a product decision, not dead-code removal):**

| Module(s) | Wired into (kept) | Decision needed |
|---|---|---|
| `geo_intel`, `ml_model`, `session_graph`, `async_pipeline` (P1.12) | `api_routers/enterprise.py` — the legacy behavioral-analytics/JWT layer ("stolen-JWT detector" origin) | **Keep or cut the legacy behavioral layer?** It's not part of the verify/authorize/contain thesis, but it's live + tested. Cutting = gut those enterprise endpoints (overlaps Phase 3 `enterprise.py`→`admin.py`). |
| `network_intel` (P1.6) | `misc.py` (threat feed), `compliance.py`, `enterprise.py`, `intel.py` (13 uses) + INIT_TARGETS | Keep the network threat-intel feed, or cut the feed endpoints too? |
| `schema_registry`, `siem_schema` (P1.12) | `misc.py`/`identity_surface.py`; `siem.py` | Tied to misc/siem — resolve during Phase 3 dissolution of misc.py. |
| `cert_dashboard` (P1.7) | `certs.py` + `compliance_posture.py` (federal, KEEP) — 22 uses + INIT_TARGETS | Decouple `compliance_posture` first, or keep cert_dashboard. |
| legacy `compliance` (P1.9) | `compliance_posture`, `fips`, `feature_gates`, `metering`, `hvip`, `dpop` (7) | Migrate importers to `compliance_engine`/`compliance_posture` first (bigger). |
| `verifier_reputation` (P1.3) | `proof_of_control.py` (KEEP) + INIT_TARGETS | Inline what proof_of_control uses, or keep. |

**ARC-TOUCHING (doable, needs demo-arc rebuild + decoupling):**
- `honeypot_mesh` (P1.8) — demo scene 5 + **`edge_enforcement` product import** (honeytoken) + INIT_TARGETS. Inline the honeytoken primitive edge_enforcement needs, cut the rest, drop demo scene 5.
- `federation`+`trust_federation` (P1.2) — demo scenes 8-10 + **`policy_guard` CONST-06** + `agent_lifecycle` + INIT_TARGETS. Remove CONST-06, drop Act 2 from the arc.

**RECOMMENDATION:** the biggest lever is a single owner call — **keep or cut the
legacy behavioral-analytics layer** (`enterprise.py` + geo_intel/ml_model/
session_graph/async_pipeline/network_intel). If cut, it's ~1,500+ LOC and should
be done as its own decision, likely fused with the Phase-3 `enterprise.py`→
`admin.py` consolidation rather than piecemeal. The remaining decouplings
(cert_dashboard, compliance, verifier, federation, honeypot) are then a clean
follow-on. Continuing to force these as "dead-code" cuts would break the suite or
require gutting kept endpoints — out of scope for Phase 1 without these calls.

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

**D-2 — Orphan disposition (RESOLVED by owner 2026-07-04).** `orphan_guard.py
--report` finds 8 modules with zero live inbound edges (test-only). Per-module
verdict; each wire-in is timeboxed to ≤ 1 day, else a `DECISION NEEDED` line and
move on (enrichment must not eat the timeline):

| Module | Verdict |
|---|---|
| `modules.identity.dpop` | **WIRE into VERIFY** — proof-of-possession → evidence in the `/v1/verify` verdict. |
| `modules.auth.scopes` | **WIRE into AUTHORIZE** — scope eval → `reasons[]` in the authorize verdict. |
| `modules.security.field_crypto` | **WIRE, federal-scoped** — active under IL5/enterprise profiles for stored evidence + PII; NOT in the Tier-1 zero-dep default path. |
| `modules.security.{mtls, mtls_peer, mtls_server}` | **KEEP, tier-gated** — wire into `deploy/federal/` + Tier 3/4 with profile-gated activation; not in the default path (Tier 1 stays zero-config). |
| `modules.security.secrets` | **INVESTIGATE FIRST** (~30 min) — if referenced by prod config/compose or the T0 hardening path, wire tier-gated like mtls; if dead, attic. Log the finding. |
| `modules.identity.agent_assurance` | **FOLD into the `evaluate()`/Verdict core** (see D-6) — this is PR #144's verdict facade; reconcile, do not duplicate. |

**D-3 — Phase 0 CI lives in a new workflow file.** Smoke tests + orphan guard are
in `.github/workflows/simplification-guards.yml`, not appended to `ci.yml`, so
they don't conflict with the three in-flight PRs that edit `ci.yml`.

**D-4 — Merge in-flight PRs before Phase 1 (DONE 2026-07-04).** #145, #142, #143
squash-merged in that order; #144 (agent assurance verdict facade) also landed.
`ARCHITECTURE.md` will need a refresh after the 31→9 router consolidation.

**D-5 — platform/ + collector/ cut (owner signed off, intentional).** This
reverses the open-core split (PRs #80–85), a distribution-strategy bet; the
product decision is now two artifacts — server + SDK — and a legible repo for an
acquirer. Preserve, don't erase, the narrative:
  * `ATTIC.md` documents the split as a *validated architecture option* an
    acquirer could re-activate, with pointers to PRs #80–85.
  * `collector/` goes to its **own archived repo**, Apache-2.0 intact.
  * **Coverage:** re-baseline the floor immediately after these cuts; record the
    old and new denominators here. The rule becomes "never below the POST-cut
    baseline" (not the Phase-0 84%, which includes now-removed well-tested code).

**D-6 — Single `evaluate(question, subject) -> Verdict` core (approved, guard-railed).**
A thin orchestration facade (a dispatcher, NOT a framework) that the three `/v1`
endpoints, the SDK, the CLI, and the console all call. Pillar-module internals
are untouched; the P2.4 `Verdict` schema is unchanged. **Reconcile with PR #144's
`modules/identity/agent_assurance.py`** (the existing verdict facade) rather than
adding a parallel one. Hard guardrail: if the facade exceeds ~300 LOC or starts
wanting its own plugin/registry abstractions, STOP and leave a `DECISION NEEDED`.
One code path, zero cleverness.

**D-7 — Demo-smoke gate is load-bearing for Phase 1.** The demo arc (a Phase-0 CI
gate) exercises many to-be-cut modules via the seeders. Treat seeders/harnesses
as product surface: when a cut module is imported only by a seeder, update the
seeder in the SAME commit so the arc exercises kept modules only. The gate must
never go red; if a cut can't keep it green in one commit, split the commit —
never skip the gate. The end-state arc is rebuilt around the three questions
(baseline → drift → self-modification → MCP chain → blast radius → revoke →
trace), all on surviving modules.

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
