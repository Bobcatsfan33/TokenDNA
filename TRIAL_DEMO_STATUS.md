# Trial / Demo — Status

Progress tracker for the self-serve trial + hosted-demo mission. Updated at the
start and end of every session.

- **Current phase:** T0 — Trial Scaffold & Mode Switch (IN PROGRESS)
- **Session status:** Core mode-switch landed and prod-safe. `TOKENDNA_TRIAL_MODE`
  flag + `modules/trial/` guard + conditional `api_routers/trial.py` +
  guardrail test. Prod surface unchanged when off (CI-enforced).
- **Next action:** finish T0.4 (`.env.trial.example`, `make trial-up/reset`),
  T0.5 (`deploy/trial/docker-compose.trial.yml`), then T1 (trial license).

## Operating rules (non-negotiable)
Trial ≠ prod (all behind `TOKENDNA_TRIAL_MODE`, default false). **DEV_MODE is NOT
trial mode** — trial keeps real OIDC on, DEV_MODE bypasses it. Their data stays
theirs (single-tenant, local volume, no phone-home). Safe-by-default (shadow/
observe via `shadow_mode.py`). One-command up/reset. Show the license gates, don't
remove them (issue a real trial key; label Enterprise views). CI green + honesty
framing preserved. Secrets from env/mounted files only.

## Phase checklist
- [~] **T0 — Scaffold & mode switch**
  - [x] T0.1 `TRIAL_DEMO_STATUS.md`
  - [x] T0.2 `TOKENDNA_TRIAL_MODE` in `config.py` + `modules/trial/{__init__,guard}.py` (`trial_enabled()`, `require_trial()`)
  - [x] T0.3 `api_routers/trial.py` mounted ONLY when `trial_enabled()` (route guard runs trial-off, so trial routes never enter the snapshot — no guard change needed)
  - [ ] T0.4 `.env.trial.example` + `make trial-up` / `make trial-reset`
  - [ ] T0.5 `deploy/trial/docker-compose.trial.yml` (single app + one data volume; SQLite default — see DECISION T0.5)
  - [x] T0.6 guardrail test (`tests/test_trial_mode.py`): trial off ⇒ no `/trial/*` + surface == snapshot; trial on ⇒ only adds routes
- [ ] T1 — Trial license issuance (⚠ external dep: private license server)
- [ ] T2 — Connect their IdP (OIDC)
- [ ] T3 — Import their data
- [ ] T4 — Guided tour on their data
- [ ] T5 — Hosted shared demo + packaging
- [ ] V — Final verification

## Decisions & DECISION NEEDED
- **T1.3 (recommend self-serve):** trial-key delivery — bundle a key vs. self-serve
  fetch from the license server. Recommend **self-serve fetch** (captures the
  lead's email). `DECISION NEEDED` from owner.
- **T0.5:** compose storage — SQLite single-container default. This depends on
  simplification **Phase 2 (storage optional)**, which is NOT done yet. Ship a
  minimal Postgres service now, `DECISION` to slim to SQLite-only once Phase 2 lands.
- **T2.1:** IdP-config encryption at rest via `field_crypto`. Per simplification
  D-2, `field_crypto` is an orphan slated to be **wired in federal-scoped**. If not
  wired when T2 lands, `DECISION` whether to wire it here or store plaintext-in-volume
  with a warning.
- **T5.5 (recommend on for hosted):** lead-capture form on the trial-key request.

## External dependencies (track here)
- **Private license server (separate repo).** T1.1 (add `POST /trial` issuance:
  tier=enterprise, all `ent.*`, exp=now+14d, org="TRIAL") and **T1.4 (VITAL:
  catalog sync** — retire `ent.federation`, redefine `ent.enforcement_plane` after
  cert_dashboard removal; trial "all features" set must == post-simplification
  `COMMERCIAL_FEATURES` in `modules/product/commercial_tiers.py`) must be done
  there. As of now this repo has **no license-server checkout** and the licensing
  Session-2 scaffold was never created — `DECISION NEEDED`: create it.

## Cross-mission dependencies (simplification)
- The plan's flagship endpoints `/v1/verify|authorize|contain` do NOT exist yet
  (simplification Phase 2.4). Until then, the trial tour uses the current working
  endpoints: `/api/policy/guard/evaluate`, `/api/drift/record`, `/api/mcp/inspect`,
  `/api/simulate/blast_radius`, `/api/abac/evaluate`.
- Tamper-evident `TraceReport` (Phase 2.2) — the T4.2 "money screen" — is not built
  yet. T4 depends on it.
- Simplification Phase 1 is mid-flight (5 clean cuts landed; behavioral-layer
  excision is the next step). Keep trial code additive and flag-isolated so the two
  missions don't collide.
