# TokenDNA — CLAUDE.md
_Last updated: 2026-04-26 (post-FAT merge — Demo Suite + Shadow Mode sprint active)_

## What This Project Is

TokenDNA is an AI agent identity security platform. It provides behavioral identity verification, trust graph analysis, blast radius simulation, and exploit intent correlation for AI agents operating in enterprise environments. It addresses three gaps that no major vendor closed at RSA 2026.

## Language & Stack

- Python 3.12, FastAPI, Postgres (primary), SQLite (dev/test fallback)
- `pytest` for tests, `ruff` for lint
- All modules live under `modules/`; API routes in `api.py`; tests in `tests/`

## Commands

```bash
# Run tests
pytest

# Run specific test file
pytest tests/test_trust_graph.py -v

# Lint
ruff check .

# Coverage
pytest --cov=modules --cov-report=term-missing
```

Coverage gate: **≥ 80%** on any module being touched. Do not land below this.

---

## Actual Current State (verified 2026-04-25)

### Shipped and wired to API

| Module | File | Lines | Tests | API Routes | Tier Gate |
|--------|------|-------|-------|------------|-----------|
| UIS Narrative Layer | `modules/identity/uis_narrative.py` | 499 | ✅ | wired | — |
| Agent Identity Passport | `modules/identity/passport.py` | 1091 | ✅ | wired | — |
| Verifier Reputation Network | `modules/identity/verifier_reputation.py` | 981 | ✅ | wired | — |
| Identity Deception Mesh | `modules/identity/deception_mesh.py` | 902 | ✅ | wired | — |
| Attestation Portability + OSS SDK | `modules/identity/portability.py` | 112+ | ✅ | wired | — |
| Conformance Registry | `modules/identity/conformance_registry.py` | 455 | ✅ | wired | — |
| UIS Trust Graph | `modules/identity/trust_graph.py` | 913 | ✅ | wired | — |
| Blast Radius Simulator | `modules/identity/blast_radius.py` | 401 | ✅ | wired | `ent.blast_radius` |
| Intent Correlation Engine | `modules/identity/intent_correlation.py` | 842 | ✅ | wired | `ent.intent_correlation` |

### Phase 5 / 6 — partially shipped (verified by audit 2026-04-25)

These existed before today's audit; CLAUDE.md previously listed them as "not started," which was wrong. Status reflects audit against the 7-item completeness checklist (routes wired, tier gate, test coverage of business logic, real algorithm, cross-module integration, audit logging, end-to-end exercised).

| Module | Lines | Tests | Routes | Gate | Status | Gaps |
|---|---|---|---|---|---|---|
| `policy_guard.py` | 569 | 48 / 102 asserts | 11 | `ent.enforcement_plane` | ✅ **shipped** Sprint A | — |
| `policy_advisor.py` | 990 | 48 / 90 asserts | 11 | `ent.enforcement_plane` | ✅ **shipped** Sprint A | — |
| `permission_drift.py` | 641 | 50 / ~115 asserts | 13 | `ent.behavioral_dna` | ✅ **shipped** Sprint A | — |
| `agent_lifecycle.py` | 679 | 30 / 37 asserts | 19 | `ent.behavioral_dna` | **~70%** *(deferred)* | no trust_graph integration; thin tests |
| `mcp_inspector.py` | 907 | 49 / ~150 asserts | 8 | `ent.mcp_gateway` | ✅ **shipped** MCP Sprint | — |
| `cert_dashboard.py` | 659 | 28 / 37 asserts | 17 refs | `ent.enforcement_plane` | **~55%** *(deferred)* | essentially CRUD; lifecycle automation missing |

### Production hardening — shipped (last 24 hrs)

- T0 hardening: secret gate, prod compose, DR/release docs (`#35`)
- T1 Postgres migration: phased modules (`#37`, `#42`); per-module psycopg DSN normalization (`#43`)
- T1 Alembic baseline (`#38`)
- T1 Helm chart + plain k8s manifests + deploy runbook (`#39`)
- T1 observability: Prometheus, OpenTelemetry, Sentry (`#36`)
- T1 SAML 2.0 SSO + SCIM 2.0 alpha scaffold (`#40`); SCIM PATCH + filter expressions + ReDoS hardening (`#44`)
- T1 Grafana dashboards + Prometheus alert rules (`#45`)
- T2 stress harness + performance SLOs (`#41`)
- CI prod-readiness gates (`#43`) — Postgres Integration, Helm Lint, Stress Smoke, Secret Gate now green on every PR
- PG paths: `delegation_receipt` (`#32`), `threat_sharing` (`#31`)
- UIS hardening: real schema validation, dedup, MCP protocol, stable event_id (`#33`)
- ZTIX honesty: simulate-as-demo labelling, periodic proof-of-control, record_proof auto-wire (`#34`)

### Sprint A — RSA narrative wedge (shipped 2026-04-25, PR #46)

- `trust_graph.record_policy_modification()` + `POLICY_SCOPE_MODIFICATION` (CRITICAL) + `PERMISSION_WEIGHT_DRIFT` (HIGH) anomaly detections.
- `AuditEvent` emission added to every state-changing path in `policy_guard`, `policy_advisor`, `permission_drift` (10 new event types in `AuditEventType`).
- `tests/test_rsa_narrative_e2e.py` proves Trust Graph anomaly → Policy Guard BLOCK → Policy Advisor suggestion → operator approval, end-to-end.
- 6 new edge-case tests added to `test_permission_drift.py`.
- Coverage on touched modules: `permission_drift` 99%, `policy_guard` 97%, `policy_advisor` 87%.

### MCP Inspector hardening sprint (shipped 2026-04-26, PR #47)

- `_find_subsequence_with_gap` — bounded-gap subsequence chain matcher with `CHAIN_PATTERN_MAX_GAP=3` + time-window gating via `CHAIN_PATTERN_WINDOW_SECONDS=3600`. Patterns carry confidence scores + matched positions.
- `_record_trust_graph_edge` — every `inspect_call` records an agent→tool edge into the central trust graph (best-effort; failures don't block inspection).
- `MCP_CALL_INSPECTED`, `MCP_VIOLATION_DETECTED`, `MCP_CHAIN_PATTERN_MATCHED`, `MCP_VIOLATION_RESOLVED` audit events emitted on every state-changing path.
- 16 new tests covering subsequence matcher, time-window gating, trust_graph integration, audit emission.
- Coverage: `mcp_inspector` 97% (up from ~65% baseline).

### Sprint B — Demo Polish + Runtime Risk Engine packaging (shipped 2026-04-26, PR #48)

- `BlastRadiusResult.recent_anomalies_in_blast` + `recent_mcp_violations_in_blast` — single API call surfaces live Trust Graph anomalies + open MCP violations attached to nodes inside the blast set.
- 5 new built-in Intent Correlation playbooks tying Sprint-A and MCP signals into kill chains (RSA gap 1, RSA gap 2, MCP read→exfil, MCP privilege ladder, multi-vector finale). Total: 15 → 20.
- `scripts/demo_runtime_risk_engine.py` — replayable, idempotent 10-min demo arc covering all seven scenes (baseline → drift → self-mod → MCP chain → deception → blast radius → verdict).
- README rewritten to lead with the Runtime Risk Engine pitch, three RSA gaps closed, integrated detection loop diagram, commercial tier map.

### FAT — Federated Agent Trust (shipped 2026-04-26, PR #49)

- `modules/identity/federation.py` (new) — handshake + mutual trust + revoke lifecycle. Two SQLite tables (PG-compatible). HMAC-SHA256 signed offers. Glob-style accepted_scope matching.
- `trust_graph.crosses_org` edge type + `record_cross_org_action` + `CROSS_ORG_ACTION_WITHOUT_HANDSHAKE` (CRITICAL) anomaly.
- `policy_guard` `CONST-06`: cross-org action without dual attestation → BLOCK. Fail-closed.
- 7 new `AuditEventType` values (federation handshake / trust / cross-org).
- `ent.federation` tier gate (Enterprise).
- Demo Act 2 (scenes 8-10): handshake → cross-org BLOCK → cross-org ALLOW.
- Coverage: `federation.py` 94%; full suite 1664/1664 pass.

### What is NOT done yet

#### Demo Suite v2 + Shadow Mode trial (ACTIVE)
Built per the data-sourcing strategy from the Sprint-B-end conversation. Turns TokenDNA from "demo arc with no backdrop" into "30-day operational environment a sales engineer can drive live."

- `scripts/demo_seed_v2.py` — generates ~30 days of patterned UIS history for ~50 Acme + ~20 Beta agents with realistic distributions: auth events with diverse IP/ASN, drift baselines, prior policy violations, honeytokens, intent_correlation matches, federation handshake established.
- `data/demo_fixtures/` — committed curated samples (no external API key requirements): MITRE ATT&CK technique subset, IP geo samples (no MaxMind dep), agent archetype templates, multi-stage attack chain templates.
- `modules/product/shadow_mode.py` (new) — observe-only mode toggle + connector framework + "what we found" report generator. Lets a prospect run TokenDNA against their real audit logs in pure observe mode for 14 days.
- `scripts/shadow_trial_report.py` — CLI that renders the trial report from existing audit events + violations + drift alerts.
- `docs/demo/RUN_DEMO.md` — pre-flight + step-by-step walkthrough for spinning up and running the demo.
- Tests for everything new.

**Done when:** `scripts/demo_seed_v2.py` produces a fresh deployment with 30 days of realistic operational history; `shadow_mode.py` ingests real audit-log JSONL without taking enforcement actions; `RUN_DEMO.md` walks a non-engineer through clone → install → seed → run; full suite green.

#### Reasoning Attestation (DEFERRED — separate future feature)
Identified during Sprint B as the #1 moat-widening opportunity. Captures `WHO + WHAT + WHEN + WHY` (prompt context, model identifier, reasoning trace) for every agent action as a signed bundle. Required for EU AI Act / GDPR Art. 22 / NIST AI RMF compliance. Will be its own sprint after Demo Suite + Shadow Mode lands.

#### Modules deferred to post-customer (or lighter post-Sprint-B cycle)
- `agent_lifecycle.py` — ghost-agent enforcement; needs trust_graph integration to be production-grade. Low moat cost (table-stakes feature).
- `cert_dashboard.py` — currently CRUD only; "Adaptive lifecycle automation" promised in old roadmap is missing. Low moat cost (CRUD store is sufficient for SOC 2 evidence at sale time).

---

## Active Roadmap

The plan below replaces the earlier `Trust Graph → 5-1 → ... → 6-2` linear sequence. Sprint A finishes the RSA narrative wedge; the MCP Inspector hardening sprint protects MCP positioning before it becomes a competitive liability; Sprint B packages the demo arc.

### Sprint A — Finish the RSA narrative wedge — ✅ DONE (PR #46, merged 2026-04-25)

All 5 items shipped (anomaly detections, audit emission, drift algorithm tests, RSA E2E integration test, buffer used for coverage hardening). 1605/1605 tests pass on `main`.

### MCP Inspector hardening sprint — ✅ DONE (PR #47, merged 2026-04-26)

All 5 items shipped (chain pattern matcher with bounded-gap subsequence matching + confidence scoring, trust_graph agent→tool edge emission, MCP_* audit events, 16 new tests bringing coverage to 97%).

### Sprint B — Demo polish + RSA Runtime Risk Engine packaging — ✅ DONE (PR #48, merged 2026-04-26)

All 4 items shipped (live blast radius enrichment, 5 new playbooks, 10-min demo arc script, README repackaging). 1632/1632 tests pass on `main`.

### FAT — Federated Agent Trust — ✅ DONE (PR #49, merged 2026-04-26)

All 6 items shipped (federation module with handshake/accept/revoke, trust_graph crosses_org edge + anomaly, policy_guard CONST-06, federation audit events, ent.federation tier gate, demo Act 2 with scenes 8-10). 1664/1664 tests pass on `main`.

### Demo Suite v2 + Shadow Mode trial — ACTIVE (started 2026-04-26 post FAT merge)

Built per the data-sourcing strategy from the Sprint-B-end conversation: turn TokenDNA from "demo arc with no backdrop" into "30-day operational environment a sales engineer can drive live" + give prospects a way to point the platform at their real audit logs in observe-only mode.

| # | Task | Est |
|---|------|-----|
| 1 | `data/demo_fixtures/` — curated MITRE techniques, IP geo samples, agent archetypes, attack chain templates (no external API keys) | 0.5 day |
| 2 | `scripts/demo_seed_v2.py` — generates ~30 days of patterned UIS history for ~50 Acme + ~20 Beta agents, federation handshake, drift baselines, prior violations, honeytokens | 2 days |
| 3 | `modules/product/shadow_mode.py` — observe-only toggle + connector framework + report generator | 1 day |
| 4 | `scripts/shadow_trial_report.py` — CLI render of trial findings | 0.5 day |
| 5 | `docs/demo/RUN_DEMO.md` — clone → install → seed → run walkthrough | 0.5 day |
| 6 | Tests + buffer | 0.5 day |

### Deferred (post-customer or future sprint cycle)

- **Reasoning Attestation** — the #1 moat-widening feature identified during Sprint B. Will be its own sprint after FAT lands. Captures `WHY` for every agent action (prompt context, model identifier, reasoning trace, alternatives considered) as a signed bundle. EU AI Act / GDPR Art. 22 / NIST AI RMF compliance prerequisite.
- `agent_lifecycle.py` ghost-agent offboarding hardening
- `cert_dashboard.py` lifecycle automation
- Phase 7+ (no scope yet — a live customer's feedback will reshape this)

---

## Sequencing (do not deviate)

```
Sprint A  →  MCP Inspector hardening  →  Sprint B  →  FAT  →  Demo Suite v2 + Shadow Mode
                                                                       │
                                                                       ▼
                                                                  Reasoning Attestation
                                                                  (next moat-widening
                                                                   feature; deferred
                                                                   to its own sprint)
                                                                       │
                                                                       ▼
                                                                  Hard pivot to non-engineering
                                                                  tracks (customer-facing
                                                                  dashboard, SOC 2, onboarding
                                                                  docs, GTM artifacts)
```

After Sprint B: agent_lifecycle and cert_dashboard get a lighter sprint cycle only if a customer signal demands them, otherwise they wait.

---

## Per-sprint workflow

For every sprint above:

1. Branch off `main`: `git checkout -b sprint/<short-name>`
2. Implement scope, write tests first (TDD per `~/.claude/rules/common/testing.md`)
3. Run `pytest --cov=modules --cov-report=term-missing` — confirm ≥80% on every touched module
4. Open PR with descriptive title; wait for full CI suite (Postgres Integration, CodeQL, Stress Smoke, Helm Lint) to go green
5. Squash-merge to `main` (matches existing convention)
6. **Update this CLAUDE.md** to reflect what shipped and what's next; commit the update directly to `main` (or as part of the same PR if scope-appropriate)
7. Move to the next sprint

---

## Rules

- **Do not touch shipped modules** (uis_narrative, passport, verifier_reputation, deception_mesh, portability, conformance_registry) unless the active sprint explicitly requires it.
- **No silently marking sprints complete.** A sprint is done when the criteria listed under that sprint are satisfied — not just "tests pass."
- **Postgres-compatible SQL only.** SQLite fallback exists for dev; all new queries must work on both. Use recursive CTEs for graph traversal — consistent with existing pattern. SQLite-only syntax (`INSERT OR IGNORE`, `ALTER TABLE ADD COLUMN` without `IF NOT EXISTS`) must be branched on `should_use_postgres()`.
- **Direct psycopg consumers must normalise the DSN.** Call `normalize_dsn_for_psycopg()` from `modules.storage.pg_connection` rather than passing `os.getenv("TOKENDNA_PG_DSN")` raw — the env var carries SQLAlchemy's `+psycopg` driver suffix that libpq does not understand.
- **Commercial tier gates** go in `modules/product/commercial_tiers.py` before the feature ships, not after. New `ent.*` keys reuse existing tier rank where possible (community / pro / enterprise).
- **RSA narrative is the pitch.** Every feature should map to one of the three RSA gaps or the demo arc. If it doesn't, it's not on the roadmap.
- **Every state-changing operation in a security module emits an `AuditEvent`.** No exceptions; this is a SOC 2 prerequisite.

---

## Reference Files

Full roadmap and sequencing rationale: `~/.openclaw/workspace-developer/memory/reference-tokendna-roadmap-revised-2026-04-17.md`
Phase 5 expansion detail: `~/.openclaw/workspace-developer/memory/reference-tokendna-phase5-expansion-2026-04-23.md`
