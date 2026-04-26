# TokenDNA — CLAUDE.md
_Last updated: 2026-04-25 (post-Sprint A merge)_

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
| `policy_guard.py` | 569 | 48 / 102 asserts | 11 | `ent.enforcement_plane` | **~90%** | no audit-log emission |
| `policy_advisor.py` | 990 | 48 / 90 asserts | 11 | `ent.enforcement_plane` | **~85%** | no audit-log emission |
| `permission_drift.py` | 641 | 44 / 87 asserts | 13 | `ent.behavioral_dna` | **~80%** | thin algorithm test coverage (2 algo / 12 CRUD); no audit-log |
| `agent_lifecycle.py` | 679 | 30 / 37 asserts | 19 | `ent.behavioral_dna` | **~70%** | no trust_graph integration; thin tests |
| `mcp_inspector.py` | 907 | 33 / 50 asserts | 8 | `ent.mcp_gateway` | **~65%** | no trust_graph integration; chain pattern detection thin; no audit-log; biggest module / weakest tests |
| `cert_dashboard.py` | 659 | 28 / 37 asserts | 17 refs | `ent.enforcement_plane` | **~55%** | essentially CRUD; lifecycle automation missing; only 1 algorithm-test |

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
- 6 new edge-case tests added to `test_permission_drift.py` (boundary, zero baseline, out-of-window, cross-tenant, attestation mix, per-policy isolation).
- Coverage: `permission_drift` 99%, `policy_guard` 97%, `policy_advisor` 87%, `trust_graph` 71% headline (~91% on SQLite-reachable code; the rest is exercised by the Postgres Integration CI gate).

### What is NOT done yet

#### Sprint 2-3 — Demo Polish (not started)
- Connect Blast Radius visualization to live Trust Graph data
- Seed Intent Correlation with sample playbook library
- 10-minute demo arc: Blast Radius → Intent Feed → Deception Mesh catch
- Update README, API spec, docs — package as "TokenDNA Runtime Risk Engine"

#### Modules deferred to post-customer (or lighter post-Sprint-B cycle)
- `agent_lifecycle.py` — ghost-agent enforcement; needs trust_graph integration to be production-grade. Low moat cost (table-stakes feature).
- `cert_dashboard.py` — currently CRUD only; "Adaptive lifecycle automation" promised in old roadmap is missing. Low moat cost (CRUD store is sufficient for SOC 2 evidence at sale time).

---

## Active Roadmap

The plan below replaces the earlier `Trust Graph → 5-1 → ... → 6-2` linear sequence. Sprint A finishes the RSA narrative wedge; the MCP Inspector hardening sprint protects MCP positioning before it becomes a competitive liability; Sprint B packages the demo arc.

### Sprint A — Finish the RSA narrative wedge — ✅ DONE (PR #46, merged 2026-04-25)

All 5 items shipped (anomaly detections, audit emission, drift algorithm tests, RSA E2E integration test, buffer used for coverage hardening). 1605/1605 tests pass on `main`.

### MCP Inspector hardening sprint — ACTIVE (started 2026-04-25 post Sprint A merge)

`mcp_inspector.py` is at ~65% — biggest module, weakest tests. MCP is a 2025-2026 hot zone; deferring this sprint means a competitor could ship "MCP-aware identity security" first. Holding it before Sprint B (rather than after) so the demo can include a credible MCP story.

| # | Task | Est |
|---|------|-----|
| 1 | Add chain pattern detection — multi-call sequences that imply a forbidden composite operation | 2 days |
| 2 | Wire trust_graph integration — emit graph edges when MCP calls cross agent boundaries | 1 day |
| 3 | Add `AuditEvent` emission on every MCP call inspection + violation | 0.5 day |
| 4 | Test coverage to 80% — currently 33 tests / 50 asserts on a 907-line module | 1 day |
| 5 | Buffer | 0.5 day |

**Done when:** mcp_inspector reaches the same 7-item completeness bar as policy_guard.

### Sprint B — Demo polish + RSA Runtime Risk Engine packaging (1 week)

| # | Task | Est |
|---|------|-----|
| 1 | Live Blast Radius ↔ Trust Graph wiring (replace mocked simulation data with real graph queries) | 2 days |
| 2 | Seed Intent Correlation with playbook library (data-exfil, privilege escalation, lateral movement, etc.) | 1 day |
| 3 | 10-min demo arc script: Blast Radius → Intent Feed → Deception Mesh catch → MCP Inspector violation → policy_guard reject (live data, end-to-end) | 1 day |
| 4 | README + API spec + marketing site copy: package the integrated story as "TokenDNA Runtime Risk Engine" | 1 day |

**Done when:** demo arc runs reliably 5x in a row against a fresh deployment; README + landing-page copy match the demo; tier gates verified on all demo touchpoints.

### Deferred (post-customer or lighter sprint cycle)

- `agent_lifecycle.py` ghost-agent offboarding hardening
- `cert_dashboard.py` lifecycle automation
- Phase 7+ (no scope yet — a live customer's feedback will reshape this)

---

## Sequencing (do not deviate)

```
Sprint A  →  MCP Inspector hardening  →  Sprint B  →  hard pivot to non-engineering tracks
                                                       (customer-facing dashboard, SOC 2,
                                                        onboarding docs, GTM artifacts)
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
