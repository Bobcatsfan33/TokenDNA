# TokenDNA — Architecture

A one-day onboarding map for an engineer (or an acquiring team) picking up this
codebase. It describes what runs, where the code lives, how a request becomes a
decision, how data is stored, and every gate CI enforces.

> Companion docs: `CLAUDE.md` (current state + roadmap), `docs/LICENSING.md`
> (entitlement boundary), `docs/BENCHMARK.md` (detection efficacy),
> `docs/operations/` (RUNBOOK, HA, incident response), `docs/api/` (OpenAPI).

## 1. What it is

TokenDNA is an AI-agent identity security platform: behavioral identity
verification, trust-graph analysis, blast-radius simulation, and exploit-intent
correlation for agents operating in enterprise environments. The runtime
"decision" is: given an agent action + its attestation + live signals, allow /
step-up / block, and record why.

## 2. Repository layout

| Path | What lives here |
|---|---|
| `api.py` | FastAPI app factory. **Frozen** at ~205 lines (CI ratchet); it only wires config, middleware, and calls `api_routers.mount_all`. |
| `api_routers/` | 31 domain routers (the decomposed API surface). New endpoints are born here, never in `api.py`. `__init__.py` holds `ALL_ROUTERS` + `mount_all`. |
| `modules/identity/` | The product core — 67 modules: UIS, passport, trust graph, drift, policy guard/advisor, MCP inspector, blast radius, intent correlation, federation, cert/attestation, kill-switch planes, etc. |
| `modules/security/` | Cross-cutting security: `audit_log`, `rbac`, `fips`, `mtls`, `field_crypto`, `headers`. |
| `modules/tenants/` | Multi-tenant context: `models` (Plan/TenantContext), `store`, `middleware` (`get_tenant`, DEV_MODE synthetic tenant). |
| `modules/product/` | Commercial layer: `commercial_tiers` (ent.* gates), `licensing` (signed-license entitlement boundary), `feature_gates`, `staged_rollout`. |
| `modules/storage/` | Storage gateway: `pg_connection` (DSN normalization; the only sanctioned DB entrypoint). |
| `collector/` | Apache-2.0 open-core edge collector (adapters → NormalizedEvent → transport). Separate pip package `tokendna_collector`. |
| `platform/` | BUSL-1.1 cloud ingestion + stream engines. Separate pip package `tokendna_platform`. |
| `tokendna_sdk/` | The pip-published SDK (`tokendna-sdk`), the only pip-installable part of the monorepo. |
| `edge/` | Edge (JS) enforcement worker — JWT → DPoP → revocation → drift-tier checks. |
| `dashboard/`, `landing/`, `console` | Operator UI + marketing landing + Cytoscape console. |
| `scripts/` | Ops + CI scripts: route guard, monolith ratchet, seeders, demo arc, adversarial + efficacy harnesses, OSCAL/STIG generators. |
| `alembic/` | Postgres migrations. |
| `tests/` | Backend test suite (2200+). `platform/tests`, `collector/tests` cover the sub-packages. |
| `.github/workflows/` | CI (`ci.yml`), image release (`release-docker.yml`), PyPI publish (`publish.yml`). |

## 3. The request → decision path (runtime loop)

```
   client / agent
        │  HTTP  (X-API-Key / bearer; DEV_MODE injects a synthetic tenant)
        ▼
   FastAPI app (api.py) ── middleware: tenant resolution, RBAC, headers
        │
        ▼
   api_routers/<domain>.py
        │  Depends(require_feature("ent.*"))  ← commercial entitlement gate
        │        └─ capped by signed license when TOKENDNA_LICENSE_ENFORCEMENT=enforce
        ▼
   modules/identity/<engine>
        │
        ├─ edge_enforcement.evaluate_runtime_enforcement()  ← the lean allow/step-up/block
        │      fast path; SLO = EDGE_DECISION_SLO_MS (default 5ms)
        │
        └─ detection engines (drift / policy_guard / mcp_inspector / …)
                 │  every state change emits an AuditEvent (SOC2 requirement)
                 ▼
           trust_graph  ← anomalies (POLICY_SCOPE_MODIFICATION, PERMISSION_WEIGHT_DRIFT,
                 │        MCP_CHAIN_PATTERN_MATCHED, CROSS_ORG_ACTION_WITHOUT_HANDSHAKE)
                 ▼
           intent_correlation  ← multi-step kill-chain playbook matching
                 ▼
           blast_radius  ← downstream-impact simulation over the trust graph
```

The three RSA-2026 scenarios TokenDNA leads with map onto this loop: permission
drift (`/api/drift/record`), policy self-modification (`/api/policy/guard/evaluate`,
CONST-01..06), and MCP tool-chain attacks (`/api/mcp/inspect`, bounded-gap
subsequence matcher). `docs/BENCHMARK.md` measures detection on all three.

## 4. Data flow: open-core ingestion split

Two Apache-2.0 / BUSL-1.1 layers exist alongside the monolith:

```
  cloud logs / IdP / MCP  ──► collector/ (Apache-2.0)
     Okta, CloudTrail,          BaseAdapter → NormalizedEvent → transport
     Azure Activity, DNS                │
                                        ▼
                              platform/ (BUSL-1.1)
     schema registry → dedup (tenant,event_id) → EventRouter → StreamEngine(s)
     (TrustGraph / BehavioralDNA / PermissionDrift / MCPChain / PolicyGuard)
                                        │
                                        ▼
                          Findings → AlertRouter → SIEM forwarders
                          (Splunk HEC / Datadog) + compliance reports
```

The engines under `platform/tokendna_platform/engines/*` currently DELEGATE to
the algorithms in `modules/identity/*` (disposition map in `platform/README.md`).

## 5. API surface discipline (T-1)

`api.py` is frozen; two CI gates protect the surface:

- **Monolith ratchet** (`scripts/ci/api_monolith_ratchet.py`) — `api.py` may only
  shrink. Any growth fails CI.
- **Route-surface guard** (`scripts/ci/openapi_route_guard.py`) — the externally
  visible route set is snapshotted in `scripts/ci/openapi_routes.json`. Adding an
  endpoint requires `--update` and a committed snapshot diff, so the surface can
  never change silently. Runs with `TOKENDNA_ENV=ci` (it sets `DEV_MODE=true`
  internally, which the deny-by-default guard requires — see §7).

## 6. Storage backends

- **Postgres is primary; SQLite is the dev/test fallback.** Every product module
  goes through `modules.storage.pg_connection` — a CI guardrail rejects any
  direct `sqlite3.connect` in `modules/` (only `pg_connection.py` may).
- Direct psycopg consumers call `normalize_dsn_for_psycopg()` (the env DSN
  carries SQLAlchemy's `+psycopg` suffix libpq doesn't understand).
- SQLite-only syntax must branch on the backend; graph traversal uses recursive
  CTEs (portable across both).
- Schema migrations live in `alembic/`.

## 7. Security boundaries you must not weaken

- **DEV_MODE deny-by-default (PR #140).** `DEV_MODE=true` bypasses ALL auth, so
  `config.py` hard-exits (SystemExit) at import unless the resolved environment
  (`TOKENDNA_ENV`, then `ENVIRONMENT`) is one of {dev, development, test, testing,
  local, ci}. Every local/CI command with `DEV_MODE=true` must export
  `TOKENDNA_ENV=ci` (or dev). Regression-guarded by `tests/test_dev_mode_guard.py`.
- **Licensing entitlement boundary.** `modules/product/licensing.py` verifies an
  Ed25519-signed `TDNA1.<payload>.<sig>` license offline. `commercial_tiers` caps
  the effective tier when `TOKENDNA_LICENSE_ENFORCEMENT=enforce` (default off).
  `TOKENDNA_LICENSE_ENFORCEMENT` gates commercial entitlement ONLY — never authn.
  The private signing key never enters the repo.
- **FIPS gate (SC-13).** No non-approved hash primitive for security in
  `modules/`; the federal image bakes `REQUIRE_FIPS=true` and fails closed
  (exit 78) off a validated host.
- **Audit on every state change.** Security modules emit an `AuditEvent` on every
  state-changing path (SOC2 prerequisite). Sink is `AUDIT_LOG_PATH`.

## 8. CI gate inventory

`.github/workflows/ci.yml` (required unless noted) plus release/publish flows:

| Gate | Job / file | Enforces |
|---|---|---|
| Lint | `ci.yml: lint` — `ruff check` | style |
| Storage guardrail | `ci.yml: lint` | no direct `sqlite3.connect` in `modules/` |
| Monolith ratchet | `ci.yml: lint` → `api_monolith_ratchet.py` | `api.py` only shrinks |
| Route-surface guard | `ci.yml: lint` → `openapi_route_guard.py` | API surface unchanged w/o snapshot |
| FIPS crypto-primitive gate | `ci.yml: lint` | SC-13 hash discipline |
| FIPS fail-closed gate | `ci.yml: lint` | `assert_fips_mode()` exits 78 off-FIPS |
| Import verification | `ci.yml: lint` | core modules import |
| Full test suite | `ci.yml: test-suite` | `tests` + `platform/tests` + `collector/tests` (incl. `test_licensing.py`, `test_dev_mode_guard.py`) |
| DoD ATO evidence | `ci.yml: ato-evidence` | OSCAL/STIG evidence generates; uploads artifact |
| Dependency scan | `ci.yml: dependency-scan` — pip-audit | CVEs in `requirements.txt` |
| CodeQL | `ci.yml: codeql` | static security analysis |
| Secret scan | `ci.yml: secrets-scan` — TruffleHog | no committed secrets |
| Secret gate | `ci.yml: secret-gate` | prod secret hygiene |
| Container build + Trivy | `ci.yml: docker-build` | image builds; image CVE scan |
| Runtime readiness | `ci.yml: runtime-readiness` | boots `api:app` (`TOKENDNA_ENV=ci DEV_MODE=true`), load/SLO smoke |
| Adversarial harness | `ci.yml: adversarial-security` | `adversarial_harness.py --strict` |
| Policy regression gate | `ci.yml: policy-regression-gate` | decision-audit regression |
| Postgres integration | `ci.yml: postgres-integration` | real-Postgres tests |
| Helm lint | `ci.yml: helm-lint` | chart validity |
| Stress smoke | `ci.yml: stress-smoke` | p95 gate under load |
| Detection efficacy (advisory) | `ci.yml: efficacy-benchmark` | `efficacy_benchmark.py`; uploads report (non-blocking) |
| DCO | `dco.yml` | every PR commit carries `Signed-off-by` |
| Image release | `release-docker.yml` (tags) | multi-arch build, cosign keyless sign + verify, SLSA provenance, cosign-signed SPDX SBOM attestation |
| SDK publish | `publish.yml` (tags) | builds + OIDC-publishes `tokendna-sdk` to (Test)PyPI |

## 9. Local development

```bash
pip install -r requirements.txt pytest pytest-asyncio ruff
pip install -e ./platform -e ./collector           # sub-packages
cp .env.example .env

# Boot (DEV_MODE bypasses auth — TOKENDNA_ENV=ci satisfies the deny-by-default guard):
TOKENDNA_ENV=ci DEV_MODE=true uvicorn api:app --reload

# Tests (mirrors CI):
python -m pytest -q --import-mode=importlib tests platform/tests collector/tests

# Seed a demo + run the 10-minute narrative arc:
python scripts/demo_seed_v2.py && python scripts/demo_seed_gap.py
TOKENDNA_ENV=ci DEV_MODE=true uvicorn api:app --port 8000 &
python scripts/demo_runtime_risk_engine.py
```

`make install` / `make test` / `make lint` wrap the same commands CI uses.

## 10. Where to look next

- New feature? Add a router under `api_routers/`, gate it with
  `require_feature("ent.*")`, snapshot the route (`openapi_route_guard.py
  --update`), emit `AuditEvent`s, keep queries Postgres-compatible.
- Understanding detection? Start at `edge_enforcement.py`, then `trust_graph.py`,
  `intent_correlation.py`, `blast_radius.py`.
- Compliance/federal? `modules/security/fips.py`, `scripts/generate_oscal.py`,
  `docs/marketing/FEDERAL_ONEPAGER.md`, the ATO evidence job.
