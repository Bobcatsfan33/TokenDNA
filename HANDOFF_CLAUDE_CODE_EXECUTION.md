# HANDOFF — Claude Code Execution Plan: License Gating + Acquisition Readiness (v2)

*Companion to: `TOKENDNA_ACQUISITION_ROADMAP.md`, `tokendna_licensing_install.sh`, `tokendna_license_server_install.sh`*
*Rebuilt against master @ `6382c58` (2026-07-03, post PR #140). Supersedes v1.*
*Pattern: same as `HANDOFF_TOKENDNA_ROADMAP_EXECUTION.md` already in the repo — this file is Claude Code's source of truth for this workstream.*

---

## Repo-state notes this plan was verified against

The install scripts were authored at `efc51e7` and re-verified against the current head `6382c58`. Two facts matter:

1. **The two files the install script fully rewrites — `modules/product/commercial_tiers.py` and `api_routers/__init__.py` — are unchanged between those commits.** The rewrites are still byte-exact against master. The drift check in Session 1 remains as a safety net, but it should come back clean.
2. **PR #140 made DEV_MODE deny-by-default.** `config.py` now raises `SystemExit` at import whenever `DEV_MODE=true` and the resolved environment (`TOKENDNA_ENV`, then `ENVIRONMENT`) is not one of `{dev, development, test, testing, local, ci}`. Consequences baked into this plan: every local command that sets `DEV_MODE=true` must also export `TOKENDNA_ENV=ci` (or `dev`); the route-surface guard sets `DEV_MODE=true` *internally*, so it needs `TOKENDNA_ENV=ci` too (the install script already does this); any new CI job Claude Code writes that uses DEV_MODE must declare `TOKENDNA_ENV: ci`, matching what ci.yml now does; and `tests/test_dev_mode_guard.py` exists — nothing in the licensing work may weaken or special-case that guard.

Also new since v1: the repo has a `Makefile` whose targets mirror CI exactly. Use `make install`, `make test`, `make lint` instead of hand-rolled pip/pytest incantations.

## How to use this file

Drop the three companion files plus this one into the TokenDNA repo root, then start Claude Code there:

```bash
cd ~/path/to/TokenDNA
cp ~/Downloads/TOKENDNA_ACQUISITION_ROADMAP.md \
   ~/Downloads/tokendna_licensing_install.sh \
   ~/Downloads/tokendna_license_server_install.sh \
   ~/Downloads/HANDOFF_CLAUDE_CODE_EXECUTION.md .
claude
```

Paste the Session 1 kickoff prompt below. Run **one session per phase** — each ends with a verification gate and a commit. The repo's CI is strict (route-surface guard, monolith ratchet, FIPS gate, DEV_MODE guard) and small verified increments are what keep it green.

Hard rules for every session:

1. **The install scripts are ground truth, not inspiration.** Their embedded code was syntax-verified and round-trip tested (server-signed key → product verification, tamper + expiry rejection). Claude Code's job is to *execute and verify*, adapting only on confirmed drift.
2. **The private signing key never enters any repo, any prompt, or any context window.** Claude Code may run `scripts/generate_license_keys.py` (writes to `~/.tokendna/`), but must never `cat`, read, or paste the PEM. If a step seems to need the key contents, the step is wrong.
3. **Never weaken PR #140.** The licensing gate and the DEV_MODE guard are independent security boundaries. No new env var may bypass authentication, and `TOKENDNA_LICENSE_ENFORCEMENT` must never affect authn — it only caps commercial-tier entitlement.

---

## Session 1 — Execute the license spine (public repo)

**Kickoff prompt (paste into Claude Code):**

```
Read HANDOFF_CLAUDE_CODE_EXECUTION.md fully, then execute Session 1.

Context you must internalize first:
- This repo's HEAD includes PR #140: config.py raises SystemExit when
  DEV_MODE=true unless TOKENDNA_ENV/ENVIRONMENT is one of
  {dev, development, test, testing, local, ci}. Every DEV_MODE command below
  therefore exports TOKENDNA_ENV=ci. Read tests/test_dev_mode_guard.py so you
  don't accidentally regress it.
- make install / make test / make lint mirror CI exactly. Use them.

Task: apply tokendna_licensing_install.sh to this repo.

1. Read the script fully. It creates branch feat/stripe-license-gating and
   writes: modules/product/licensing.py (new), a full rewrite of
   modules/product/commercial_tiers.py, api_routers/license.py (new), a full
   rewrite of api_routers/__init__.py, scripts/generate_license_keys.py,
   tests/test_licensing.py, docs/LICENSING.md, and .env.example additions.

2. Drift check (expected clean — the rewrites were re-verified against
   6382c58): diff the script's two rewrite payloads against the current
   modules/product/commercial_tiers.py and api_routers/__init__.py. If either
   differs from what the script would overwrite EXCEPT for the intended
   additions (_license_capped_rank, the license_state param on
   forbidden_payload, the license_router import + ALL_ROUTERS entry), stop
   and port those additions onto the live file instead of overwriting.

3. Run the script. It generates the signing keypair into ~/.tokendna/ —
   never read or display the private key file. The script already runs the
   route-surface guard as: TOKENDNA_ENV=ci python3 scripts/ci/openapi_route_guard.py --update

4. Verification gate — all must pass before committing:
   - python -m pytest -q tests/test_licensing.py
   - make test          (full backend + platform + collector suite)
   - make lint
   - TOKENDNA_ENV=ci python scripts/ci/openapi_route_guard.py   (clean, post-update)
   - python scripts/ci/api_monolith_ratchet.py
   - python -m pytest -q tests/test_dev_mode_guard.py           (guard intact)
   - Boot check:
       TOKENDNA_ENV=ci DEV_MODE=true DATA_DB_PATH=/tmp/tdna-lic.db \
         uvicorn api:app --port 8000 &
     then confirm: unauthenticated curl of /api/license/status behaves like
     other /api/* routes (401 path), /healthz is 200, and the demo arc still
     completes: python scripts/demo_runtime_risk_engine.py
   - Negative check: with TOKENDNA_LICENSE_ENFORCEMENT unset, confirm via the
     test suite that ent.* gating behavior is unchanged (default off).

5. Scan the full diff for forbidden content before committing: any PEM
   content, any phone number, any personal email, any Stripe secret. Then
   commit with the message the script specifies. Do NOT push — I review and
   push manually. End by printing git log -1 --stat.
```

**Acceptance criteria:** full suite green via `make test`, route guard green with `GET /api/license/status` and `POST /api/license/activate` in the snapshot, `test_dev_mode_guard.py` untouched and passing, demo arc unchanged under default `TOKENDNA_LICENSE_ENFORCEMENT=off`, diff contains only intended files.

## Session 2 — License service (PRIVATE repo, separate session)

Run in a *different directory and a fresh Claude Code session* — never in the public repo's context:

```
Execute tokendna_license_server_install.sh to scaffold ./tokendna-license-server.
Then:
1. Verify: pip install -r requirements.txt; python -m py_compile *.py; and a
   local round-trip with a THROWAWAY key (never ~/.tokendna/): generate an
   Ed25519 key in /tmp, then
   LICENSE_PRIVATE_KEY_PATH=/tmp/throwaway.pem python issue_license.py \
     --customer cus_test --org Test --tier pro --days 1
   and confirm the output parses as TDNA1.<b64>.<b64>.
2. Add tests/test_signing.py covering issue_license payload fields, tier
   validation, and expiry math.
3. Add a GitHub Actions workflow: py_compile + tests on push.
4. Commit. Remind me this repo must be created PRIVATE:
   gh repo create tokendna-license-server --private --source=. --push
```

**Acceptance criteria:** compiles, round-trip passes with a throwaway key, `.gitignore` excludes `*.pem`, `*.key`, `licenses.db`, `.env`.

## Session 3 — Detection-efficacy benchmark (roadmap Phase 2)

```
Read TOKENDNA_ACQUISITION_ROADMAP.md (Phase 2), scripts/adversarial_harness.py,
and scripts/demo_seed_gap.py (the seeded scenarios are reusable fixtures).
Build scripts/efficacy_benchmark.py: a reproducible harness that replays the
three RSA-2026 scenarios the README claims (policy self-modification,
permission drift, MCP chain attack) against a local instance booted with
TOKENDNA_ENV=ci DEV_MODE=true, and emits a JSON + markdown report: detection
rate, false-positive rate on a benign-traffic baseline, and p50/p95 decision
latency vs EDGE_DECISION_SLO_MS. Reuse existing harness scenarios where
possible. Add an advisory (non-blocking) CI job that uploads the report as an
artifact — the job MUST declare TOKENDNA_ENV: ci like the other DEV_MODE jobs
in ci.yml. Add docs/BENCHMARK.md describing methodology honestly, including
what the benchmark does NOT cover.
```

**Acceptance criteria:** `TOKENDNA_ENV=ci python scripts/efficacy_benchmark.py --strict` green locally, report artifact uploads in CI, methodology doc makes no unverifiable claims.

## Session 4 — UIS standalone spec repo (adoption lens, play #1)

```
Read TOKENDNA_ACQUISITION_ROADMAP.md (Lens 2, play 1). Extract the UIS schema
into a new sibling repo ./uis-spec: the JSON schema served at
/api/schema/uis.json, a written SPEC.md (field semantics, versioning policy,
conformance levels), 3+ example event payloads, a tiny Python validator
package (uis-validate), and mapping docs for SPIFFE/SPIRE and the OAuth
agent-identity draft landscape. Apache-2.0 license — the spec must be
maximally adoptable even though TokenDNA core is BUSL. CI: schema-validate
the examples. Only main-repo change allowed: a "Spec lives at <repo>" pointer
in README.md.
```

## Session 5 — MCP inspector standalone wedge (adoption lens, play #2)

```
Locate the mcp_inspector bounded-gap subsequence matcher (start from
api_routers/mcp.py and modules/). Extract it into a standalone
pip-installable tool in a new sibling repo ./mcp-inspector: a CLI that takes
an MCP server manifest or traffic capture and reports chain-pattern findings
with confidence scores. MIT or Apache-2.0. README positioning: "is your MCP
server lying to you?" with a funnel link to TokenDNA. Keep the extraction
thin — vendor the matcher, don't drag in tenants/storage/auth. Note the
asset_inventory scanner (modules/identity/asset_inventory.py) already parses
LangGraph/OpenAI-Agents/CrewAI/AutoGen/MCP manifests — reuse its manifest
parsing rather than writing a new one.
```

## Session 6 — Release hygiene (code lens, Phase 3)

```
In the main repo: (1) add Sigstore/cosign signing to
.github/workflows/release-docker.yml (it already does SLSA on tags — extend,
don't replace); (2) create ARCHITECTURE.md — a one-day-onboarding document
for an acquiring team: module map, data flows, the runtime loop, storage
backends, the full CI gate inventory (ratchet, route guard, FIPS gate,
DEV_MODE guard, secret gate, adversarial + policy-regression lanes, licensing
tests); (3) add DCO enforcement (CI check for Signed-off-by) documented in
CONTRIBUTING.md; (4) verify publish.yml actually publishes tokendna_sdk to
PyPI and fix if not. Each item = separate commit. Any job using DEV_MODE
declares TOKENDNA_ENV: ci.
```

---

## Human-only checklist (Claude Code cannot do these)

Stripe dashboard: create products/prices/payment links and the webhook endpoint per the license server README; set `STRIPE_API_KEY` / `STRIPE_WEBHOOK_SECRET` / `PRICE_TIER_MAP_JSON` in the deployment host. Your phone number's only role is securing your Stripe login — it goes nowhere else. Deploy the license service (Railway/Fly) with the private key as a secret mount. Back up `~/.tokendna/license_signing_private.pem` to a password manager immediately after Session 1. Engage a pen-test vendor (Cure53 / Trail of Bits / Doyensec) and a compliance platform (Vanta/Drata) per roadmap Phase 2. Design-partner outreach and conference CFPs per the sequencing table. Review + push every branch Claude Code produces — keep the owner-approval gate CONTRIBUTING.md promises.

## Suggested CLAUDE.md addition (main repo)

Append to the existing CLAUDE.md so every future session inherits the guardrails:

```markdown
## Licensing workstream guardrails
- modules/product/licensing.py is the entitlement boundary. Never weaken
  parse_and_verify, never add a bypass env var beyond
  TOKENDNA_LICENSE_ENFORCEMENT, never log raw license keys.
  TOKENDNA_LICENSE_ENFORCEMENT gates commercial entitlement ONLY — it must
  never affect authentication. The DEV_MODE deny-by-default guard (PR #140,
  config.py + tests/test_dev_mode_guard.py) is a separate boundary; do not
  special-case or weaken it for licensing.
- The Ed25519 private signing key lives outside the repo (~/.tokendna/).
  Never read, display, or commit PEM files. TruffleHog runs in CI.
- New endpoints require TOKENDNA_ENV=ci python scripts/ci/openapi_route_guard.py
  --update plus a committed snapshot. Local runs with DEV_MODE=true always
  export TOKENDNA_ENV=ci (or dev) — config.py hard-exits otherwise.
- Default enforcement is "off"; changing that default is a breaking change
  requiring a major version bump and a RELEASES.md entry.
- The license server is a separate PRIVATE repo. Nothing from it (Stripe
  keys, issuance logic beyond the shared TDNA1 format) belongs here.
```
